#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   🔐 SSH Security Auditor - Interactive Demo             ║
║   Enterprise SSH Infrastructure Hardening Tool            ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Functions
print_step() {
    echo -e "\n${GREEN}==>${NC} ${BLUE}$1${NC}\n"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Step 1: Setup
print_step "Step 1: Setting up demo environment"
echo "Creating demo directories..."
mkdir -p demo-reports
mkdir -p demo-data/vulnerable
mkdir -p demo-data/secure

print_success "Demo directories ready"

# Step 2: Start containers
print_step "Step 2: Starting SSH demo servers"
echo "Launching Docker containers..."
docker-compose -f docker-compose.demo.yml up -d --build

print_warning "Waiting for SSH servers to initialize (15 seconds)..."
sleep 15

# Verify containers are running
print_step "Step 3: Verifying SSH servers"
CONTAINERS=("ssh-vulnerable" "ssh-moderate" "ssh-secure" "ssh-legacy")
for container in "${CONTAINERS[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        print_success "$container is running"
    else
        print_error "$container failed to start"
    fi
done

# Show running servers
echo -e "\n${BLUE}Running SSH Servers:${NC}"
echo "  📍 Vulnerable Server:  172.20.0.10:22 (localhost:2222)"
echo "  📍 Moderate Server:    172.20.0.11:22 (localhost:2223)"
echo "  📍 Secure Server:      172.20.0.12:22 (localhost:2224)"
echo "  📍 Legacy Server:      172.20.0.13:22 (localhost:2225)"

# Step 4: Run scans
print_step "Step 4: Running security scans"

echo -e "${YELLOW}Scanning individual hosts...${NC}\n"

# Scan vulnerable server
print_warning "Scanning VULNERABLE server (expecting critical issues)..."
docker exec ssh-audit-tool ssh-audit \
    --allowlist 172.20.0.10 \
    --ports 22 \
    --timeout 10 \
    --output-json /app/reports/vulnerable-scan.json \
    --output-markdown /app/reports/vulnerable-scan.md \
    --i-am-authorized || true

# Scan secure server
print_warning "Scanning SECURE server (expecting good results)..."
docker exec ssh-audit-tool ssh-audit \
    --allowlist 172.20.0.12 \
    --ports 22 \
    --timeout 10 \
    --output-json /app/reports/secure-scan.json \
    --output-markdown /app/reports/secure-scan.md \
    --i-am-authorized || true

# Network-wide scan
print_warning "Running network-wide scan..."
docker exec ssh-audit-tool ssh-audit \
    --allowlist 172.20.0.0/16 \
    --ports 22 \
    --concurrency 10 \
    --timeout 10 \
    --output-json /app/reports/network-scan.json \
    --output-markdown /app/reports/network-scan.md \
    --output-html /app/reports/network-scan.html \
    --i-am-authorized || true

print_success "Scans completed!"

# Step 5: Show results
print_step "Step 5: Scan Results Summary"

if [ -f demo-reports/network-scan.json ]; then
    echo -e "${BLUE}Network Scan Summary:${NC}"

    # Extract summary using jq if available
    if command -v jq &> /dev/null; then
        echo -e "\n📊 Statistics:"
        jq -r '.summary | to_entries | .[] | "  \(.key): \(.value)"' demo-reports/network-scan.json 2>/dev/null || true

        echo -e "\n🔍 Discovered Hosts:"
        jq -r '.hosts[] | "  → \(.ip):\(.port) - Risk: \(.riskScore // "N/A") - \(.banner // "No banner")"' demo-reports/network-scan.json 2>/dev/null || head -20 demo-reports/network-scan.json
    else
        print_warning "Install 'jq' for better JSON parsing"
        echo "Raw summary (first 30 lines):"
        head -30 demo-reports/network-scan.json
    fi
else
    print_warning "No scan results found"
fi

# Step 6: Generated Reports
print_step "Step 6: Generated Reports"
echo "📄 Reports available in ./demo-reports/:"
ls -lh demo-reports/ | tail -n +2

echo -e "\n${GREEN}Report files:${NC}"
echo "  📋 network-scan.json      - Machine-readable results"
echo "  📝 network-scan.md        - Human-readable Markdown"
echo "  🌐 network-scan.html      - Interactive HTML dashboard"
echo "  📊 vulnerable-scan.json   - Vulnerable server details"
echo "  ✅ secure-scan.json       - Secure server details"

# Step 7: Interactive options
print_step "Step 7: Next Steps"
echo "What would you like to do?"
echo ""
echo "  1) View HTML dashboard in browser"
echo "  2) View Markdown report"
echo "  3) Run custom scan"
echo "  4) Inspect a specific server"
echo "  5) Stop demo and cleanup"
echo "  6) Keep running (manual exploration)"
echo ""

read -p "Choose option (1-6): " choice

case $choice in
    1)
        if [ -f demo-reports/network-scan.html ]; then
            print_success "Opening HTML dashboard..."
            xdg-open demo-reports/network-scan.html 2>/dev/null || open demo-reports/network-scan.html 2>/dev/null || print_warning "Please open demo-reports/network-scan.html manually"
        else
            print_error "HTML report not found"
        fi
        ;;
    2)
        if [ -f demo-reports/network-scan.md ]; then
            less demo-reports/network-scan.md
        else
            print_error "Markdown report not found"
        fi
        ;;
    3)
        echo "Enter target (e.g., 172.20.0.10):"
        read target
        echo "Enter port (e.g., 22):"
        read port
        docker exec ssh-audit-tool ssh-audit \
            --allowlist "$target" \
            --ports "$port" \
            --i-am-authorized
        ;;
    4)
        echo "Available servers:"
        docker-compose -f docker-compose.demo.yml ps
        echo ""
        echo "Enter container name (e.g., ssh-vulnerable):"
        read container
        docker exec -it "$container" /bin/sh
        ;;
    5)
        print_warning "Stopping and cleaning up..."
        docker-compose -f docker-compose.demo.yml down -v
        print_success "Demo environment stopped"
        echo "Reports preserved in ./demo-reports/"
        ;;
    6)
        print_success "Demo environment is running!"
        echo ""
        echo "Useful commands:"
        echo "  docker-compose -f docker-compose.demo.yml ps     # List containers"
        echo "  docker exec -it ssh-audit-tool /bin/sh          # Interactive shell"
        echo "  docker-compose -f docker-compose.demo.yml down  # Stop demo"
        echo ""
        echo "Manual scan example:"
        echo "  docker exec ssh-audit-tool ssh-audit --allowlist 172.20.0.10 --ports 22 --i-am-authorized"
        ;;
    *)
        print_warning "Invalid option"
        ;;
esac

echo -e "\n${GREEN}════════════════════════════════════════════${NC}"
echo -e "${GREEN}Demo completed successfully! 🎉${NC}"
echo -e "${GREEN}════════════════════════════════════════════${NC}\n"
