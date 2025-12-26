#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   🔐 SSH Security Auditor - Quick Demo                   ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

# Build the tool
echo -e "${GREEN}Step 1: Building SSH Audit Tool${NC}"
make build || go build -o build/ssh-audit ./cmd/ssh-audit

# Start servers
echo -e "\n${GREEN}Step 2: Starting Demo SSH Servers${NC}"
docker-compose -f docker-compose.simple.yml up -d

echo -e "\n${YELLOW}Waiting 20 seconds for SSH servers to fully initialize...${NC}"
for i in {20..1}; do
    echo -ne "\rTime remaining: ${i}s "
    sleep 1
done
echo -e "\n"

# Show running servers
echo -e "${BLUE}Running SSH Servers:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAMES|ssh-"

# Test connectivity
echo -e "\n${GREEN}Step 3: Testing SSH Connectivity${NC}"
for port in 2222 2223 2224; do
    echo -ne "${YELLOW}Testing port $port... ${NC}"
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        echo -e "${GREEN}✓ Connected${NC}"
    else
        echo -e "${RED}✗ Failed${NC}"
    fi
done

# Run scans
echo -e "\n${GREEN}Step 4: Running SSH Security Scans${NC}"

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scanning vulnerable server (localhost:2222)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./build/ssh-audit \
  --allowlist 127.0.0.1 \
  --ports 2222 \
  --timeout 10 \
  --i-am-authorized \
  --output-json demo-reports/vulnerable-scan.json \
  --output-markdown demo-reports/vulnerable-scan.md || echo -e "${RED}Scan encountered issues${NC}"

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Scanning all servers (network-wide)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./build/ssh-audit \
  --allowlist 127.0.0.1 \
  --ports 2222,2223,2224 \
  --timeout 10 \
  --i-am-authorized \
  --output-json demo-reports/network-scan.json \
  --output-markdown demo-reports/network-scan.md || echo -e "${RED}Scan encountered issues${NC}"

# Summary
echo -e "\n${GREEN}✅ Demo Completed!${NC}\n"

echo -e "${BLUE}Generated Reports:${NC}"
if [ -d "demo-reports" ]; then
    ls -lh demo-reports/ 2>/dev/null || echo "No reports generated"
fi

echo -e "\n${BLUE}Useful Commands:${NC}"
echo "  # View container logs"
echo "  docker logs ssh-vulnerable"
echo ""
echo "  # Manual scan"
echo "  ./build/ssh-audit --allowlist 127.0.0.1 --ports 2222,2223,2224 --i-am-authorized"
echo ""
echo "  # Stop demo"
echo "  docker-compose -f docker-compose.simple.yml down"
echo ""
echo "  # Interactive shell in container"
echo "  docker exec -it ssh-vulnerable /bin/bash"
echo ""
echo "  # Test SSH connection"
echo "  ssh -p 2222 demouser@127.0.0.1  # password: demo123"
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Demo environment is running. Press Ctrl+C to exit.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
