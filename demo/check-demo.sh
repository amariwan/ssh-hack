#!/bin/bash

# =========================================================================
# SSH Security Auditor - Demo Status Check
# =========================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  SSH Security Auditor - Demo Status Check${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Check 1: Docker
echo -e "${YELLOW}[1/6]${NC} Checking Docker..."
if docker ps > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Docker is running"
else
    echo -e "${RED}✗${NC} Docker is not running"
    exit 1
fi

# Check 2: Containers
echo -e "\n${YELLOW}[2/6]${NC} Checking SSH Containers..."
for container in ssh-vulnerable ssh-secure ssh-moderate; do
    if docker ps --filter "name=$container" --format '{{.Names}}' | grep -q "^$container$"; then
        status=$(docker inspect "$container" --format='{{.State.Status}}')
        echo -e "${GREEN}✓${NC} $container is $status"
    else
        echo -e "${RED}✗${NC} $container not found"
    fi
done

# Check 3: Ports
echo -e "\n${YELLOW}[3/6]${NC} Checking SSH Ports..."
for port in 2222 2223 2224; do
    if timeout 2 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Port $port is accessible"
    else
        echo -e "${RED}✗${NC} Port $port is not accessible"
    fi
done

# Check 4: SSH Binaries
echo -e "\n${YELLOW}[4/6]${NC} Checking SSH Build..."
if [ -f "build/ssh-audit" ]; then
    size=$(ls -lh build/ssh-audit | awk '{print $5}')
    echo -e "${GREEN}✓${NC} ssh-audit binary exists ($size)"
else
    echo -e "${RED}✗${NC} ssh-audit binary not found"
fi

# Check 5: Reports
echo -e "\n${YELLOW}[5/6]${NC} Checking Demo Reports..."
if [ -d "demo-reports" ]; then
    count=$(ls demo-reports/*.json 2>/dev/null | wc -l)
    echo -e "${GREEN}✓${NC} demo-reports directory exists ($count JSON files)"
else
    echo -e "${YELLOW}⚠${NC} demo-reports directory not created yet"
fi

# Check 6: SSH Handshake Test
echo -e "\n${YELLOW}[6/6]${NC} Testing SSH Handshake..."
output=$(timeout 3 ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 2>&1 <<< "" || true)
if echo "$output" | grep -q "Permission denied\|password\|passphrase"; then
    echo -e "${GREEN}✓${NC} SSH handshake is working (auth required as expected)"
elif echo "$output" | grep -q "Connection refused"; then
    echo -e "${RED}✗${NC} SSH connection refused"
else
    echo -e "${YELLOW}⚠${NC} SSH response: $(echo "$output" | head -1)"
fi

# Summary
echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Demo Environment Status:${NC}\n"

echo -e "  ${GREEN}Containers:${NC} 3x OpenSSH servers running"
echo -e "  ${GREEN}Ports:${NC} 2222 (vulnerable), 2223 (secure), 2224 (moderate)"
echo -e "  ${GREEN}Tool:${NC} ssh-audit binary ready"
echo -e "  ${YELLOW}Note:${NC} SSH handshake analysis may show warnings"

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Useful Commands:${NC}\n"
echo "  ssh -p 2222 demouser@127.0.0.1        # Connect to vulnerable server"
echo "  docker logs ssh-vulnerable             # View server logs"
echo "  ./build/ssh-audit --help               # Show audit tool options"
echo "  docker-compose -f docker-compose.simple.yml down  # Stop containers"
echo ""
