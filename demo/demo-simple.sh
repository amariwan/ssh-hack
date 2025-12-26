#!/bin/bash

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   🔐 SSH Security Auditor - Simple Demo                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

echo -e "${GREEN}Step 1: Building SSH Audit Tool${NC}"
echo "Building the binary locally..."
make build || go build -o build/ssh-audit ./cmd/ssh-audit

echo -e "\n${GREEN}Step 2: Starting Demo SSH Servers${NC}"
docker-compose -f docker-compose.simple.yml up -d

echo -e "\n${YELLOW}Waiting 10 seconds for servers to initialize...${NC}"
sleep 10

echo -e "\n${BLUE}Running SSH Servers:${NC}"
docker ps --format "table {{.Names}}\t{{.Ports}}" | grep ssh-

echo -e "\n${GREEN}Step 3: Scanning SSH Servers${NC}"

echo -e "\n${YELLOW}→ Scanning vulnerable server (localhost:2222)...${NC}"
./build/ssh-audit \
  --allowlist 127.0.0.1 \
  --ports 2222 \
  --timeout 5 \
  --i-am-authorized

echo -e "\n${YELLOW}→ Scanning moderate server (localhost:2224)...${NC}"
./build/ssh-audit \
  --allowlist 127.0.0.1 \
  --ports 2224 \
  --timeout 5 \
  --i-am-authorized

echo -e "\n${GREEN}✅ Demo completed!${NC}"
echo -e "\n${BLUE}Commands you can try:${NC}"
echo "  docker-compose -f docker-compose.simple.yml logs ssh-vulnerable"
echo "  ./build/ssh-audit --allowlist 127.0.0.1 --ports 2222,2223,2224 --i-am-authorized"
echo "  docker-compose -f docker-compose.simple.yml down"
echo ""
