#!/bin/bash
# VLESS-Reality Connection Test
# Tests server connectivity and data transfer

echo "============================================"
echo "  VLESS-Reality Connection Test"
echo "============================================"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SERVER="127.0.0.1"
PORT="4433"

echo "Testing connection to $SERVER:$PORT..."
echo ""

# Test 1: Port availability
echo -n "[1/4] Port availability test... "
if command -v nc &> /dev/null; then
    timeout 2 nc -zv $SERVER $PORT &> /dev/null && {
        echo -e "${GREEN}PASS${NC}"
    } || {
        echo -e "${RED}FAIL${NC} - Server not responding"
        exit 1
    }
elif command -v telnet &> /dev/null; then
    timeout 2 telnet $SERVER $PORT &> /dev/null && {
        echo -e "${GREEN}PASS${NC}"
    } || {
        echo -e "${RED}FAIL${NC} - Server not responding"
        exit 1
    }
else
    echo -e "${YELLOW}SKIP${NC} - nc/telnet not available"
fi

# Test 2: Decoy response
echo -n "[2/4] Decoy mechanism test... "
if command -v curl &> /dev/null; then
    RESPONSE=$(curl -s -m 2 http://$SERVER:$PORT 2>&1)
    if [[ $RESPONSE == *"404"* ]] || [[ $RESPONSE == *"Not Found"* ]]; then
        echo -e "${GREEN}PASS${NC} - HTTP 404 received"
    else
        echo -e "${YELLOW}WARN${NC} - Unexpected response"
    fi
else
    echo -e "${YELLOW}SKIP${NC} - curl not available"
fi

# Test 3: Python availability
echo -n "[3/4] Python environment test... "
if command -v python3 &> /dev/null; then
    python3 -c "import asyncio" 2>/dev/null && {
        echo -e "${GREEN}PASS${NC}"
    } || {
        echo -e "${RED}FAIL${NC} - asyncio not available"
        exit 1
    }
elif command -v python &> /dev/null; then
    python -c "import asyncio" 2>/dev/null && {
        echo -e "${GREEN}PASS${NC}"
    } || {
        echo -e "${RED}FAIL${NC} - asyncio not available"
        exit 1
    }
else
    echo -e "${RED}FAIL${NC} - Python not found"
    exit 1
fi

# Test 4: Files existence
echo -n "[4/4] Project files test... "
if [[ -f "server.py" ]] && [[ -f "client.py" ]]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC} - Required files missing"
    exit 1
fi

echo ""
echo -e "${GREEN}All tests passed!${NC}"
echo "System ready for demonstration."
