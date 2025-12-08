#!/bin/bash
# VLESS-Reality Server Launcher for Linux
# Municipal Stage Cybersecurity Olympiad
# Must run as root

set -e

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (use sudo)" 
   exit 1
fi

echo "============================================"
echo "  VLESS-Reality Mock Server"
echo "  Municipal Stage Cybersecurity Olympiad"
echo "============================================"
echo ""

# Check and install Python3
if ! command -v python3 &> /dev/null; then
    echo "[WARNING] Python3 not found. Installing..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-pip
    elif command -v dnf &> /dev/null; then
        dnf install -y python3 python3-pip
    else
        echo "[ERROR] Cannot install Python3 automatically. Please install manually."
        exit 1
    fi
fi

echo "[OK] Python found: $(python3 --version)"

# Check asyncio (part of stdlib, should be available)
python3 -c "import asyncio" 2>/dev/null || {
    echo "[ERROR] asyncio not available. Python version too old?"
    exit 1
}

# Check file exists
if [[ ! -f "server.py" ]]; then
    echo "[ERROR] File server.py not found!"
    exit 1
fi

echo ""
echo "Starting server..."
echo "Port: 4433"
echo "UUID: 12345678-1234-5678-1234-567812345678"
echo "Reality SNI: www.microsoft.com"
echo ""

# Run server
python3 server.py
