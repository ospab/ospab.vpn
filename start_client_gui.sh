#!/bin/bash
# VLESS-Reality GUI Client Launcher for Linux
# Municipal Stage Cybersecurity Olympiad
# Must run as root

set -e

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (use sudo)" 
   exit 1
fi

echo "============================================"
echo "  VLESS-Reality Client (GUI)"
echo "  Municipal Stage Cybersecurity Olympiad"
echo "============================================"
echo ""

# Check and install Python3
if ! command -v python3 &> /dev/null; then
    echo "[WARNING] Python3 not found. Installing..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y python3 python3-pip python3-tk
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-pip python3-tkinter
    elif command -v dnf &> /dev/null; then
        dnf install -y python3 python3-pip python3-tkinter
    else
        echo "[ERROR] Cannot install Python3 automatically. Please install manually."
        exit 1
    fi
fi

echo "[OK] Python found: $(python3 --version)"

# Check tkinter
echo "Checking tkinter..."
python3 -c "import tkinter" 2>/dev/null && echo "[OK] tkinter available" || {
    echo "[WARNING] tkinter not found. Installing..."
    if command -v apt-get &> /dev/null; then
        apt-get install -y python3-tk
    elif command -v yum &> /dev/null; then
        yum install -y python3-tkinter
    elif command -v dnf &> /dev/null; then
        dnf install -y python3-tkinter
    else
        echo "[ERROR] Cannot install tkinter automatically."
        exit 1
    fi
}

# Check file exists
if [[ ! -f "client_gui.py" ]]; then
    echo "[ERROR] File client_gui.py not found!"
    exit 1
fi

echo ""
echo "Launching GUI client..."
echo "Server: 127.0.0.1:4433"
echo "UUID: 12345678-1234-5678-1234-567812345678"
echo "Reality SNI: www.microsoft.com"
echo ""

# Run GUI client
python3 client_gui.py
