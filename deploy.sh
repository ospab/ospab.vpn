#!/bin/bash

# ospab.vpn Server Deployment Script
# Installs dependencies, configures firewall, creates systemd service

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           ospab.vpn Deployment Script            ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  • Install dependencies                          ║${NC}"
echo -e "${CYAN}║  • Configure firewall (ufw)                      ║${NC}"
echo -e "${CYAN}║  • Create systemd service                        ║${NC}"
echo -e "${CYAN}║  • Generate config.yml                           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] This script must be run as root${NC}"
    echo -e "${YELLOW}[!] Run: sudo ./deploy.sh${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Step 1: Install dependencies
echo -e "${CYAN}[1/4] Installing dependencies...${NC}"

if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip ufw > /dev/null 2>&1
    echo -e "${GREEN}[+] Dependencies installed (apt)${NC}"
elif command -v yum &> /dev/null; then
    yum install -y -q python3 python3-pip ufw > /dev/null 2>&1 || yum install -y -q python3 python3-pip firewalld > /dev/null 2>&1
    echo -e "${GREEN}[+] Dependencies installed (yum)${NC}"
elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm python python-pip ufw > /dev/null 2>&1
    echo -e "${GREEN}[+] Dependencies installed (pacman)${NC}"
else
    echo -e "${YELLOW}[!] Could not detect package manager, assuming Python is installed${NC}"
fi

# Verify Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Python3 not found!${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python3: $(python3 --version)${NC}"

# Step 2: Configuration
echo ""
echo -e "${CYAN}[2/4] Server Configuration${NC}"
echo "────────────────────────────────────────"

read -p "[?] Server port [443]: " PORT
PORT=${PORT:-443}

read -p "[?] UUID (empty=generate): " UUID
if [ -z "$UUID" ]; then
    UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
    echo -e "${GREEN}[+] Generated UUID: ${UUID}${NC}"
fi

read -p "[?] SNI domain [www.microsoft.com]: " SNI
SNI=${SNI:-www.microsoft.com}

# Step 3: Configure firewall
echo ""
echo -e "${CYAN}[3/4] Firewall Configuration${NC}"
echo "────────────────────────────────────────"

if command -v ufw &> /dev/null; then
    read -p "[?] Configure UFW firewall? [Y/n]: " CONFIGURE_UFW
    CONFIGURE_UFW=${CONFIGURE_UFW:-Y}
    
    if [[ "$CONFIGURE_UFW" =~ ^[Yy]$ ]]; then
        ufw allow $PORT/tcp > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1  # SSH
        
        if ! ufw status | grep -q "Status: active"; then
            read -p "[?] Enable UFW? (ensure SSH is allowed) [y/N]: " ENABLE_UFW
            if [[ "$ENABLE_UFW" =~ ^[Yy]$ ]]; then
                ufw --force enable > /dev/null 2>&1
            fi
        fi
        echo -e "${GREEN}[+] UFW: Port $PORT/tcp allowed${NC}"
    else
        echo -e "${YELLOW}[!] Skipping firewall configuration${NC}"
    fi
else
    echo -e "${YELLOW}[!] UFW not found, skipping firewall${NC}"
fi

# Step 4: Create config.yml
echo ""
echo -e "${CYAN}[4/4] Creating Configuration Files${NC}"
echo "────────────────────────────────────────"

cat > config.yml << EOF
# ospab.vpn server configuration
# Generated: $(date)

server:
  port: $PORT
  uuid: "$UUID"
  sni: "$SNI"

proxy:
  port: 10808
EOF

echo -e "${GREEN}[+] Created config.yml${NC}"

# Create systemd service
cat > /etc/systemd/system/ospab-vpn.service << EOF
[Unit]
Description=ospab.vpn Reality VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=/usr/bin/python3 $SCRIPT_DIR/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ospab-vpn > /dev/null 2>&1
echo -e "${GREEN}[+] Created systemd service: ospab-vpn${NC}"

# Get local IP
LOCAL_IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "0.0.0.0")

# Summary
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           Deployment Complete!                   ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  IP:     ${GREEN}$LOCAL_IP${NC}"
echo -e "${CYAN}║${NC}  Port:   ${GREEN}$PORT${NC}"
echo -e "${CYAN}║${NC}  UUID:   ${GREEN}$UUID${NC}"
echo -e "${CYAN}║${NC}  SNI:    ${GREEN}$SNI${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Service commands:                               ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}    ${YELLOW}systemctl start ospab-vpn${NC}    - Start"
echo -e "${CYAN}║${NC}    ${YELLOW}systemctl stop ospab-vpn${NC}     - Stop"
echo -e "${CYAN}║${NC}    ${YELLOW}systemctl status ospab-vpn${NC}   - Status"
echo -e "${CYAN}║${NC}    ${YELLOW}journalctl -u ospab-vpn -f${NC}   - Logs"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -p "[?] Start service now? [Y/n]: " START_NOW
START_NOW=${START_NOW:-Y}

if [[ "$START_NOW" =~ ^[Yy]$ ]]; then
    systemctl start ospab-vpn
    echo -e "${GREEN}[+] Service started!${NC}"
    echo ""
    systemctl status ospab-vpn --no-pager
fi
