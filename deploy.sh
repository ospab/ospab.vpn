#!/bin/bash
# Quick Deploy Script for VLESS-Reality Server
# Run this on your VPS after uploading files

set -e

echo "============================================"
echo "  VLESS-Reality Quick Deploy"
echo "============================================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root"
   exit 1
fi

# Install dependencies
echo "[1/6] Installing dependencies..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip ufw fail2ban
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip firewalld fail2ban
elif command -v dnf &> /dev/null; then
    dnf install -y python3 python3-pip firewalld fail2ban
fi
echo "[OK] Dependencies installed"
echo ""

# Configure firewall
echo "[2/6] Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 443/tcp
    ufw allow 22/tcp  # Keep SSH open!
    echo "y" | ufw enable
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --permanent --add-port=22/tcp
    firewall-cmd --reload
fi
echo "[OK] Firewall configured"
echo ""

# Check UUID
echo "[3/6] Checking UUID configuration..."
# Generate a new UUID if not provided
NEW_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
echo "export VLESS_UUID=${NEW_UUID}" >> /etc/environment
echo "[OK] Generated new UUID: ${NEW_UUID}"
echo "     Saved to /etc/environment"
echo ""

# Create systemd service
echo "[4/6] Creating systemd service..."
cat > /etc/systemd/system/vless-reality.service << EOF
[Unit]
Description=VLESS-Reality VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
Environment="VLESS_UUID=${NEW_UUID}"
ExecStart=/usr/bin/python3 $(pwd)/server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vless-reality
echo "[OK] Systemd service created"
echo ""

# Test server
echo "[5/6] Testing server configuration..."
python3 -c "import asyncio" || {
    echo "[ERROR] Python asyncio not available"
    exit 1
}
echo "[OK] Python configuration valid"
echo ""

# Start service
echo "[6/6] Starting VLESS-Reality service..."
systemctl start vless-reality
sleep 2
systemctl status vless-reality --no-pager

echo ""
echo "============================================"
echo "  Deployment Complete!"
echo "============================================"
echo ""
echo "Server Status:"
systemctl is-active vless-reality && echo "  ✓ Service is running" || echo "  ✗ Service failed to start"
echo ""
echo "Next Steps:"
echo "  1. Test decoy: curl http://$(hostname -I | awk '{print $1}'):443"
echo "  2. Check logs: journalctl -u vless-reality -f"
echo "  3. Configure client with server IP"
echo ""
echo "Security Reminders:"
echo "  - Change default UUID if not done yet!"
echo "  - Configure ALLOWED_IPS in server.py"
echo "  - Monitor logs for suspicious activity"
echo ""
