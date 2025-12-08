#!/bin/bash
# UUID Generator for VLESS-Reality

echo "============================================"
echo "  UUID Generator for VLESS-Reality"
echo "============================================"
echo ""

echo "Generating new UUID..."
echo ""

UUID=$(python3 -c "import uuid; print(uuid.uuid4())")

echo "New UUID: $UUID"
echo ""
echo "Copy this UUID to:"
echo "  1. server.py - line: VLESS_UUID = \"$UUID\""
echo "  2. client.py - line: VLESS_UUID = \"$UUID\""
echo "  3. client_gui.py - line: VLESS_UUID = \"$UUID\""
echo ""
echo "============================================"
echo "IMPORTANT: UUID must be IDENTICAL on both"
echo "server and all clients!"
echo "============================================"
echo ""

# Offer to update files automatically
read -p "Update files automatically? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "server.py" ]; then
        sed -i "s/VLESS_UUID = \".*\"/VLESS_UUID = \"$UUID\"/" server.py
        echo "✓ Updated server.py"
    fi
    if [ -f "client.py" ]; then
        sed -i "s/VLESS_UUID = \".*\"/VLESS_UUID = \"$UUID\"/" client.py
        echo "✓ Updated client.py"
    fi
    if [ -f "client_gui.py" ]; then
        sed -i "s/VLESS_UUID = \".*\"/VLESS_UUID = \"$UUID\"/" client_gui.py
        echo "✓ Updated client_gui.py"
    fi
    echo ""
    echo "All files updated with new UUID!"
fi
