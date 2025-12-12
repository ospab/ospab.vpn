#!/bin/bash
cd "$(dirname "$0")"

# Run client
python3 client.py "$@"

# Cleanup proxy on exit
if command -v gsettings &> /dev/null; then
    gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null
fi
