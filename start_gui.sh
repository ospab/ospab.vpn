#!/bin/bash
cd "$(dirname "$0")"
python3 client_gui.py

# Cleanup on exit
if command -v gsettings &> /dev/null; then
    gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null
fi
