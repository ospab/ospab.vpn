#!/usr/bin/env bash
set -euo pipefail

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found. This script requires systemd (systemctl). On WSL or systems without systemd please use another method (tmux, screen, or supervisor) to run the process."
  exit 1
fi

usage() {
  cat <<EOF
Usage: $0 install [run-as-user]
       $0 remove

install: create and enable systemd service for the server
       optional: run-as-user - username to run the service as (defaults to SUDO_USER or root)
remove: remove and disable the service
EOF
}

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

ACTION="$1"
RUN_AS_USER=""
if [ "$ACTION" = "install" ]; then
  if [ "$#" -ge 2 ]; then
    RUN_AS_USER="$2"
  else
    RUN_AS_USER="${SUDO_USER:-root}"
  fi
fi

SERVICE_NAME="ospab-server.service"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="$(command -v python3 || command -v python)"

if [ -z "$PYTHON_BIN" ]; then
  echo "python3 not found in PATH"
  exit 1
fi

if [ "$ACTION" = "install" ]; then
  if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo) to install the service"
    exit 1
  fi

  echo "Creating systemd unit at ${UNIT_PATH} (Run as: ${RUN_AS_USER})"
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=ospab.vpn Reality Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON_BIN} ${PROJECT_DIR}/server.py
Restart=on-failure
RestartSec=5
User=${RUN_AS_USER}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  echo "Service $SERVICE_NAME installed and started. Check logs: sudo journalctl -u $SERVICE_NAME -f"
  exit 0

elif [ "$ACTION" = "remove" ]; then
  if [ "$EUID" -ne 0 ]; then
    echo "Run as root (sudo) to remove the service"
    exit 1
  fi

  if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    systemctl disable --now "$SERVICE_NAME" || true
  fi
  rm -f "$UNIT_PATH" || true
  systemctl daemon-reload
  echo "Service $SERVICE_NAME removed"
  exit 0
else
  usage
  exit 1
fi