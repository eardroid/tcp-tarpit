#!/bin/bash
# Start the TCP tarpit. Needs root (iptables + NFQUEUE + raw sockets).
# Run inside the Linux host (Ubuntu/Debian/Kali/WSL2):  bash run.sh
set -euo pipefail

cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root:  sudo bash run.sh" >&2
  exit 1
fi

if [ ! -d .venv ]; then
  echo "No .venv found. Set up first:" >&2
  echo "  sudo apt install -y iptables nmap netcat-openbsd \\" >&2
  echo "    libnetfilter-queue-dev python3-venv python3-dev build-essential" >&2
  echo "  python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

sudo modprobe nfnetlink_queue 2>/dev/null || true

. .venv/bin/activate
exec python main.py "$@"
