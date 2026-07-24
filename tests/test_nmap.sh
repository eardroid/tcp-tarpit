#!/usr/bin/env bash
set -euo pipefail

target="${1:?Usage: $0 TARGET_IP}"
ports="21,22,23,25,80,443,3306,3389,5900,8080"

echo "Connect scan: third distinct port should start the scanner tarpit path."
nmap -sT -sV --max-retries 1 -p "$ports" "$target"

echo "SYN scan: every trap port should appear open after its fake SYN-ACK."
sudo nmap -sS -p "$ports" "$target"
