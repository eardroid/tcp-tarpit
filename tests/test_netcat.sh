#!/usr/bin/env bash
set -euo pipefail

target="${1:?Usage: $0 TARGET_IP}"

echo "A single connection should be classified normal and closed quickly."
nc -v -w 3 "$target" 22 || true

echo "Three different ports within ten seconds should make the third one a scanner connection."
for port in 21 22 23; do
  nc -v -w 15 "$target" "$port" || true
done
