#!/usr/bin/env bash
set -euo pipefail

target="${1:?Usage: $0 TARGET_IP}"

echo "Single HTTP request - expected clean close."
curl --connect-timeout 3 -v "http://${target}/" || true

echo "Use this only after two other trap-port probes to observe the scanner dribble path."
curl --connect-timeout 15 --max-time 35 -v "http://${target}:8080/" || true
