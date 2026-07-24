#!/bin/bash
# Stop the tarpit cleanly: send SIGINT to main.py, then scrub any leftover rules.
set -uo pipefail

echo "Stopping tarpit..."
pkill -INT -f "python main.py" 2>/dev/null || true
sleep 2

# Remove any rules the tarpit may have left behind (power loss, hard kill, etc.)
iptables-save 2>/dev/null | grep -v "tcp-tarpit" | iptables-restore 2>/dev/null || true

# If NFQUEUE is still bound, unbind it.
if ls /proc/net/netfilter/nfnetlink_queue >/dev/null 2>&1; then
  queue_count=$(wc -l < /proc/net/netfilter/nfnetlink_queue 2>/dev/null || echo 0)
  if [ "$queue_count" -gt 0 ] 2>/dev/null; then
    echo "Warning: NFQUEUE still has ${queue_count} entry/entries."
    echo "Reboot or flush conntrack if it stays stuck."
  fi
fi

echo "Done. Any remaining tcp-tarpit iptables rules have been removed."
