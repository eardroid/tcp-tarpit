#!/bin/bash
# Stop the tarpit cleanly: send SIGINT to main.py, then scrub any leftover rules.
set -uo pipefail

cd "$(dirname "$0")"

echo "Stopping tarpit..."
pkill -INT -f "python main.py" 2>/dev/null || true
sleep 2

# Delete only our own rules using the same code that installed them.
# (The old version piped all of iptables through grep, which could wipe
# rules that were never ours if anything failed halfway.)
python3 -c "from iptables import Iptables; Iptables().remove()" 2>/dev/null || \
  echo "Could not scrub iptables rules, main.py removes them on clean exit." >&2

# If NFQUEUE is still bound, unbind it.
if ls /proc/net/netfilter/nfnetlink_queue >/dev/null 2>&1; then
  queue_count=$(wc -l < /proc/net/netfilter/nfnetlink_queue 2>/dev/null || echo 0)
  if [ "$queue_count" -gt 0 ] 2>/dev/null; then
    echo "Warning: NFQUEUE still has ${queue_count} entry/entries."
    echo "Reboot or flush conntrack if it stays stuck."
  fi
fi

echo "Done."
