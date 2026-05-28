#!/usr/bin/env bash
# The link watcher re-syncs rules when a referenced interface changes
# operstate (down → up or vice versa). This scenario toggles the test
# interface and asserts the daemon's log shows the watcher firing.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

# Rule references the test interface so the watcher considers iface changes
# relevant.
moat_cli default deny incoming
moat_cli allow in on "$IFACE_H" port 7777 proto tcp

LOG="/tmp/moatd-${NS_H}.log"

# Toggle: up → down → up. Each transition is a snapshot change the watcher
# must notice. Inter-step sleeps are larger than the poll interval (2s).
ip -n "$NS_H" link set "$IFACE_H" down
sleep 2.5
ip -n "$NS_H" link set "$IFACE_H" up
# Give the watcher up to 5s to see the up event.
for _ in $(seq 1 10); do
    if grep -q "interface change touched a rule" "$LOG"; then
        break
    fi
    sleep 0.5
done

count="$(grep -c "interface change touched a rule" "$LOG" || true)"
if [ "${count:-0}" -lt 1 ]; then
    echo "FAIL: watcher never logged an iface change"
    tail -40 "$LOG"
    exit 1
fi
log "watcher detected $count iface change(s)"
