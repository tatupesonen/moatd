#!/usr/bin/env bash
# Daemon attaches XDP + TC to the configured interface inside the test netns.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

# bpftool net show only prints names for generic/skb XDP; in native ("driver")
# mode it shows only the id. Verify both programs exist by name via prog show,
# and confirm the interface lines are non-empty.
ip netns exec "$NS_H" bpftool prog show name moat_ingress 2>&1 | grep -q xdp \
    || { echo "moat_ingress XDP program not loaded"; ip netns exec "$NS_H" bpftool prog show; exit 1; }
ip netns exec "$NS_H" bpftool prog show name moat_egress 2>&1 | grep -q sched_cls \
    || { echo "moat_egress TC program not loaded"; ip netns exec "$NS_H" bpftool prog show; exit 1; }

net="$(ip netns exec "$NS_H" bpftool net show 2>&1)"
echo "$net" | grep -A1 "^xdp:" | grep -q "$IFACE_H" \
    || { echo "no XDP attachment on $IFACE_H"; echo "$net"; exit 1; }
echo "$net" | grep -A1 "^tc:"  | grep -q "$IFACE_H" \
    || { echo "no TC attachment on $IFACE_H";  echo "$net"; exit 1; }

# Status reports the attached interface.
status="$(moat_cli status)"
echo "$status" | grep -q "$IFACE_H" || { echo "status missing $IFACE_H:"; echo "$status"; exit 1; }

log "attach OK: $IFACE_H, ingress+egress visible"
