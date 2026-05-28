#!/usr/bin/env bash
# The link watcher attaches XDP+TC to interfaces that appear AFTER moatd
# has started. The standard veth pair is created up-front, but a second
# pair is created mid-test and we assert moatd dynamically attaches to it.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

NS_C2="${NS_C2:-moat-c2}"
IFACE_H2="${IFACE_H2:-mvethH2}"
IFACE_C2="${IFACE_C2:-mvethC2}"
ADDR_H2_V4="${ADDR_H2_V4:-10.98.0.1}"
ADDR_C2_V4="${ADDR_C2_V4:-10.98.0.2}"

multi_cleanup() {
    ip netns del "$NS_C2" 2>/dev/null || true
    cleanup
}
trap multi_cleanup EXIT

setup_netns

# Whitelist BOTH interfaces, even though the second doesn't exist yet. The
# watcher should pick it up the moment it appears.
MOAT_IFACES="$IFACE_H,$IFACE_H2" start_moatd

# Sanity: only the existing one is attached.
ip netns exec "$NS_H" bpftool prog show name moat_ingress >/dev/null 2>&1 \
    || { echo "FAIL: moat_ingress not loaded"; exit 1; }
if ip netns exec "$NS_H" bpftool net show 2>&1 | grep -q "$IFACE_H2"; then
    echo "FAIL: $IFACE_H2 appears attached before it exists"
    exit 1
fi

# Create the second veth pair AFTER moatd started.
ip netns add "$NS_C2"
ip link add "$IFACE_H2" type veth peer name "$IFACE_C2"
ip link set "$IFACE_H2" netns "$NS_H"
ip link set "$IFACE_C2" netns "$NS_C2"
ip -n "$NS_H" addr add "$ADDR_H2_V4/24" dev "$IFACE_H2"
ip -n "$NS_C2" addr add "$ADDR_C2_V4/24" dev "$IFACE_C2"
ip -n "$NS_C2" link set lo up
ip -n "$NS_H" link set "$IFACE_H2" up
ip -n "$NS_C2" link set "$IFACE_C2" up

# Wait for watcher to attach (poll up to 5s).
for _ in $(seq 1 10); do
    if ip netns exec "$NS_H" bpftool net show 2>&1 | grep -q "$IFACE_H2"; then
        break
    fi
    sleep 0.5
done

if ! ip netns exec "$NS_H" bpftool net show 2>&1 | grep -q "$IFACE_H2"; then
    echo "FAIL: $IFACE_H2 did not get attached after appearing"
    ip netns exec "$NS_H" bpftool net show
    exit 1
fi
log "dynamic attach to $IFACE_H2 verified"

# Behavioral check: with default-deny + iface-scoped rule, traffic on the
# newly-attached iface is correctly filtered.
moat_cli default deny incoming
moat_cli allow in on "$IFACE_H" port 7777 proto tcp

ip netns exec "$NS_H" nc -l -p 7777 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.2
expect_blocked "client on dynamically-attached $IFACE_H2 -> host:7777 (rule excludes $IFACE_H2)" \
    ip netns exec "$NS_C2" nc -z -w 2 -4 "$ADDR_H2_V4" 7777
stop_listener
