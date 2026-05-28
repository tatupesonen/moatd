# shellcheck shell=bash
# Shared helpers for moat integration tests.
#
# Each scenario sources this file. It defines:
#   setup_netns / teardown_netns        veth-connected netns pair
#   start_moatd / stop_moatd            moatd in the host-side netns
#   moat_cli                            run moat CLI against running moatd
#   nc_to_host_v4 / nc_to_host_v6       client -> host connectivity probes
#   listen_in_host / stop_listener      host-side listener
#   ping_from_host                      ping from host netns to client
#   expect_pass / expect_blocked        assertion helpers
#   trap cleanup EXIT                   put this in every scenario

set -uo pipefail

NS_H="${NS_H:-moat-h}"
NS_C="${NS_C:-moat-c}"
IFACE_H="${IFACE_H:-mvethH}"
IFACE_C="${IFACE_C:-mvethC}"
ADDR_H_V4="${ADDR_H_V4:-10.99.0.1}"
ADDR_C_V4="${ADDR_C_V4:-10.99.0.2}"
PREFIX_V4="${PREFIX_V4:-24}"
ADDR_H_V6="${ADDR_H_V6:-fd00:99::1}"
ADDR_C_V6="${ADDR_C_V6:-fd00:99::2}"
PREFIX_V6="${PREFIX_V6:-64}"

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
MOATD_BIN="${MOATD_BIN:-$REPO_ROOT/target/debug/moatd}"

MOATD_PID=
LISTENER_PID=

log() {
    printf '    %s\n' "$*" >&2
}

setup_netns() {
    teardown_netns >/dev/null 2>&1 || true
    rm -f /etc/moatd/rules.toml  # fresh per-test config; restarts within a test preserve it
    ip netns add "$NS_H"
    ip netns add "$NS_C"
    ip link add "$IFACE_H" type veth peer name "$IFACE_C"
    ip link set "$IFACE_H" netns "$NS_H"
    ip link set "$IFACE_C" netns "$NS_C"

    ip -n "$NS_H" addr add "$ADDR_H_V4/$PREFIX_V4" dev "$IFACE_H"
    ip -n "$NS_C" addr add "$ADDR_C_V4/$PREFIX_V4" dev "$IFACE_C"
    ip -n "$NS_H" -6 addr add "$ADDR_H_V6/$PREFIX_V6" dev "$IFACE_H" nodad
    ip -n "$NS_C" -6 addr add "$ADDR_C_V6/$PREFIX_V6" dev "$IFACE_C" nodad

    ip -n "$NS_H" link set lo up
    ip -n "$NS_C" link set lo up
    ip -n "$NS_H" link set "$IFACE_H" up
    ip -n "$NS_C" link set "$IFACE_C" up

    # Quick reachability sanity check (before moatd attaches).
    ip netns exec "$NS_C" ping -c 1 -W 1 "$ADDR_H_V4" >/dev/null 2>&1 \
        || { echo "veth sanity ping failed" >&2; return 1; }
}

start_moatd() {
    rm -f /run/moatd/control.sock
    local ifaces="${MOAT_IFACES:-$IFACE_H}"
    ip netns exec "$NS_H" env MOAT_INTERFACES="$ifaces" MOAT_LOG_STDOUT=1 "$MOATD_BIN" daemon \
        > "/tmp/moatd-${NS_H}.log" 2>&1 &
    MOATD_PID=$!
    for _ in $(seq 1 50); do
        if [ -S /run/moatd/control.sock ] && "$MOATD_BIN" ping >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "moatd failed to start (log: /tmp/moatd-${NS_H}.log)" >&2
    tail -20 "/tmp/moatd-${NS_H}.log" >&2 || true
    return 1
}

stop_moatd() {
    if [ -n "$MOATD_PID" ]; then
        kill -TERM "$MOATD_PID" 2>/dev/null || true
        wait "$MOATD_PID" 2>/dev/null || true
        MOATD_PID=
    fi
    rm -f /run/moatd/control.sock
}

teardown_netns() {
    [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null || true
    LISTENER_PID=
    ip netns del "$NS_H" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
}

cleanup() {
    stop_moatd
    teardown_netns
    rm -f /etc/moatd/rules.toml
}

moat_cli() {
    "$MOATD_BIN" "$@"
}

# nc_to_host_v4 PORT [TIMEOUT=2]
nc_to_host_v4() {
    local port="$1"
    local timeout="${2:-2}"
    ip netns exec "$NS_C" nc -z -w "$timeout" -4 "$ADDR_H_V4" "$port"
}

nc_to_host_v6() {
    local port="$1"
    local timeout="${2:-2}"
    ip netns exec "$NS_C" nc -z -w "$timeout" -6 "$ADDR_H_V6" "$port"
}

# nc_to_client_v4 PORT [TIMEOUT=2] -- from host netns to client (tests egress)
nc_to_client_v4() {
    local port="$1"
    local timeout="${2:-2}"
    ip netns exec "$NS_H" nc -z -w "$timeout" -4 "$ADDR_C_V4" "$port"
}

# listen_in_host PORT [PROTO=tcp]
listen_in_host() {
    local port="$1"
    local proto="${2:-tcp}"
    if [ "$proto" = "udp" ]; then
        ip netns exec "$NS_H" nc -l -u -p "$port" >/dev/null 2>&1 &
    else
        ip netns exec "$NS_H" nc -l -p "$port" >/dev/null 2>&1 &
    fi
    LISTENER_PID=$!
    sleep 0.2
}

listen_in_host_v6() {
    local port="$1"
    ip netns exec "$NS_H" nc -6 -l -p "$port" >/dev/null 2>&1 &
    LISTENER_PID=$!
    sleep 0.2
}

listen_in_client() {
    local port="$1"
    ip netns exec "$NS_C" nc -l -p "$port" >/dev/null 2>&1 &
    LISTENER_PID=$!
    sleep 0.2
}

stop_listener() {
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=
    fi
}

ping_from_host_v4() {
    local count="${1:-1}"
    ip netns exec "$NS_H" ping -c "$count" -W 2 "$ADDR_C_V4" >/dev/null 2>&1
}

ping_from_host_v6() {
    local count="${1:-1}"
    ip netns exec "$NS_H" ping -6 -c "$count" -W 2 "$ADDR_C_V6" >/dev/null 2>&1
}

ping_from_client_v4() {
    local count="${1:-1}"
    ip netns exec "$NS_C" ping -c "$count" -W 2 "$ADDR_H_V4" >/dev/null 2>&1
}

ping_from_client_v6() {
    local count="${1:-1}"
    ip netns exec "$NS_C" ping -6 -c "$count" -W 2 "$ADDR_H_V6" >/dev/null 2>&1
}

expect_pass() {
    local desc="$1"
    shift
    if "$@"; then
        log "PASS  $desc"
    else
        log "FAIL  $desc (expected success, got $?)"
        return 1
    fi
}

expect_blocked() {
    local desc="$1"
    shift
    if "$@"; then
        log "FAIL  $desc (expected blocked, got success)"
        return 1
    else
        log "PASS  $desc"
    fi
}
