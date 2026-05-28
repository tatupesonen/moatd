#!/usr/bin/env bash
# App profiles: `moatd allow <name>` resolves to one or more port rules
# via /etc/moatd/applications.d/<name>.toml.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

# Stash any pre-existing profiles so the test starts from a known state.
PROFILES_BACKUP=
if [ -d /etc/moatd/applications.d ]; then
    PROFILES_BACKUP="$(mktemp -d)"
    cp -a /etc/moatd/applications.d/. "$PROFILES_BACKUP/" 2>/dev/null || true
fi

profile_cleanup() {
    rm -rf /etc/moatd/applications.d
    if [ -n "${PROFILES_BACKUP:-}" ]; then
        mkdir -p /etc/moatd/applications.d
        cp -a "$PROFILES_BACKUP/." /etc/moatd/applications.d/ 2>/dev/null || true
        rm -rf "$PROFILES_BACKUP"
    fi
    cleanup
}
trap profile_cleanup EXIT

# Install a known set of profiles for this test.
mkdir -p /etc/moatd/applications.d
cat > /etc/moatd/applications.d/ssh.toml <<'EOF'
name = "ssh"
ports = "22"
proto = "tcp"
EOF
cat > /etc/moatd/applications.d/web.toml <<'EOF'
name = "web"
ports = "80,443"
proto = "tcp"
EOF

setup_netns
start_moatd

# Single-port profile: one rule.
moat_cli allow ssh
rules="$(moat_cli list)"
echo "$rules" | grep -q "port 22 proto tcp" || {
    echo "FAIL: ssh profile didn't add port 22 rule"
    echo "$rules"
    exit 1
}
single_count="$(echo "$rules" | wc -l)"
[ "$single_count" -eq 1 ] || {
    echo "FAIL: expected 1 rule after 'allow ssh', got $single_count"
    echo "$rules"
    exit 1
}
log "ssh -> port 22/tcp"

# Multi-port profile: two rules.
moat_cli allow web
rules="$(moat_cli list)"
total_count="$(echo "$rules" | wc -l)"
[ "$total_count" -eq 3 ] || {
    echo "FAIL: expected 3 rules after 'allow web' (web adds 80+443), got $total_count"
    echo "$rules"
    exit 1
}
echo "$rules" | grep -q "port 80 proto tcp"  || { echo "FAIL: web didn't expand to 80"; exit 1; }
echo "$rules" | grep -q "port 443 proto tcp" || { echo "FAIL: web didn't expand to 443"; exit 1; }
log "web -> port 80/tcp + port 443/tcp"

# Unknown profile name should error.
if moat_cli allow nonexistent-profile-xyz 2>/dev/null; then
    echo "FAIL: unknown profile name should have errored"
    exit 1
fi
log "unknown profile rejected"
