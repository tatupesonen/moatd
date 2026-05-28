#!/usr/bin/env bash
# Rules persist to /etc/moatd/rules.toml and are re-applied on restart.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"
trap cleanup EXIT

setup_netns
start_moatd

moat_cli default deny incoming
moat_cli allow 22/tcp
moat_cli allow 443/tcp

# Snapshot current rules.
before="$(moat_cli list)"
echo "$before" | grep -q "port 22 proto tcp"   || { echo "missing 22 rule"; exit 1; }
echo "$before" | grep -q "port 443 proto tcp"  || { echo "missing 443 rule"; exit 1; }

stop_moatd
start_moatd

after="$(moat_cli list)"
[ "$before" = "$after" ] || {
    echo "rules drifted across restart"; printf 'before:\n%s\nafter:\n%s\n' "$before" "$after"
    exit 1
}

# And the default policy survived too.
moat_cli status | grep -q "Default in:  Deny" || { moat_cli status; exit 1; }

log "persisted across restart: 2 rules + default deny in"
