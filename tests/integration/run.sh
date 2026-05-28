#!/usr/bin/env bash
# Integration test runner for moat.
#
# Requires root (uses ip netns). Each scenario is self-contained and runs
# serially. Failing scenarios print their log; the runner exits non-zero
# if any scenario failed.

set -u

if [ "$EUID" -ne 0 ]; then
    echo "This script needs root (uses ip netns). Re-run with sudo." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIOS=("$SCRIPT_DIR"/scenarios/*.sh)

# Preflight: binaries must exist
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
for bin in target/debug/moatd target/debug/moat; do
    if [ ! -x "$REPO_ROOT/$bin" ]; then
        echo "Missing $bin. Run \`cargo build\` first." >&2
        exit 1
    fi
done

# Preflight: tools we depend on
for tool in ip nc ping bpftool; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing tool: $tool. Install it (e.g. apt install iproute2 netcat-openbsd iputils-ping linux-tools-common)." >&2
        exit 1
    fi
done

pass=0
fail=0
failed_names=()

for scenario in "${SCENARIOS[@]}"; do
    name="$(basename "$scenario" .sh)"
    printf '=== %-30s ' "$name"
    log="$(mktemp)"
    if bash "$scenario" >"$log" 2>&1; then
        echo "ok"
        ((pass++))
    else
        echo "FAIL"
        sed 's/^/    | /' "$log"
        failed_names+=("$name")
        ((fail++))
    fi
    rm -f "$log"
done

echo
echo "$pass passed, $fail failed"
if [ "$fail" -gt 0 ]; then
    printf 'Failures: %s\n' "${failed_names[*]}"
    exit 1
fi
