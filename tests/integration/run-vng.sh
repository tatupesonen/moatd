#!/usr/bin/env bash
# Run the integration suite inside a throwaway VM via virtme-ng, so the eBPF
# program is exercised against a chosen kernel in isolation (and without
# touching the host's firewall state).
#
# Usage:
#   ./run-vng.sh                      # current host kernel
#   ./run-vng.sh /path/to/bzImage ... # one or more specific kernel images
#
# Override pytest args with PYTEST_ARGS, e.g. PYTEST_ARGS="-m perf" ./run-vng.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

command -v vng >/dev/null || { echo "vng (virtme-ng) not found: apt install virtme-ng" >&2; exit 1; }
command -v uv  >/dev/null || { echo "uv not found: https://astral.sh/uv" >&2; exit 1; }

( cd "$REPO" && cargo build )
( cd "$HERE" && uv sync )

PYTEST_ARGS="${PYTEST_ARGS:--m 'not perf' -q}"

kernels=("$@")
[ ${#kernels[@]} -eq 0 ] && kernels=("")  # empty string => current host kernel

rc=0
for kern in "${kernels[@]}"; do
    label="${kern:-$(uname -r) (host)}"
    echo "================ kernel: $label ================"
    kflag=()
    [ -n "$kern" ] && kflag=(-r "$kern")
    # vng runs the guest as root, mounts the host fs, and exits with the
    # command's status. netns + BPF all work against the booted kernel.
    if ! vng --user root "${kflag[@]}" --memory 2G -- \
        bash -lc "cd '$HERE' && .venv/bin/python -m pytest $PYTEST_ARGS"; then
        rc=1
        echo "FAILED on kernel: $label" >&2
    fi
done
exit $rc
