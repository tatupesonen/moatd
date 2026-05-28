"""Characterizes the egress hot path: an established flow's per-packet cost
should stay flat as the rule count grows, because the conntrack fast-path skips
the rule walk. Marked `perf` (opt-in) since it's slower and timing-sensitive.
"""

import shutil
import subprocess
import time

import pytest

from moatlib import Moatd, bpf
from moatlib.sh import nsexec, run

pytestmark = pytest.mark.perf


def _bpf_stats(enable: bool) -> None:
    run(["sysctl", "-w", f"kernel.bpf_stats_enabled={int(enable)}"])


def _avg_egress_ns(topo, duration: float = 3.0) -> float:
    """Average ns/run of moat_egress while an iperf3 flow runs host->client."""
    server = subprocess.Popen(
        nsexec(topo.primary.ns_c, "iperf3", "-s", "-1"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    try:
        t0, c0 = bpf.prog_stats(topo.ns_h, "moat_egress")
        run(
            nsexec(topo.ns_h, "iperf3", "-c", topo.primary.v4_c, "-t", str(int(duration))),
            check=False,
            timeout=duration + 10,
        )
        t1, c1 = bpf.prog_stats(topo.ns_h, "moat_egress")
    finally:
        server.terminate()
        server.wait()
    runs = c1 - c0
    assert runs > 1000, f"too few egress runs to measure ({runs})"
    return (t1 - t0) / runs


def test_established_flow_cost_flat_under_many_rules(topo):
    if shutil.which("iperf3") is None:
        pytest.skip("iperf3 not installed")

    _bpf_stats(True)
    try:
        with Moatd(topo) as m:
            baseline = _avg_egress_ns(topo)

            # 200 non-matching allow rules: a new flow would walk all of them,
            # but an established flow takes the conntrack fast-path.
            for i in range(200):
                m.cli("allow", "out", "to", f"203.0.113.{i % 254 + 1}", "port", "9", "proto", "tcp")

            loaded = _avg_egress_ns(topo)
    finally:
        _bpf_stats(False)

    print(f"\negress avg ns/pkt: {baseline:.0f} (0 rules) -> {loaded:.0f} (200 rules)")
    assert loaded < baseline * 2 + 500, (
        f"established-flow egress cost grew with rule count "
        f"({baseline:.0f} -> {loaded:.0f} ns); conntrack fast-path may have regressed"
    )
