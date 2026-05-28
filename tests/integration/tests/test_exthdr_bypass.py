"""Regression for the IPv6 extension-header port-matching bypass.

We assert on the daemon's own BLOCK log rather than a kernel reply: the host
kernel won't respond to a bare Hop-by-Hop header, but the firewall's drop
decision is exactly what we want to observe anyway.
"""

import time

import pytest

from moatlib import packets

pytestmark = pytest.mark.scapy


def _blocked_port(log: str, port: int) -> bool:
    return any(f":{port}/" in line and "BLOCK" in line for line in log.splitlines())


def test_hopbyhop_header_does_not_bypass_port_deny(topo, moatd):
    c, p = topo.primary.ns_c, topo.primary
    moatd.cli("logging", "on")
    moatd.cli("deny", "in", "port", "9999", "proto", "tcp")  # default-allow otherwise

    # A SYN to the denied port behind a Hop-by-Hop header must still be dropped.
    # Pre-fix, the ext header made the rule miss (proto/port parsed as 0).
    packets.send(c, kind="v6hbh", iface=p.if_c, src=p.v6_c, dst=p.v6_h, dport=9999)
    time.sleep(1.2)  # block-log drainer dedupes over 1s
    assert _blocked_port(moatd.log_text(), 9999), "ext-header SYN bypassed the port deny"

    # An allowed port is not over-blocked: XDP read the real port through the header.
    packets.send(c, kind="v6hbh", iface=p.if_c, src=p.v6_c, dst=p.v6_h, dport=8888)
    time.sleep(1.2)
    assert not _blocked_port(moatd.log_text(), 8888), "ext-header SYN to an allowed port was dropped"
