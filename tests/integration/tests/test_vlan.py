"""802.1Q VLAN handling: tagged frames are parsed and filtered, not bypassed."""

import time

import pytest

from moatlib import packets

pytestmark = pytest.mark.scapy


def _blocked(log: str, port: int) -> bool:
    return any(f":{port}/" in line and "BLOCK" in line for line in log.splitlines())


def test_single_tag_is_filtered(topo, moatd):
    c, p = topo.primary.ns_c, topo.primary
    moatd.cli("logging", "on")
    moatd.cli("deny", "in", "port", "9999", "proto", "tcp")
    mac = topo.host_mac(p.if_h)

    packets.send(c, kind="v4vlan", iface=p.if_c, src=p.v4_c, dst=p.v4_h, dstmac=mac, dport=9999)
    time.sleep(1.2)
    assert _blocked(moatd.log_text(), 9999), "VLAN-tagged SYN to a denied port should be blocked"


def test_single_tag_allowed_port_passes(topo, moatd):
    c, p = topo.primary.ns_c, topo.primary
    moatd.cli("logging", "on")
    moatd.cli("deny", "in", "port", "9999", "proto", "tcp")  # default-allow otherwise
    mac = topo.host_mac(p.if_h)

    packets.send(c, kind="v4vlan", iface=p.if_c, src=p.v4_c, dst=p.v4_h, dstmac=mac, dport=8888)
    time.sleep(1.2)
    assert not _blocked(moatd.log_text(), 8888), "VLAN-tagged SYN to an allowed port should pass"
