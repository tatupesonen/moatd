import time

from moatlib import Listener, Moatd, nc_connect
from moatlib import bpf
from moatlib.netns import Link


def _wait_attached(ns: str, iface: str, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bpf.is_attached(ns, iface):
            return True
        time.sleep(0.3)
    return False


def test_attaches_to_interface_that_appears_later(topo):
    if2 = "mvethH2"
    # Whitelist both up front; the second iface does not exist yet.
    with Moatd(topo, interfaces=f"{topo.primary.if_h},{if2}") as m:
        assert not bpf.is_attached(topo.ns_h, if2), "second iface attached before it exists"

        link2 = topo.add_link(
            Link(if_h=if2, if_c="mvethC2", ns_c="moat-c2", v4_h="10.98.0.1", v4_c="10.98.0.2")
        )

        assert _wait_attached(topo.ns_h, if2), f"{if2} not attached:\n{bpf.net_show(topo.ns_h)}"

        m.cli("default", "deny", "incoming")
        m.cli("allow", "in", "on", topo.primary.if_h, "port", "7777", "proto", "tcp")
        with Listener(topo.ns_h, 7777):
            assert not nc_connect(link2.ns_c, link2.v4_h, 7777), "rule excludes the new iface"
