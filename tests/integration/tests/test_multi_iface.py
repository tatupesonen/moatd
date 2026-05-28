from moatlib import Listener, Moatd, nc_connect
from moatlib.netns import Link


def test_rule_scoped_to_one_interface(topo):
    link2 = topo.add_link(
        Link(if_h="mvethH2", if_c="mvethC2", ns_c="moat-c2", v4_h="10.98.0.1", v4_c="10.98.0.2")
    )
    ifaces = f"{topo.primary.if_h},{link2.if_h}"
    with Moatd(topo, interfaces=ifaces) as m:
        m.cli("default", "deny", "incoming")
        m.cli("allow", "in", "on", topo.primary.if_h, "port", "7777", "proto", "tcp")

        with Listener(topo.ns_h, 7777):
            assert nc_connect(topo.primary.ns_c, topo.primary.v4_h, 7777), "allowed on scoped iface"
        with Listener(topo.ns_h, 7777):
            assert not nc_connect(link2.ns_c, link2.v4_h, 7777), "denied on other iface"
