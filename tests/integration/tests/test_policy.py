from moatlib import Listener, nc_connect, ping


def test_default_allow_passes_both_directions(topo, moatd):
    with Listener(topo.ns_h, 8080):
        assert nc_connect(topo.primary.ns_c, topo.primary.v4_h, 8080), "default allow should pass"
    assert ping(topo.ns_h, topo.primary.v4_c), "host->client ping should pass"


def test_default_deny_in_with_allow_rule(topo, moatd):
    moatd.cli("default", "deny", "incoming")
    moatd.cli("allow", "22/tcp")

    with Listener(topo.ns_h, 22):
        assert nc_connect(topo.primary.ns_c, topo.primary.v4_h, 22), "port 22 allow rule"
    with Listener(topo.ns_h, 8080):
        assert not nc_connect(topo.primary.ns_c, topo.primary.v4_h, 8080), "8080 should be denied"


def test_default_deny_out_with_allow_rule(topo, moatd):
    moatd.cli("default", "deny", "outgoing")
    moatd.cli("allow", "out", "to", topo.primary.v4_c, "port", "80", "proto", "tcp")

    with Listener(topo.primary.ns_c, 80):
        assert nc_connect(topo.ns_h, topo.primary.v4_c, 80), "explicit allow out"
    with Listener(topo.primary.ns_c, 81):
        assert not nc_connect(topo.ns_h, topo.primary.v4_c, 81), "default deny out"
