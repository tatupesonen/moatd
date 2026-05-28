from moatlib import Listener, nc_connect, ping


def test_ndp_survives_default_deny_in(topo, moatd):
    moatd.cli("default", "deny", "incoming")
    # Inbound echo is blocked, but NDP (types 133-137) must still pass.
    assert not ping(topo.primary.ns_c, topo.primary.v6_h, v6=True), "inbound v6 echo blocked"
    # Reverse direction proves NDP works (else the host can't resolve the peer).
    assert ping(topo.ns_h, topo.primary.v6_c, v6=True), "host->client v6 echo"


def test_v6_ingress_rule_blocks_one_port(topo, moatd):
    with Listener(topo.ns_h, 8080, v6=True):
        assert nc_connect(topo.primary.ns_c, topo.primary.v6_h, 8080, v6=True), "default allow v6"

    moatd.cli("deny", "in", "port", "80", "proto", "tcp")
    with Listener(topo.ns_h, 80, v6=True):
        assert not nc_connect(topo.primary.ns_c, topo.primary.v6_h, 80, v6=True), "v6 deny rule"
    with Listener(topo.ns_h, 8081, v6=True):
        assert nc_connect(topo.primary.ns_c, topo.primary.v6_h, 8081, v6=True), "other v6 ports open"
