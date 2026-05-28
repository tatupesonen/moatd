from moatlib import Listener, nc_connect, ping


def test_tcp_reply_rides_conntrack(topo, moatd):
    moatd.cli("default", "deny", "incoming")
    with Listener(topo.primary.ns_c, 7777):
        # Host opens TCP to client; the SYN-ACK reply must be allowed back in by
        # the conntrack reverse lookup or the handshake never completes.
        assert nc_connect(topo.ns_h, topo.primary.v4_c, 7777, timeout=3)


def test_icmp_id_disambiguates_request_from_reply(topo, moatd):
    moatd.cli("default", "deny", "incoming")
    # Host-initiated echo: the reply (same icmp id) rides conntrack.
    assert ping(topo.ns_h, topo.primary.v4_c), "host->client echo reply should pass"
    # Unsolicited inbound echo uses a different id, so the reverse lookup misses.
    assert not ping(topo.primary.ns_c, topo.primary.v4_h), "inbound echo should be denied"
