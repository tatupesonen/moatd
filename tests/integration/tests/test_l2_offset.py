"""The loader records the per-interface L2 length (0 for raw-L3 devices)."""

import pytest

from moatlib import Moatd, bpf


def test_tun_records_zero_l2_offset(topo):
    topo.add_tun("moattun", "10.97.0.1")
    veth_ifx = topo.ifindex(topo.primary.if_h)
    tun_ifx = topo.ifindex("moattun")

    with Moatd(topo, interfaces=f"{topo.primary.if_h},moattun") as m:
        l2 = bpf.iface_l2_map(topo.ns_h)
        assert l2.get(veth_ifx) == 14, f"ethernet veth should be 14: {l2}"
        if tun_ifx not in l2:
            pytest.skip(f"kernel did not attach to the tun device: {bpf.net_show(topo.ns_h)}")
        assert l2[tun_ifx] == 0, f"tun (ARPHRD_NONE) should be 0: {l2}"
