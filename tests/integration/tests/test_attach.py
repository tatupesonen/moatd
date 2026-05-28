from moatlib import bpf


def test_attaches_xdp_and_tc(topo, moatd):
    iface = topo.primary.if_h

    assert bpf.prog(topo.ns_h, "moat_ingress"), "XDP program not loaded"
    assert bpf.prog(topo.ns_h, "moat_egress"), "TC program not loaded"

    net = bpf.net_show(topo.ns_h)
    assert iface in net, f"no attachment on {iface}:\n{net}"

    status = moatd.cli("status").stdout
    assert iface in status, f"status missing {iface}:\n{status}"
