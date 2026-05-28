"""Source-CIDR matching across prefix lengths (exercises the v6 word-mask)."""

import pytest

from moatlib import Listener, nc_connect

# client is fd00:99::2; each rule denies a src CIDR on tcp/8080.
V6_CASES = [
    ("fd00:99::2/128", True),   # exact, full low word
    ("fd00:99::/64", True),     # high word only (the 64-bit boundary)
    ("fd00:99::/120", True),    # partial low-word mask
    ("fd00:99::/48", True),     # partial high-word mask
    ("fd00:99::/1", True),      # single top bit
    ("fd00:aa::/64", False),    # different /64
    ("fd00:99::3/128", False),  # different host
]


# `from <cidr>` (no port) matches on the source address only; `from <cidr> port
# N` would set the source port, which never matches an ephemeral client port.
@pytest.mark.parametrize("cidr,should_block", V6_CASES)
def test_v6_source_cidr(topo, moatd, cidr, should_block):
    moatd.cli("deny", "in", "from", cidr, "proto", "tcp")
    with Listener(topo.ns_h, 8080, v6=True):
        reached = nc_connect(topo.primary.ns_c, topo.primary.v6_h, 8080, v6=True)
    assert reached == (not should_block), f"{cidr}: expected blocked={should_block}"


@pytest.mark.parametrize(
    "cidr,should_block",
    [("10.99.0.2/32", True), ("10.99.0.0/24", True), ("10.0.0.0/8", True), ("10.99.0.3/32", False)],
)
def test_v4_source_cidr(topo, moatd, cidr, should_block):
    moatd.cli("deny", "in", "from", cidr, "proto", "tcp")
    with Listener(topo.ns_h, 8080):
        reached = nc_connect(topo.primary.ns_c, topo.primary.v4_h, 8080)
    assert reached == (not should_block), f"{cidr}: expected blocked={should_block}"
