"""A host/client netns pair joined by a veth, with optional extra pairs.

The daemon runs inside the host netns; the CLI runs in the root netns and
reaches it over the shared /run/moatd/control.sock (mount ns is shared).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .sh import nsexec, ok, run

RULES_FILE = "/etc/moatd/rules.toml"


@dataclass
class Link:
    """One veth pair: host-side iface in ns_h, client-side in ns_c."""

    if_h: str
    if_c: str
    ns_c: str
    v4_h: str
    v4_c: str
    prefix4: int = 24
    v6_h: str | None = None
    v6_c: str | None = None
    prefix6: int = 64


@dataclass
class Topology:
    ns_h: str = "moat-h"
    primary: Link = field(
        default_factory=lambda: Link(
            if_h="mvethH",
            if_c="mvethC",
            ns_c="moat-c",
            v4_h="10.99.0.1",
            v4_c="10.99.0.2",
            v6_h="fd00:99::1",
            v6_c="fd00:99::2",
        )
    )
    extra: list[Link] = field(default_factory=list)

    def __enter__(self) -> "Topology":
        self.setup()
        return self

    def __exit__(self, *exc) -> None:
        self.teardown()

    def _client_namespaces(self) -> list[str]:
        return [self.primary.ns_c, *(l.ns_c for l in self.extra)]

    def setup(self) -> None:
        self.teardown()
        # Fresh per-test config; restarts within a test preserve it.
        _rm(RULES_FILE)
        run(["ip", "netns", "add", self.ns_h])
        run(["ip", "-n", self.ns_h, "link", "set", "lo", "up"])
        self._add_link(self.primary)
        # Reachability sanity check before moatd attaches.
        if not ping_ok(self.primary.ns_c, self.primary.v4_h):
            raise RuntimeError("veth sanity ping failed")

    def add_link(self, link: Link) -> Link:
        self.extra.append(link)
        self._add_link(link)
        return link

    def _add_link(self, link: Link) -> None:
        run(["ip", "netns", "add", link.ns_c])
        run(["ip", "-n", link.ns_c, "link", "set", "lo", "up"])
        run(["ip", "link", "add", link.if_h, "type", "veth", "peer", "name", link.if_c])
        run(["ip", "link", "set", link.if_h, "netns", self.ns_h])
        run(["ip", "link", "set", link.if_c, "netns", link.ns_c])
        run(["ip", "-n", self.ns_h, "addr", "add", f"{link.v4_h}/{link.prefix4}", "dev", link.if_h])
        run(["ip", "-n", link.ns_c, "addr", "add", f"{link.v4_c}/{link.prefix4}", "dev", link.if_c])
        if link.v6_h and link.v6_c:
            run(["ip", "-n", self.ns_h, "-6", "addr", "add", f"{link.v6_h}/{link.prefix6}", "dev", link.if_h, "nodad"])
            run(["ip", "-n", link.ns_c, "-6", "addr", "add", f"{link.v6_c}/{link.prefix6}", "dev", link.if_c, "nodad"])
        run(["ip", "-n", self.ns_h, "link", "set", link.if_h, "up"])
        run(["ip", "-n", link.ns_c, "link", "set", link.if_c, "up"])

    def add_tun(self, name: str, v4: str, prefix4: int = 24) -> None:
        """A persistent tun device in the host netns (ARPHRD_NONE, no L2 header)."""
        run(["ip", "-n", self.ns_h, "tuntap", "add", "mode", "tun", name])
        run(["ip", "-n", self.ns_h, "addr", "add", f"{v4}/{prefix4}", "dev", name])
        run(["ip", "-n", self.ns_h, "link", "set", name, "up"])

    def ifindex(self, name: str) -> int:
        out = run(["ip", "-n", self.ns_h, "-o", "link", "show", name]).stdout
        return int(out.split(":", 1)[0].strip())

    def host_mac(self, name: str) -> str:
        out = run(["ip", "-n", self.ns_h, "-o", "link", "show", name]).stdout
        return out.split("link/ether", 1)[1].split()[0]

    def teardown(self) -> None:
        for ns in [self.ns_h, *self._client_namespaces()]:
            run(["ip", "netns", "del", ns], check=False)
        _rm(RULES_FILE)

    # Command prefixes for running inside a namespace.
    def in_host(self, *args: str) -> list[str]:
        return nsexec(self.ns_h, *args)

    def in_client(self, *args: str) -> list[str]:
        return nsexec(self.primary.ns_c, *args)


def ping_ok(ns: str, addr: str, count: int = 1, v6: bool = False) -> bool:
    cmd = nsexec(ns, "ping", *(["-6"] if v6 else []), "-c", str(count), "-W", "1", addr)
    return ok(cmd, timeout=count * 3 + 3)


def _rm(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
