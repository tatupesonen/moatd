"""Connectivity probes and listeners driven from inside a netns."""

from __future__ import annotations

import subprocess
import time

from .netns import Topology, ping_ok
from .sh import nsexec, ok


def nc_connect(ns: str, addr: str, port: int, timeout: float = 2.0, v6: bool = False) -> bool:
    """TCP connect probe from `ns`. True iff the connection succeeds."""
    fam = "-6" if v6 else "-4"
    cmd = nsexec(ns, "nc", "-z", "-w", str(int(timeout)), fam, addr, str(port))
    return ok(cmd, timeout=timeout + 3)


def ping(ns: str, addr: str, count: int = 1, v6: bool = False) -> bool:
    return ping_ok(ns, addr, count=count, v6=v6)


class Listener:
    """A backgrounded `nc -l` in a netns, as a context manager."""

    def __init__(self, ns: str, port: int, udp: bool = False, v6: bool = False):
        self.ns = ns
        self.port = port
        self.udp = udp
        self.v6 = v6
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "Listener":
        args = ["nc", "-l"]
        if self.v6:
            args.append("-6")
        if self.udp:
            args.append("-u")
        args += ["-p", str(self.port)]
        self.proc = subprocess.Popen(
            nsexec(self.ns, *args),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.2)
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
