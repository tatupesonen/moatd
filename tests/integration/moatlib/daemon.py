"""Run moatd inside a netns and drive it via the moat/moatd CLI."""

from __future__ import annotations

import os
import pathlib
import subprocess
import time

from .netns import Topology
from .sh import ok, run

REPO = pathlib.Path(__file__).resolve().parents[3]
MOATD = REPO / "target" / "debug" / "moatd"
SOCKET = "/run/moatd/control.sock"


def foreign_daemon_running() -> bool:
    """True if some moatd we didn't start owns the control socket."""
    return os.path.exists(SOCKET) and ok([str(MOATD), "ping"], timeout=3)


class Moatd:
    def __init__(self, topo: Topology, interfaces: str | None = None):
        self.topo = topo
        self.interfaces = interfaces if interfaces is not None else topo.primary.if_h
        self.logfile = f"/tmp/moatd-{topo.ns_h}.log"
        self.proc: subprocess.Popen | None = None
        self._log = None

    def __enter__(self) -> "Moatd":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self, timeout: float = 10.0) -> None:
        _rm(SOCKET)
        env = dict(os.environ, MOAT_INTERFACES=self.interfaces, MOAT_LOG_STDOUT="1")
        self._log = open(self.logfile, "w")
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", self.topo.ns_h, str(MOATD), "daemon"],
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(SOCKET) and ok([str(MOATD), "ping"], timeout=2):
                return
            if self.proc.poll() is not None:
                raise RuntimeError(f"moatd exited early:\n{self.log_text()}")
            time.sleep(0.1)
        raise RuntimeError(f"moatd did not come up in {timeout}s:\n{self.log_text()}")

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None
        if self._log is not None:
            self._log.close()
            self._log = None
        _rm(SOCKET)

    def cli(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return run([str(MOATD), *args], check=check, timeout=10)

    def cli_ok(self, *args: str) -> bool:
        return self.cli(*args, check=False).returncode == 0

    def log_text(self) -> str:
        try:
            return pathlib.Path(self.logfile).read_text()
        except FileNotFoundError:
            return "(no log)"


def _rm(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
