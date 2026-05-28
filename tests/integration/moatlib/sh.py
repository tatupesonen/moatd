"""Thin subprocess wrappers. Tests run as root, so no sudo here."""

from __future__ import annotations

import subprocess


class CommandError(RuntimeError):
    pass


def run(cmd: list[str], *, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    if check and proc.returncode != 0:
        raise CommandError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def ok(cmd: list[str], *, timeout: float | None = None) -> bool:
    """Run a command, return True iff it exits 0. A timeout counts as failure."""
    try:
        return run(cmd, check=False, timeout=timeout).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def nsexec(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]
