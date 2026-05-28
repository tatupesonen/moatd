"""Drive _send.py inside a netns to emit crafted packets."""

from __future__ import annotations

import json
import pathlib
import sys

from .sh import nsexec, run

_SENDER = pathlib.Path(__file__).with_name("_send.py")


def send(ns: str, **kwargs) -> dict:
    args: list[str] = []
    for key, value in kwargs.items():
        if value is None:
            continue
        args += [f"--{key.replace('_', '-')}", str(value)]
    # sys.executable is the venv python (pytest runs under it); scapy lives there.
    proc = run(nsexec(ns, sys.executable, str(_SENDER), *args), timeout=20)
    return json.loads(proc.stdout)
