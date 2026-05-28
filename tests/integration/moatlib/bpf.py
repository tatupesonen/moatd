"""bpftool queries against programs/maps loaded inside a netns."""

from __future__ import annotations

import json

from .sh import nsexec, run


def _bpftool_json(ns: str, *args: str):
    proc = run(nsexec(ns, "bpftool", "-j", *args), check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def prog(ns: str, name: str) -> dict | None:
    data = _bpftool_json(ns, "prog", "show", "name", name)
    if not data:
        return None
    return data[0] if isinstance(data, list) else data


def net_show(ns: str) -> str:
    return run(nsexec(ns, "bpftool", "net", "show"), check=False).stdout


def is_attached(ns: str, iface: str) -> bool:
    return iface in net_show(ns)


def prog_stats(ns: str, name: str) -> tuple[int, int]:
    """(run_time_ns, run_cnt). Zeros unless kernel.bpf_stats_enabled=1."""
    p = prog(ns, name) or {}
    return int(p.get("run_time_ns", 0)), int(p.get("run_cnt", 0))


def map_dump(ns: str, name: str) -> list[dict]:
    data = _bpftool_json(ns, "map", "dump", "name", name)
    return data or []


def _hexbytes_to_int_le(byts: list[str]) -> int:
    raw = bytes(int(b, 16) for b in byts)
    return int.from_bytes(raw, "little")


def iface_l2_map(ns: str) -> dict[int, int]:
    """Decode the IFACE_L2 map into {ifindex: l2_len}."""
    out: dict[int, int] = {}
    for entry in map_dump(ns, "IFACE_L2"):
        key = entry.get("key")
        val = entry.get("value")
        if not key or not val:
            continue
        out[_hexbytes_to_int_le(key)] = _hexbytes_to_int_le(val)
    return out
