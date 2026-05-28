import time

from moatlib import Moatd
from moatlib.sh import run


def test_resyncs_when_referenced_iface_flaps(topo):
    iface = topo.primary.if_h
    with Moatd(topo) as m:
        m.cli("default", "deny", "incoming")
        m.cli("allow", "in", "on", iface, "port", "7777", "proto", "tcp")

        run(["ip", "-n", topo.ns_h, "link", "set", iface, "down"])
        time.sleep(2.5)  # longer than the 2s poll interval
        run(["ip", "-n", topo.ns_h, "link", "set", iface, "up"])

        marker = "interface change touched a rule"
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if marker in m.log_text():
                break
            time.sleep(0.5)
        assert marker in m.log_text(), f"watcher never re-synced:\n{m.log_text()[-2000:]}"
