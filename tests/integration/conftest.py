import os

import pytest

from moatlib import Moatd, Topology
from moatlib.daemon import MOATD, foreign_daemon_running


@pytest.fixture(scope="session", autouse=True)
def _preflight():
    if os.geteuid() != 0:
        pytest.exit("integration tests need root (ip netns). Run via `make integration-test`.", returncode=1)
    if not MOATD.exists():
        pytest.exit(f"{MOATD} missing; run `cargo build` first.", returncode=1)
    if foreign_daemon_running():
        pytest.exit(
            "another moatd already owns /run/moatd/control.sock (the installed "
            "service?). Stop it first: `sudo systemctl stop moatd`.",
            returncode=1,
        )


@pytest.fixture
def topo():
    with Topology() as t:
        yield t


@pytest.fixture
def moatd(topo):
    with Moatd(topo) as m:
        yield m
