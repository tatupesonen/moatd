import pathlib
import shutil
import tempfile

import pytest

from moatlib import Moatd

APPS = pathlib.Path("/etc/moatd/applications.d")


@pytest.fixture
def app_profiles():
    backup = None
    if APPS.exists():
        backup = pathlib.Path(tempfile.mkdtemp())
        shutil.copytree(APPS, backup / "apps")
    APPS.mkdir(parents=True, exist_ok=True)
    (APPS / "ssh.toml").write_text('name = "ssh"\nports = "22"\nproto = "tcp"\n')
    (APPS / "web.toml").write_text('name = "web"\nports = "80,443"\nproto = "tcp"\n')
    try:
        yield
    finally:
        shutil.rmtree(APPS, ignore_errors=True)
        if backup is not None:
            shutil.copytree(backup / "apps", APPS)
            shutil.rmtree(backup, ignore_errors=True)


def test_app_profile_expansion(topo, app_profiles):
    with Moatd(topo) as m:
        m.cli("allow", "ssh")
        rules = m.cli("list").stdout
        assert "port 22 proto tcp" in rules
        assert len(rules.strip().splitlines()) == 1

        m.cli("allow", "web")
        rules = m.cli("list").stdout
        lines = rules.strip().splitlines()
        assert len(lines) == 3, f"web should expand to 80+443:\n{rules}"
        assert "port 80 proto tcp" in rules
        assert "port 443 proto tcp" in rules

        assert not m.cli_ok("allow", "nonexistent-profile-xyz"), "unknown profile should error"
