from moatlib import Moatd


def test_rules_persist_across_restart(topo):
    with Moatd(topo) as m:
        m.cli("default", "deny", "incoming")
        m.cli("allow", "22/tcp")
        m.cli("allow", "443/tcp")
        before = m.cli("list").stdout

    assert "port 22 proto tcp" in before
    assert "port 443 proto tcp" in before

    # Fresh daemon, same /etc/moatd/rules.toml.
    with Moatd(topo) as m:
        after = m.cli("list").stdout
        assert before == after, f"rules drifted:\nbefore:\n{before}\nafter:\n{after}"
        assert "Deny" in m.cli("status").stdout, "default policy should persist"
