import pytest

from phantomdocs.view_agent_units import render_units


def fixture():
    settings = {
        key: "/etc/view/" + key
        for key in (
            "python",
            "reader",
            "org",
            "config",
            "journal",
            "committed",
            "policy_lock",
        )
    }
    settings["supplementary_groups"] = [2001]
    config = {
        "reader_uid": 1001,
        "issuer_uid": 1002,
        "socket_group": 2001,
        "socket_path": "/run/phantomview-example/reader/link.sock",
    }
    return settings, config


def render(settings, config):
    return render_units(
        settings,
        config,
        settings_path="/etc/view/settings.json",
        module_path="/opt/view",
        reader_group=1001,
        tmpfiles_path="/etc/view/runtime.conf",
    )


def test_owned_runtime_lifecycle_and_root_guard_are_explicit():
    settings, config = fixture()
    result = render(settings, config)
    assert (
        "RuntimeDirectory=phantomview-example/reader\n"
        in result["reader.override.conf"]
    )
    assert "RuntimeDirectoryPreserve=no" in result["reader.override.conf"]
    assert "NoNewPrivileges=false" in result["reader.override.conf"]
    assert (
        "--runtime-directory /run/phantomview-example/reader"
        in result["reader.override.conf"]
    )
    assert "d:u:1002:rw-" in result["runtime.conf"]
    assert "OnUnitInactiveSec=30s" in result["phantomview-agent-supervisor.timer"]
    assert "--apply" in result["phantomview-agent-supervisor.service"]


@pytest.mark.parametrize(
    "path",
    [
        "/run/shared.sock",
        "/home/example/reader/link.sock",
        "/run/phantomview-example/../reader/link.sock",
    ],
)
def test_unowned_runtime_paths_are_refused(path):
    settings, config = fixture()
    config["socket_path"] = path
    with pytest.raises(ValueError):
        render(settings, config)
