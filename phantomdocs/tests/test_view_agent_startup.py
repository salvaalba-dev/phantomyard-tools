import copy
import threading
from contextlib import contextmanager

import pytest

from phantomdocs.view_agent_startup import check_startup, launch_protected


def fixture():
    org = {
        "version": 1,
        "organization": {"id": "example"},
        "actors": [{"id": "agent", "telegram_bot": "@example_bot"}],
    }
    config = {"organization": "example", "actor": "agent", "agent_actors": ["agent"]}
    return org, config


def test_startup_and_recovery_are_authority_bound():
    org, config = fixture()
    check_startup(org, config, b"config", "rev", committed=(b"config", "rev"))
    check_startup(
        org, config, b"config", "rev", committed=None, pending=(b"config", "rev")
    )
    with pytest.raises(ValueError):
        check_startup(
            org, config, b"old", "rev", committed=None, pending=(b"config", "rev")
        )
    with pytest.raises(ValueError):
        check_startup(
            org, config, b"config", "new", committed=None, pending=(b"config", "rev")
        )
    with pytest.raises(ValueError):
        check_startup(org, config, b"config", "new", committed=(b"config", "rev"))
    with pytest.raises(ValueError):
        check_startup(org, config, b"config", "rev", committed=None)


def test_removed_actor_or_channel_cannot_reopen_after_restart():
    org, config = fixture()
    no_channel = copy.deepcopy(org)
    no_channel["actors"][0].pop("telegram_bot")
    with pytest.raises(ValueError):
        check_startup(
            no_channel, config, b"config", "rev", committed=(b"config", "rev")
        )
    org["actors"] = []
    with pytest.raises(ValueError):
        check_startup(org, config, b"config", "rev", committed=(b"config", "rev"))


def test_duplicate_routes_rejected():
    org, config = fixture()
    config["additional_issuers"] = [{"actor": "agent"}]
    with pytest.raises(ValueError):
        check_startup(org, config, b"config", "rev", committed=(b"config", "rev"))


def test_policy_writer_waits_until_launcher_is_ready(monkeypatch):
    guard = threading.Lock()
    entered, ready, writer_acquired = (threading.Event() for _ in range(3))

    @contextmanager
    def policy_lock(_path, *, exclusive):
        with guard:
            yield

    monkeypatch.setattr("phantomdocs.view_agent_startup.policy_guard", policy_lock)
    monkeypatch.setattr("phantomdocs.view_agent_startup._check_locked", lambda *_: None)

    def wait_for_ready():
        entered.set()
        assert ready.wait(3)

    def launch():
        launch_protected(
            org_path="org",
            config_path="config",
            journal_path="journal",
            committed_path="committed",
            policy_lock="lock",
            start_and_wait=wait_for_ready,
        )

    def writer():
        with guard:
            writer_acquired.set()

    launcher = threading.Thread(target=launch)
    launcher.start()
    assert entered.wait(3)
    writer_thread = threading.Thread(target=writer)
    writer_thread.start()
    assert not writer_acquired.wait(0.1)
    ready.set()
    launcher.join(3)
    writer_thread.join(3)
    assert writer_acquired.is_set()
