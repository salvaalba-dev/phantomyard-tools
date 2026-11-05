"""Validation tests for synthetic host configuration and policy."""

import json
from pathlib import Path

import pytest
import test_workflow_scan as fixtures
import yaml

from phantomdocs import workflow_admission_config as admission_config
from phantomdocs.workflows import resolve_processor


@pytest.fixture
def config():
    return {
        "identity_map": "/etc/example/identities.json",
        "ledger_path": "/var/lib/example/jobs.sqlite",
        "policy_lock": "/etc/example/policy.lock",
        "org_path": "/etc/example/org.yaml",
        "installation_path": "/etc/example/installation.json",
        "processor_config_path": "/etc/example/bot.toml",
        "processor_state_path": None,
        "socket_path": "/run/example/admission.sock",
        "store_path": "/var/lib/example/store",
        "server_uid": 321,
    }


def set_payload(monkeypatch, payload):
    monkeypatch.setattr(admission_config, "_read_protected", lambda _path: payload)


def test_valid_config_is_loaded(config, monkeypatch):
    set_payload(monkeypatch, json.dumps(config).encode())
    assert admission_config.load_config("/etc/example/host.json") == config


@pytest.mark.parametrize(
    "path", ["relative", "/x/../other", "/x//other", "/x/./other", "/x/\x00"]
)
def test_unsafe_paths_are_rejected(config, monkeypatch, path):
    config["identity_map"] = path
    set_payload(monkeypatch, json.dumps(config).encode())
    with pytest.raises(ValueError, match="unsafe"):
        admission_config.load_config("/etc/example/host.json")


def test_duplicate_json_and_extra_fields_are_rejected(config, monkeypatch):
    set_payload(monkeypatch, b'{"identity_map":"/x","identity_map":"/y"}')
    with pytest.raises(ValueError, match="invalid protected JSON"):
        admission_config.load_config("/etc/example/host.json")
    config["allow_untrusted_actor"] = True
    set_payload(monkeypatch, json.dumps(config).encode())
    with pytest.raises(ValueError, match="configuration"):
        admission_config.load_config("/etc/example/host.json")


def test_organization_must_be_valid_and_unambiguous(monkeypatch):
    org = fixtures.system.__wrapped__()[2]
    set_payload(monkeypatch, yaml.safe_dump(org).encode())
    assert admission_config.load_policy("/etc/example/org.yaml") == org
    set_payload(monkeypatch, b"version: 1\nversion: 2\n")
    with pytest.raises(ValueError, match="organization"):
        admission_config.load_policy("/etc/example/org.yaml")
    set_payload(monkeypatch, b"!!python/object:builtins.object {}")
    with pytest.raises(ValueError, match="organization"):
        admission_config.load_policy("/etc/example/org.yaml")


def test_installation_uses_existing_contract_validation(monkeypatch):
    installation = fixtures.system.__wrapped__()[1]
    set_payload(monkeypatch, json.dumps(installation).encode())
    assert (
        admission_config.load_installation("/etc/example/installation.json")
        == installation
    )
    set_payload(monkeypatch, b"{}")
    with pytest.raises(ValueError):
        admission_config.load_installation("/etc/example/installation.json")


@pytest.mark.parametrize("state", [None, {}, {"default_persona": "state-actor"}])
def test_processor_matches_native_resolver(tmp_path, monkeypatch, state):
    config_path = tmp_path / "bot.toml"
    config_path.write_text('default_persona = "config-actor"\n', encoding="utf-8")
    state_path = None
    if state is not None:
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(
        admission_config, "_read_protected", lambda path: Path(path).read_bytes()
    )
    assert admission_config.load_processor(
        config_path, state_path
    ) == resolve_processor(config_path, state_path)


def test_processor_does_not_ignore_invalid_explicit_state(monkeypatch):
    set_payload(monkeypatch, b'{"default_persona":null}')
    with pytest.raises(ValueError, match="state"):
        admission_config.load_processor(
            "/etc/example/bot.toml", "/etc/example/state.json"
        )
