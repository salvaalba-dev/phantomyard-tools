"""Snapshot validation and a publication command never compile persona state."""

from pathlib import Path
from types import ModuleType

import pytest
import yaml
from click.testing import CliRunner

from phantomorg.cli import main
from phantomorg.spec.loader import OrgSpecError
from phantomorg.validator import validate_org, validate_org_bytes

FIXTURE = Path(__file__).parent / "fixtures/source-publication-org.yaml"


def test_snapshot_and_path_validation_agree():
    spec, result = validate_org(FIXTURE)
    other, checked = validate_org_bytes(FIXTURE.read_bytes())
    assert spec.organization == other.organization
    assert result.errors == checked.errors == []
    assert result.warnings == checked.warnings


def test_snapshot_validation_never_reopens_or_writes_files(monkeypatch):
    payload = FIXTURE.read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("snapshot validation touched a file")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    spec, result = validate_org_bytes(payload)
    assert spec.organization.id == "sample-org" and result.ok


@pytest.mark.parametrize(
    "payload", [b"version: 1\nversion: 1\n", b"\xff", b"version: 9\n"]
)
def test_snapshot_parser_rejects_invalid_input(payload):
    with pytest.raises(OrgSpecError):
        validate_org_bytes(payload)


def test_snapshot_checks_references_and_hierarchy():
    raw = yaml.safe_load(FIXTURE.read_bytes())
    raw["actors"][0]["role"] = "missing"
    assert not validate_org_bytes(yaml.safe_dump(raw).encode())[1].ok
    raw = yaml.safe_load(FIXTURE.read_bytes())
    raw["roles"][0]["reports_to"] = "reader"
    assert not validate_org_bytes(yaml.safe_dump(raw).encode())[1].ok


def test_publish_command_delegates_once_without_persona_work(monkeypatch):
    calls = []
    module = ModuleType("phantomdocs.workflow_bridge_policy")
    module.refresh = lambda **kw: calls.append(kw) or "restarted"
    monkeypatch.setitem(__import__("sys").modules, module.__name__, module)
    result = CliRunner().invoke(
        main,
        [
            "publish-policy",
            "--candidate",
            "/candidate",
            "--source",
            "/source",
            "--destination",
            "/bridge",
            "--destination",
            "/docs",
            "--policy-lock",
            "/lock",
            "--expected-source-sha256",
            "1" * 64,
            "--candidate-sha256",
            "2" * 64,
            "--organization",
            "sample-org",
            "--resolver",
            "/resolver",
            "--unit",
            "bridge.service",
        ],
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0]["destination"] == ("/bridge", "/docs")
    assert "restarted" in result.output


def test_publish_help_does_not_require_phantomdocs(monkeypatch):
    monkeypatch.setitem(
        __import__("sys").modules, "phantomdocs.workflow_bridge_policy", None
    )
    result = CliRunner().invoke(main, ["publish-policy", "--help"])
    assert result.exit_code == 0 and "--candidate-sha256" in result.output
