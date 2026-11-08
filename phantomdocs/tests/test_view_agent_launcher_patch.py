import hashlib
import importlib
import importlib.util
import os
from pathlib import Path

import pytest

from phantomdocs import view_agent_launcher_patch as patcher


def test_rejects_unknown_launcher():
    with pytest.raises(ValueError, match="Unsupported"):
        patcher.patch_launcher(b"different")


def test_candidate_requires_explicit_configured_routes(monkeypatch):
    source = b"""FIELDS = {'actor'}
def validate(value):
    if set(value) - (FIELDS | {'additional_issuers', 'reviewed_knowledge'}):
        raise ValueError('unexpected')
    result = dict(value)
    return result


def issuer_routes(config):
    return []


def build(config):
    options = {'additional_issuers': config['additional_issuers']} if 'additional_issuers' in config else {}
    if 'reviewed_knowledge' in config:
        options['reviewed_knowledge'] = config['reviewed_knowledge']
    return options
"""
    monkeypatch.setattr(patcher, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    namespace = {}
    exec(patcher.patch_launcher(source), namespace)  # noqa: S102 - synthetic source
    validate, build = namespace["validate"], namespace["build"]
    assert validate({"actor": "one"}) == {"actor": "one"}
    configured = validate(
        {
            "actor": "one",
            "additional_issuers": [{"actor": "two"}],
            "agent_actors": ["two"],
        }
    )
    assert build(configured)["agent_actors"] == ["two"]
    for invalid in ("two", ["other"], ["two", "two"], [["two"]]):
        with pytest.raises(ValueError):
            validate({"actor": "one", "agent_actors": invalid})


def test_rejects_missing_anchor(monkeypatch):
    source = b"print('different')\n"
    monkeypatch.setattr(patcher, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    with pytest.raises(ValueError, match="composition changed"):
        patcher.patch_launcher(source)


@pytest.mark.skipif(
    not os.environ.get("PHANTOMVIEW_READER_REFERENCE"),
    reason="Viewer checkout is optional",
)
def test_pinned_launcher_preserves_human_configuration(monkeypatch, tmp_path):
    directory = Path(os.environ["PHANTOMVIEW_READER_REFERENCE"])
    if not directory.is_absolute():
        raise ValueError("An explicit viewer source directory is required")
    monkeypatch.syspath_prepend(str(directory))
    original = importlib.import_module("reader_launch")
    fixture = importlib.import_module("test_reader_launch")
    candidate_path = tmp_path / "candidate_launcher.py"
    candidate_path.write_bytes(
        patcher.patch_launcher(Path(original.__file__).read_bytes())
    )
    spec = importlib.util.spec_from_file_location("candidate_launcher", candidate_path)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    config = fixture.example()
    assert candidate.validate(config) == original.validate(config)
    name = config["actor"]
    assert candidate.validate(config | {"agent_actors": [name]})["agent_actors"] == [
        name
    ]
    with pytest.raises(ValueError):
        candidate.validate(config | {"agent_actors": ["unknown"]})
