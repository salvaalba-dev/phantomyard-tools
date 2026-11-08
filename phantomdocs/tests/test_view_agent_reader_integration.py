"""Optional integration against an explicitly selected pinned viewer checkout."""

import importlib
import importlib.util
import os
from pathlib import Path

import pytest

from phantomdocs.view_agent_reader_patch import patch_reader


@pytest.mark.skipif(
    not os.environ.get("PHANTOMVIEW_READER_REFERENCE"),
    reason="Viewer checkout is optional",
)
def test_reader_agent_session_filters_and_revokes(monkeypatch, tmp_path):
    directory = Path(os.environ["PHANTOMVIEW_READER_REFERENCE"])
    if not directory.is_absolute():
        raise ValueError("An explicit viewer source directory is required")
    monkeypatch.syspath_prepend(str(directory))
    reader = importlib.import_module("identified_reader")
    fixture = importlib.import_module("test_identified_reader")
    candidate_path = tmp_path / "synthetic_agent_reader.py"
    candidate_path.write_bytes(patch_reader(Path(reader.__file__).read_bytes()))
    spec = importlib.util.spec_from_file_location(
        "synthetic_agent_reader", candidate_path
    )
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    monkeypatch.setattr(fixture, "reader", candidate)
    original = fixture.scoped_organization
    monkeypatch.setattr(
        fixture, "scoped_organization", lambda: original() | {"version": 1}
    )
    case = fixture.PublishedReaderTests()
    case.setUp()
    try:
        cookie = case.login()
        status, body, _ = case.request("GET", "/api/state", cookie=cookie)
        assert status == 200
        assert case.hidden not in {row["id"] for row in body["resources"]}
        case.org["policies"]["phantomview"]["persona_scope_grants"][
            "administrator"
        ] = []
        case.publish_authority()
        assert case.request("GET", "/api/state", cookie=cookie)[0] == 401
    finally:
        case.doCleanups()

