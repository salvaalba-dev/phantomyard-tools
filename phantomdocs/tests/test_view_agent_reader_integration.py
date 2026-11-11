"""Optional integration against an explicitly selected pinned viewer checkout."""

import importlib
import importlib.util
import os
from http.cookies import SimpleCookie
from pathlib import Path
from types import SimpleNamespace

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
    original_reader = candidate.PublishedReader

    class ConfiguredReader(original_reader):
        def __init__(self, **kwargs):
            super().__init__(**(kwargs | {"agent_actors": {"administrator"}}))

    candidate.PublishedReader = ConfiguredReader
    monkeypatch.setattr(fixture, "reader", candidate)
    original = fixture.scoped_organization

    def organization_with_channel():
        org = original() | {"version": 1}
        next(actor for actor in org["actors"] if actor["id"] == "administrator")[
            "telegram_bot"
        ] = "@example_bot"
        return org

    monkeypatch.setattr(fixture, "scoped_organization", organization_with_channel)
    case = fixture.PublishedReaderTests()
    case.setUp()
    try:
        cookie = case.login()
        status, body, _ = case.request("GET", "/api/state", cookie=cookie)
        assert status == 200
        assert case.hidden not in {row["id"] for row in body["resources"]}
        link = case.application.gate.issue_identified(
            case.authorization(),
            case.options["origin"],
            **fixture.context("102", "administrator", scope_id="agent-all"),
        )
        status, _, set_cookie = case.request(
            "POST", "/api/redeem", {"code": link.split("#c=")[1]}
        )
        assert status == 200
        parsed = SimpleCookie(set_cookie)
        aggregate_cookie = "phantomview=" + parsed["phantomview"].value
        status, aggregate, _ = case.request(
            "GET", "/api/state", cookie=aggregate_cookie
        )
        assert status == 200, aggregate
        assert aggregate["scope_id"] == "agent-all"
        assert case.hidden not in {row["id"] for row in aggregate["resources"]}
        native = importlib.import_module("persona_conversation")
        monkeypatch.setattr(native.PersonaAssistant, "available", lambda *_: True)
        app = candidate.PublishedReader(
            **(case.options | {"conversation_socket": "/run/example/native.sock"})
        )
        try:
            assistant = app.consultations.assistant
            monkeypatch.setattr(
                app.gate,
                "identified_scope",
                lambda _headers: (SimpleNamespace(human=None), None),
            )
            assert assistant.available({}) is False
            monkeypatch.setattr(
                app.gate,
                "identified_scope",
                lambda _headers: (SimpleNamespace(human="h"), None),
            )
            assert assistant.available({}) is True
        finally:
            app.consultations.close()
        case.org["policies"]["phantomview"]["persona_scope_grants"][
            "administrator"
        ] = []
        case.publish_authority()
        assert case.request("GET", "/api/state", cookie=cookie)[0] == 401
        assert case.request("GET", "/api/state", cookie=aggregate_cookie)[0] == 401
    finally:
        case.doCleanups()


@pytest.mark.skipif(
    not os.environ.get("PHANTOMVIEW_READER_REFERENCE"),
    reason="Viewer checkout is optional",
)
def test_configured_agent_and_existing_human_routes_coexist(monkeypatch, tmp_path):
    directory = Path(os.environ["PHANTOMVIEW_READER_REFERENCE"])
    if not directory.is_absolute():
        raise ValueError("An explicit viewer source directory is required")
    monkeypatch.syspath_prepend(str(directory))
    reader = importlib.import_module("identified_reader")
    fixture = importlib.import_module("test_identified_reader")
    candidate_path = tmp_path / "mixed_agent_reader.py"
    candidate_path.write_bytes(patch_reader(Path(reader.__file__).read_bytes()))
    spec = importlib.util.spec_from_file_location("mixed_agent_reader", candidate_path)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    monkeypatch.setattr(fixture, "reader", candidate)
    original = fixture.scoped_organization

    def organization_with_channel():
        org = original() | {"version": 1}
        next(actor for actor in org["actors"] if actor["id"] == "treasurer")[
            "telegram_bot"
        ] = "@example_bot"
        return org

    monkeypatch.setattr(fixture, "scoped_organization", organization_with_channel)
    case = fixture.PublishedReaderTests()
    case.setUp()
    try:
        options = case.multiple_options() | {"agent_actors": {"treasurer"}}
        app = candidate.PublishedReader(**options)
        try:
            with pytest.raises(ValueError):
                app.gate.issue_identified(
                    case.authorization(),
                    app.gate.origin,
                    **fixture.context("unknown", "administrator", scope_id="example"),
                )
            human = app.gate.issue_identified(
                case.authorization(),
                app.gate.origin,
                **fixture.context("102", "administrator", scope_id="example"),
            )
            recipient = app.gate.recipient_links[
                app.gate.digest(human.split("#c=")[1])
            ][0]
            assert recipient.human is not None and recipient.persona == "administrator"
            agent = app.gate.issue_identified(
                case.authorization(case.secondary_key),
                app.gate.origin,
                **fixture.context("agent", "treasurer", scope_id="agent-all"),
            )
            recipient = app.gate.recipient_links[
                app.gate.digest(agent.split("#c=")[1])
            ][0]
            assert recipient.human is None and recipient.persona == "treasurer"
            assert recipient.scope_id == "agent-all"
        finally:
            if app.consultations is not None:
                app.consultations.close()
        with pytest.raises(ValueError):
            candidate.PublishedReader(**(options | {"agent_actors": {"missing"}}))
    finally:
        case.doCleanups()
