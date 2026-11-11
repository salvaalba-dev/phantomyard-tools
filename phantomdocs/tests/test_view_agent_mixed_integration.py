"""Optional integration against the explicitly pinned composed viewer."""

import base64
import importlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

from phantomdocs.view_agent_mixed_patch import patch_reader


@pytest.mark.skipif(
    not os.environ.get("PHANTOMVIEW_MIXED_REFERENCE"),
    reason="Viewer checkout is optional",
)
def test_human_and_agent_signers_share_route_without_impersonation(
    monkeypatch, tmp_path
):
    directory = Path(os.environ["PHANTOMVIEW_MIXED_REFERENCE"])
    if not directory.is_absolute():
        raise ValueError("An explicit viewer source directory is required")
    monkeypatch.syspath_prepend(str(directory))
    reader = importlib.import_module("identified_reader")
    fixture = importlib.import_module("test_identified_reader")
    target = tmp_path / "mixed_reader.py"
    target.write_bytes(patch_reader(Path(reader.__file__).read_bytes()))
    spec = importlib.util.spec_from_file_location("mixed_reader", target)
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    monkeypatch.setattr(fixture, "reader", candidate)
    original = fixture.scoped_organization

    def organization_with_channel():
        org = original() | {"version": 1}
        next(actor for actor in org["actors"] if actor["id"] == "administrator")[
            "telegram_bot"
        ] = "@example_bot"
        return org

    monkeypatch.setattr(
        fixture, "scoped_organization", organization_with_channel
    )
    case = fixture.PublishedReaderTests()
    case.setUp()
    try:
        key = fixture.PrivateKey()
        public = key.public_key_xonly.format().hex()
        options = case.options | {
            "identities": [*case.options["identities"], public],
            "agent_actors": {"administrator"},
            "mixed_agent_signers": {"administrator": [public]},
        }
        app = candidate.PublishedReader(**options)
        try:
            human = app.gate.issue_identified(
                case.authorization(),
                app.gate.origin,
                **fixture.context("102", "administrator", scope_id="example"),
            )
            assert (
                app.gate.recipient_links[app.gate.digest(human.split("#c=")[1])][
                    0
                ].human
                is not None
            )
            agent = app.gate.issue_identified(
                case.authorization(key),
                app.gate.origin,
                **fixture.context("agent", "administrator", scope_id="agent-all"),
            )
            assert (
                app.gate.recipient_links[app.gate.digest(agent.split("#c=")[1])][
                    0
                ].human
                is None
            )
            event = json.loads(base64.b64decode(case.authorization()[6:]))
            event["pubkey"] = public
            forged = "Nostr " + base64.b64encode(json.dumps(event).encode()).decode()
            with pytest.raises(ValueError):
                app.gate.issue_identified(
                    forged,
                    app.gate.origin,
                    **fixture.context("agent", "administrator", scope_id="agent-all"),
                )
        finally:
            if app.consultations is not None:
                app.consultations.close()
    finally:
        case.doCleanups()
