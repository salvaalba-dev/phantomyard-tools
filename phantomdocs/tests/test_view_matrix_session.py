from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from phantomdocs import view_matrix_session
from phantomdocs.workflows import WorkflowError


def test_delivery_is_bound_to_session_and_authority(monkeypatch):
    state = {"locked": False, "changed": False, "sent": []}
    recipient = SimpleNamespace(persona="agent", human=None, scope_id="all")

    class Directory:
        def permits(self, current, resource):
            return current == recipient and resource["project"] == "project"

    class Gate:
        def identified_scope(self, headers):
            assert headers == "session"
            if state["changed"]:
                return SimpleNamespace(persona="other", human=None), Directory()
            return recipient, Directory()

    @contextmanager
    def authority(actor):
        assert actor == "agent"
        state["locked"] = True
        try:
            yield {"organization": {"id": "org"}}, {}, object()
        finally:
            state["locked"] = False

    def read(**kwargs):
        assert state["locked"] and kwargs["actor"] == "agent"
        return "verified"

    def send(text):
        assert state["locked"]
        state["sent"].append(text)

    monkeypatch.setattr(view_matrix_session, "read_matrix", read)
    monkeypatch.setattr(view_matrix_session, "project_category", lambda *args: "cat")
    args = {
        "gate": Gate(),
        "headers": "session",
        "version": "v2",
        "bindings": {
            "agent": {
                "versions": {},
                "root_ref": "root",
                "domain": "dept",
                "project_type": "project",
                "scope_id": "project",
            }
        },
        "authority": authority,
        "send": send,
    }
    view_matrix_session.deliver_matrix(**args)
    assert state["sent"] == ["verified"]

    def revoked(**kwargs):
        state["changed"] = True
        return "must not be delivered"

    monkeypatch.setattr(view_matrix_session, "read_matrix", revoked)
    with pytest.raises(WorkflowError):
        view_matrix_session.deliver_matrix(**args)
    assert state["sent"] == ["verified"]
    assert not state["locked"]
