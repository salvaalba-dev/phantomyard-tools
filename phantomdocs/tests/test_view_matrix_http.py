import hashlib
from types import SimpleNamespace

import pytest

from phantomdocs import view_matrix_http, view_matrix_http_patch
from phantomdocs.workflows import WorkflowError


def test_patch_rejects_changed_reader(monkeypatch):
    source = (
        b"def dispatch(method, parsed):\n    try:\n        if False:\n            pass\n"
        + (view_matrix_http_patch.ANCHOR.encode())
        + b"            pass\n    except ValueError:\n        pass\n"
    )
    monkeypatch.setattr(
        view_matrix_http_patch, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()
    )
    candidate = view_matrix_http_patch.patch_http(source)
    assert b"/api/matrix/" in candidate
    with pytest.raises(ValueError):
        view_matrix_http_patch.patch_http(source + b"# changed\n")


def test_http_refuses_failure_and_bounds_delivery(monkeypatch):
    events = []

    class Connection:
        def gettimeout(self):
            return None

        def settimeout(self, value):
            events.append(("timeout", value))

    handler = SimpleNamespace(
        headers={},
        connection=Connection(),
        send=lambda status, body: events.append((status, body)),
    )
    monkeypatch.setenv("PHANTOMVIEW_MATRIX_ROUTES", "/trusted/routes.json")
    monkeypatch.setattr(
        view_matrix_http, "_json", lambda path: {"version": 1, "routes": {}}
    )
    monkeypatch.setattr(
        view_matrix_http, "deliver", lambda **kwargs: kwargs["send"]("text")
    )
    assert view_matrix_http.dispatch(
        handler, SimpleNamespace(gate=object()), "/api/matrix/v2"
    )
    assert events == [
        ("timeout", 5),
        (200, {"version": "v2", "content": "text"}),
        ("timeout", None),
    ]
    events.clear()

    def deny(**kwargs):
        raise WorkflowError("denied")

    monkeypatch.setattr(view_matrix_http, "deliver", deny)
    assert view_matrix_http.dispatch(
        handler, SimpleNamespace(gate=object()), "/api/matrix/v2"
    )
    assert events == [(404, {"error": "Matrix unavailable"})]
