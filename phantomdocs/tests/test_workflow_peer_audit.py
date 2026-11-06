"""Audit views expose only a minimal, currently authorized document history."""

import json
import os
from copy import deepcopy

import pytest
import test_workflow_scan as fixtures

from phantomdocs.workflow_peer_audit import filtered_audit, load_audit_file


@pytest.fixture
def system():
    data = fixtures.system.__wrapped__()
    fixtures.index(data, category="category-2")
    hidden = deepcopy(data[6]["nodes"][1])
    hidden.update(
        {
            "category": "category-3",
            "mac": "4" * 64,
            "urn": "urn:example-org:doc:project-reports/secret",
            "slug": "secret",
        }
    )
    data[6]["nodes"].append(hidden)
    return data


def event(urn, mac, *, action="add", actor="coordinator", details=None):
    return {
        "ts": "2026-01-01T00:00:00Z",
        "actor": actor,
        "action": action,
        "urn": urn,
        "mac": mac,
        "details": details or {"secret": "excluded"},
        "prev": "private-previous-hash",
    }


def view(system, entries, limit=50):
    raw = b"".join((json.dumps(item) + "\n").encode() for item in entries)
    return filtered_audit(
        raw, org=system[2], actor="coordinator", manifest=system[6], limit=limit
    )


def test_returns_only_authorized_and_redacted_entries(system):
    visible = event("urn:example-org:doc:project-reports/source", "2" * 64)
    hidden = event("urn:example-org:doc:project-reports/secret", "4" * 64)
    other = event(
        "urn:example-org:doc:project-reports/source", "2" * 64, action="classification"
    )
    result = view(system, [hidden, visible, other])
    assert result == [{k: visible[k] for k in ("ts", "actor", "action", "urn", "mac")}]
    assert "secret" not in json.dumps(result)
    assert "prev" not in result[0]


def test_refuses_stale_or_mismatched_versions(system):
    entry = event("urn:example-org:doc:project-reports/source", "4" * 64)
    assert view(system, [entry]) == []


def test_limit_applies_after_filtering(system):
    visible = event("urn:example-org:doc:project-reports/source", "2" * 64)
    hidden = event("urn:example-org:doc:project-reports/secret", "4" * 64)
    assert len(view(system, [visible, hidden], limit=1)) == 1


@pytest.mark.parametrize("limit", [0, -1, 101, True, "5"])
def test_rejects_invalid_limit(system, limit):
    with pytest.raises(ValueError):
        view(system, [], limit=limit)


@pytest.mark.parametrize("raw", [b'{"x":1}', b'{"x":1,"x":2}\n', b'{"x":NaN}\n'])
def test_rejects_incomplete_or_malformed_log(system, raw):
    with pytest.raises(ValueError):
        filtered_audit(
            raw, org=system[2], actor="coordinator", manifest=system[6], limit=50
        )


def test_load_rejects_symbolic_link(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("requires no-follow support")
    real = tmp_path / "real"
    real.write_bytes(b"{}\n")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        load_audit_file(str(link))
