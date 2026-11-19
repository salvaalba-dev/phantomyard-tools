"""Reviewed PhantomOrg source changes and PR67 fanout form one transaction."""

import copy
import sys
from contextlib import contextmanager

import pytest
import yaml
from source_publication_fixture import model, snapshots
from test_policy_fanout import trial as trial  # noqa: PLC0414 -- pytest fixture

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs import workflow_phantomorg_candidate as source
from phantomdocs.access import can_read
from phantomdocs.workflow_policy_fanout import digest


@pytest.fixture
def source_trial(trial, monkeypatch):
    old, new = snapshots()
    trial["files"] = {"/source": old, "/bridge": old, "/docs": old, "/candidate": new}
    trial["permissions"]["/source"] = {"uid": 0, "gid": 0, "mode": 0o644, "xattrs": {}}
    monkeypatch.setattr(source, "policy_permissions", publisher.policy_permissions)

    @contextmanager
    def staged(path, payload):
        assert trial["policy"] and trial["pending"] is not None
        trial["files"]["/staged"] = payload
        try:
            yield "/staged"
        finally:
            del trial["files"]["/staged"]

    monkeypatch.setattr(source, "payload_file", staged)
    return trial


def options():
    old, new = snapshots()
    return {
        "source": "/source",
        "destination": ["/bridge", "/docs"],
        "lock_path": "/lock",
        "node": "/usr/bin/node",
        "resolver": "/resolver.js",
        "unit": "bridge.service",
        "candidate": "/candidate",
        "expected_source_sha256": digest(old),
        "candidate_sha256": digest(new),
        "organization": "sample-org",
    }


def test_source_and_all_copies_publish_in_one_lock_and_revoke_access(source_trial):
    state = source_trial
    before_permissions = copy.deepcopy(state["permissions"])
    assert can_read(yaml.safe_load(state["files"]["/source"]), "agent", "category-1")
    assert publisher.refresh(**options()) == "restarted"
    assert state["copies"] == ["/source", "/bridge", "/docs"]
    assert state["pending"] is None
    assert state["permissions"] == before_permissions
    for path in ("/source", "/bridge", "/docs"):
        assert state["files"][path] == snapshots()[1]
        assert not can_read(yaml.safe_load(state["files"][path]), "agent", "category-1")
    assert publisher.refresh(**options()) == "synchronized"
    assert state["copies"] == ["/source", "/bridge", "/docs"]


@pytest.mark.parametrize("fail_at", ["/source", "/bridge", "/docs", "start"])
def test_timer_resumes_source_transaction_without_candidate_file(source_trial, fail_at):
    state = source_trial
    state["fail"] = fail_at
    with pytest.raises((OSError, RuntimeError)):
        publisher.refresh(**options())
    assert state["pending"]["kind"] == source.KIND
    del state["files"]["/candidate"]
    state["fail"] = None
    recovery = {
        k: v
        for k, v in options().items()
        if k not in {"candidate", "expected_source_sha256", "candidate_sha256"}
    }
    assert publisher.refresh(**recovery) == "restarted"
    assert state["pending"] is None
    assert all(
        state["files"][p] == snapshots()[1] for p in ("/source", "/bridge", "/docs")
    )


@pytest.mark.parametrize(
    "bad",
    ["hash", "base", "organization", "references", "cycle", "duplicate", "incomplete"],
)
def test_invalid_or_unreviewed_candidates_leave_current_runtime_untouched(
    source_trial, bad
):
    state = source_trial
    args = options()
    raw = model()
    if bad == "hash":
        args["candidate_sha256"] = "0" * 64
    elif bad == "base":
        args["expected_source_sha256"] = "0" * 64
    elif bad == "organization":
        args["organization"] = "other-org"
    elif bad == "references":
        raw["actors"][0]["role"] = "unknown"
    elif bad == "cycle":
        raw["roles"][0]["reports_to"] = "reader"
    elif bad == "incomplete":
        raw = {"version": 1}
    if bad in {"references", "cycle", "incomplete", "duplicate"}:
        payload = yaml.safe_dump(raw).encode()
        if bad == "duplicate":
            payload += b"version: 1\n"
        state["files"]["/candidate"] = payload
        args["candidate_sha256"] = digest(payload)
    before = copy.deepcopy(state["files"])
    with pytest.raises(ValueError):
        publisher.refresh(**args)
    assert state["files"] == before
    assert state["active"] and state["pending"] is None
    assert state["actions"] == ["is-active"]


def test_nested_bridge_prestart_uses_recorded_candidate(source_trial):
    source_trial["nested"] = True
    assert publisher.refresh(**options()) == "restarted"
    assert source_trial["pending"] is None


@pytest.mark.parametrize("drift", ["source", "permissions", "review", "payload"])
def test_pending_source_or_review_drift_remains_blocked(source_trial, drift):
    state = source_trial
    state["fail"] = "/docs"
    with pytest.raises(OSError):
        publisher.refresh(**options())
    state["fail"] = None
    args = options()
    if drift == "source":
        raw = model()
        raw["organization"]["name"] = "Unrecorded source"
        state["files"]["/source"] = yaml.safe_dump(raw).encode()
    elif drift == "permissions":
        state["permissions"]["/source"]["mode"] = 0o600
    elif drift == "payload":
        state["pending"]["candidate"] = "invalid base64"
    else:
        args["expected_source_sha256"] = "0" * 64
    pending = copy.deepcopy(state["pending"])
    with pytest.raises(ValueError):
        publisher.refresh(**args)
    assert state["pending"] == pending
    assert state["copies"] == ["/source", "/bridge"]


def test_missing_review_or_candidate_prestart_never_controls_service(source_trial):
    for changes in (
        {"expected_source_sha256": None},
        {"candidate_sha256": None},
        {"prestart": True},
    ):
        args = options()
        args.update(changes)
        with pytest.raises(ValueError):
            publisher.refresh(**args)
    assert source_trial["actions"] == []


@pytest.mark.parametrize("failure", ["source-tenant", "validator", "bridge"])
def test_fresh_proposal_rejection_keeps_existing_service(
    source_trial, monkeypatch, failure
):
    state = source_trial
    if failure == "source-tenant":
        raw = model()
        raw["organization"]["id"] = "different-org"
        state["files"]["/source"] = yaml.safe_dump(raw).encode()
    elif failure == "validator":
        monkeypatch.setitem(sys.modules, "phantomorg.validator", None)
    else:

        def incompatible(*args, **kwargs):
            raise publisher.BridgeRefreshError("incompatible bridge candidate")

        monkeypatch.setattr(publisher, "_derive_both", incompatible)
    before = copy.deepcopy(state["files"])
    args = options()
    args["expected_source_sha256"] = digest(before["/source"])
    with pytest.raises((ValueError, publisher.BridgeRefreshError)):
        publisher.refresh(**args)
    assert state["files"] == before
    assert state["active"] and state["pending"] is None
    assert state["actions"] == ["is-active"]
