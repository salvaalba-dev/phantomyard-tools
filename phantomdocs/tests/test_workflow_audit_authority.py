from contextlib import contextmanager

import pytest

from phantomdocs.workflow_audit_authority import (
    bind_authority,
    guarded_authorizer,
    recheck_authority,
)
from phantomdocs.workflows import WorkflowError


def test_missing_or_denied_item_blocks_entire_matrix(monkeypatch):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.can_read",
        lambda org, actor, cat: cat == "allowed",
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.policy_hash", lambda org: org["revision"]
    )
    evidence = {"items": [{"id": "a"}, {"id": "b"}], "matrix_text": "b can appear here"}
    with pytest.raises(WorkflowError):
        bind_authority(
            evidence, {"revision": "one"}, "alma", {"a": "allowed"}, "allowed"
        )
    with pytest.raises(WorkflowError):
        bind_authority(
            evidence,
            {"revision": "one"},
            "alma",
            {"a": "allowed", "b": "denied"},
            "allowed",
        )


def test_changed_policy_or_actor_invalidates_existing_snapshot(monkeypatch):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.can_read", lambda org, actor, cat: True
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.policy_hash", lambda org: org["revision"]
    )
    evidence = bind_authority(
        {"items": [{"id": "a"}]},
        {"revision": "one"},
        "alma",
        {"a": "allowed"},
        "allowed",
    )
    recheck_authority(evidence, {"revision": "one"}, "alma")
    with pytest.raises(WorkflowError):
        recheck_authority(evidence, {"revision": "two"}, "alma")
    with pytest.raises(WorkflowError):
        recheck_authority(evidence, {"revision": "one"}, "other")


def test_inheritance_keeps_every_individual_restriction(monkeypatch):
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.can_read",
        lambda org, actor, cat: cat != "restricted",
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.policy_hash", lambda org: "revision"
    )
    evidence = {"items": [{"id": "a"}, {"id": "b"}]}
    accepted = bind_authority(
        evidence, {}, "alma", {}, "project", inherited_category="project"
    )
    assert accepted["authority"]["inherited_category"] == "project"
    with pytest.raises(WorkflowError):
        bind_authority(
            evidence,
            {},
            "alma",
            {"a": ["project", "restricted"]},
            "project",
            inherited_category="project",
        )


def test_guard_uses_protected_mapping_and_rechecks_each_call(monkeypatch):
    config = {
        "version": 1,
        "identity_map": "/identity",
        "policy_lock": "/lock",
        "org_path": "/org",
        "classifications": "/labels",
    }
    labels = {
        "version": 1,
        "root_ref": "gdrive://root",
        "matrix_ref": "gdrive://matrix",
        "matrix_category": "allowed",
        "items": {"a": "allowed"},
    }
    state = {"locked": False, "allowed": True}

    @contextmanager
    def guard(path, *, exclusive):
        assert path == "/lock" and not exclusive
        state["locked"] = True
        try:
            yield
        finally:
            state["locked"] = False

    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority._json",
        lambda path: config if path == "/config" else labels,
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority._read_protected", lambda path: b"org"
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.parse_policy",
        lambda raw: {"revision": "one"},
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.resolve_local_actor", lambda path: "alma"
    )
    monkeypatch.setattr("phantomdocs.workflow_audit_authority.policy_guard", guard)
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.can_read",
        lambda org, actor, cat: state["locked"] and state["allowed"],
    )
    monkeypatch.setattr(
        "phantomdocs.workflow_audit_authority.policy_hash", lambda org: org["revision"]
    )
    evidence = {
        "root_ref": "gdrive://root",
        "matrix_ref": "gdrive://matrix",
        "items": [{"id": "a"}],
    }
    with guarded_authorizer("/config") as authorize:
        authorize(evidence)
        state["allowed"] = False
        with pytest.raises(WorkflowError):
            authorize(evidence)
    assert state["locked"] is False


def test_peer_authorization_holds_both_locks_and_uses_trusted_bindings(monkeypatch):
    from contextlib import contextmanager

    from phantomdocs.workflow_audit_authority import guarded_peer_authorizer

    events = []
    config = {
        "version": 1,
        "identity_map": "/map",
        "policy_lock": "/policy.lock",
        "org_path": "/org",
        "native_manifest": "/store/manifest.yaml",
        "root_ref": "gdrive://trusted-root",
        "matrix_ref": "gdrive://trusted-matrix",
        "project_category": "project",
    }

    @contextmanager
    def guard(label):
        events.append("enter " + label)
        try:
            yield
        finally:
            events.append("leave " + label)

    module = "phantomdocs.workflow_audit_authority."
    monkeypatch.setattr(module + "_json", lambda path: config)
    monkeypatch.setattr(module + "resolve_peer_actor", lambda path, peer: "alma")
    monkeypatch.setattr(
        module + "policy_guard", lambda path, exclusive: guard("policy")
    )
    monkeypatch.setattr(module + "_read_protected", lambda path: b"policy")
    monkeypatch.setattr(module + "parse_policy", lambda data: {"policy": True})
    monkeypatch.setattr(module + "manifest_lock", lambda path: guard("manifest"))
    monkeypatch.setattr(module + "load", lambda path: {"nodes": []})

    def check(evidence, org, actor, manifest, **binding):
        assert events == ["enter policy", "enter manifest"]
        assert actor == "alma" and org == {"policy": True} and manifest == {"nodes": []}
        assert binding == {
            "root_ref": "gdrive://trusted-root",
            "matrix_ref": "gdrive://trusted-matrix",
            "project_category": "project",
        }
        assert evidence == {"snapshot": True}

    monkeypatch.setattr(module + "authorize_observations", check)
    with guarded_peer_authorizer("/config", object()) as authorize:
        authorize({"snapshot": True})
    assert events == [
        "enter policy",
        "enter manifest",
        "leave manifest",
        "leave policy",
    ]
