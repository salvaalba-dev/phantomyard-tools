"""Commit receipt ordering and configuration pinning in the existing transaction."""

import copy

import pytest
from test_policy_fanout import run
from test_policy_fanout import trial as trial  # noqa: PLC0414 -- pytest fixture

from phantomdocs import workflow_bridge_policy as publisher
from phantomdocs.workflow_policy_commit import _decode, receipt
from phantomdocs.workflow_policy_guard import policy_guard


@pytest.fixture
def committed(trial, monkeypatch):
    trial["committed"] = None
    trial["receipts"] = []
    trial["commit_failure"] = False

    def inspect(path, source):
        assert trial["policy"]
        return copy.deepcopy(trial["committed"])

    def write(path, source, payload):
        assert trial["policy"] and trial["pending"]
        assert all(
            trial["files"][p] == payload for p in ("/source", "/bridge", "/docs")
        )
        if trial["commit_failure"]:
            raise OSError("synthetic receipt fsync failure")
        trial["committed"] = receipt(source, payload)
        trial["receipts"].append(trial["committed"])

    monkeypatch.setattr(publisher, "inspect_committed_locked", inspect)
    monkeypatch.setattr(publisher, "write_committed_locked", write)
    return trial


def test_receipt_follows_verified_copies_and_successful_restart(committed):
    committed["nested"] = False
    assert run(commit_witness=True) == "restarted"
    assert len(committed["receipts"]) == 1
    assert committed["pending"] is None
    assert run(commit_witness=True) == "synchronized"
    assert len(committed["receipts"]) == 1


@pytest.mark.parametrize("failure", ["/bridge", "/docs", "start", "receipt"])
def test_failure_keeps_old_receipt_and_matching_retry_is_required(committed, failure):
    committed["committed"] = receipt("/source", b"previous")
    previous = copy.deepcopy(committed["committed"])
    committed["fail"] = None if failure == "receipt" else failure
    committed["commit_failure"] = failure == "receipt"
    with pytest.raises((OSError, RuntimeError)):
        run(commit_witness=True)
    assert committed["committed"] == previous
    assert committed["pending"]["commit_witness"] is True
    with pytest.raises(ValueError):
        run()  # a non-witness recoverer must not clear this transaction
    committed["fail"] = None
    committed["commit_failure"] = False
    assert run(commit_witness=True) == "restarted"
    assert committed["pending"] is None


def test_empty_receipt_bootstrap_is_journaled_without_a_bridge_restart(committed):
    payload = committed["files"]["/source"]
    committed["files"].update({"/bridge": payload, "/docs": payload})
    assert run(commit_witness=True) == "synchronized"
    assert committed["actions"] == ["is-active"]
    assert committed["copies"] == [] and len(committed["receipts"]) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b"[]",
        b"not-json",
        b"\xff",
        b'{"source":"a","source":"b"}',
        b"x" * 8193,
    ],
)
def test_unrecognized_or_torn_receipts_never_authorize(raw):
    with pytest.raises(ValueError):
        _decode(raw, "/source")


def test_receipt_size_is_checked_before_a_publication_can_be_created():
    with pytest.raises(ValueError, match="limit"):
        receipt("/" + "x" * 8192, b"synthetic")


@pytest.mark.parametrize(
    "timeout", [0, -1, True, "bad", float("nan"), float("inf"), 61]
)
def test_invalid_lock_deadline_fails_before_platform_or_file_access(timeout):
    with pytest.raises(ValueError):  # noqa: SIM117
        with policy_guard("/synthetic/policy.lock", exclusive=False, timeout=timeout):
            pytest.fail("invalid deadline accepted")


@pytest.mark.parametrize(
    "config",
    [
        {"schema_version": 1},
        {"schema_version": 2},
        {"schema_version": 2, "policy_lock": "/another/lock"},
    ],
)
def test_guarded_startup_cannot_use_a_legacy_or_different_lock_contract(
    monkeypatch, config
):
    import json

    from phantomdocs import view_agent_startup as startup

    monkeypatch.setattr(
        startup, "_read_protected", lambda _: json.dumps(config).encode()
    )
    with pytest.raises(ValueError):
        startup._check_locked(
            "/source", "/config", "/journal", "/committed", "/lock", True
        )
