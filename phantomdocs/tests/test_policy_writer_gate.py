"""Timer/prestart cannot bless a manual source edit after receipt activation."""

import copy

import pytest
from test_policy_commit import committed as committed  # noqa: PLC0414 -- fixture
from test_policy_fanout import run
from test_policy_fanout import trial as trial  # noqa: PLC0414 -- fixture

from phantomdocs import workflow_policy_watchdog as watchdog
from phantomdocs.workflow_policy_commit import receipt
from phantomdocs.workflow_policy_fanout import digest


def test_strict_reconcile_requires_explicit_reviewed_bootstrap(committed):
    before = copy.deepcopy(committed["files"])
    with pytest.raises(ValueError, match="receipt"):
        run(require_committed_source=True)
    assert committed["files"] == before and committed["pending"] is None
    assert (
        run(
            require_committed_source=True,
            bootstrap_source_sha256=digest(before["/source"]),
        )
        == "synchronized"
    )
    assert committed["committed"] == receipt("/source", before["/source"])


@pytest.mark.parametrize("prestart", [False, True])
def test_manual_source_edits_are_not_fanned_out_or_committed(committed, prestart):
    run(commit_witness=True)
    previous = copy.deepcopy(committed["committed"])
    copies = [committed["files"][p] for p in ("/bridge", "/docs")]
    committed["files"]["/source"] = b"version: 1\nmanual: true\n"
    with pytest.raises(ValueError, match="receipt"):
        run(require_committed_source=True, prestart=prestart)
    assert committed["committed"] == previous
    assert [committed["files"][p] for p in ("/bridge", "/docs")] == copies
    assert committed["pending"] is None


def test_unreviewed_bootstrap_and_rebootstrap_do_not_replace_receipts(committed):
    with pytest.raises(ValueError, match="bootstrap"):
        run(require_committed_source=True, bootstrap_source_sha256="a" * 64)
    source = committed["files"]["/source"]
    run(require_committed_source=True, bootstrap_source_sha256=digest(source))
    with pytest.raises(ValueError, match="bootstrap"):
        run(require_committed_source=True, bootstrap_source_sha256=digest(source))


def test_strict_reconciliation_still_completes_its_pinned_pending_record(committed):
    source = committed["files"]["/source"]
    committed["fail"] = "/docs"
    with pytest.raises(OSError):
        run(require_committed_source=True, bootstrap_source_sha256=digest(source))
    assert committed["pending"] and committed["committed"] is None
    committed["fail"] = None
    assert run(require_committed_source=True) == "restarted"
    assert committed["pending"] is None
    assert committed["committed"] == receipt("/source", source)


def test_watchdog_detects_manual_edit_even_when_all_copies_match(
    committed, monkeypatch
):
    run(commit_witness=True)
    for path in committed["files"]:
        committed["files"][path] = b"version: 1\nmanual: true\n"
    monkeypatch.setattr(
        watchdog, "inspect_committed_locked", lambda *args: committed["committed"]
    )
    result = watchdog.check(
        source="/source",
        destination=["/bridge", "/docs"],
        lock_path="/lock",
        require_committed=True,
    )
    assert result["status"] == "drift" and result["committed_matches"] is False
    assert all(d["matches"] for d in result["destinations"])
