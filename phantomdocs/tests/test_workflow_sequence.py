"""Reservations are durable, idempotent and serialized within one ledger."""

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_sequence import SequenceReservations
from phantomdocs.workflows import WorkflowError

EVIDENCE = "a" * 64
REQUEST = "b" * 64


def test_requires_explicit_baseline_and_never_reuses_an_assigned_number(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with WorkflowLedger(path) as ledger:
        service = SequenceReservations(ledger)
        with pytest.raises(WorkflowError, match="initialization"):
            service.reserve("AU", "20261107", "request-1", REQUEST)
        service.initialize("AU", "20261107", 17, EVIDENCE)
        assert (
            service.reserve("AU", "20261107", "request-1", REQUEST) == "AU-20261107-018"
        )
        assert (
            service.reserve("AU", "20261107", "request-1", REQUEST) == "AU-20261107-018"
        )
        with pytest.raises(WorkflowError, match="conflicts"):
            service.reserve("AU", "20261107", "request-1", "c" * 64)
        with pytest.raises(WorkflowError, match="conflicts"):
            service.reserve("AU", "20261108", "request-1", REQUEST)
        with pytest.raises(WorkflowError, match="different evidence"):
            service.initialize("AU", "20261107", 18, EVIDENCE)
    with WorkflowLedger(path) as ledger:
        service = SequenceReservations(ledger)
        assert (
            service.reserve("AU", "20261107", "request-2", REQUEST) == "AU-20261107-019"
        )


def test_concurrent_reservations_are_unique(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with WorkflowLedger(path) as ledger:
        SequenceReservations(ledger).initialize("AU", "20261107", 0, EVIDENCE)

    def reserve(number):
        with WorkflowLedger(path) as ledger:
            return SequenceReservations(ledger).reserve(
                "AU", "20261107", f"request-{number}", REQUEST
            )

    with ThreadPoolExecutor(max_workers=8) as workers:
        ids = list(workers.map(reserve, range(30)))
    assert set(ids) == {f"AU-20261107-{number:03d}" for number in range(1, 31)}


def test_independent_processes_share_one_sequence(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with WorkflowLedger(path) as ledger:
        SequenceReservations(ledger).initialize("AU", "20261107", 0, EVIDENCE)
    code = (
        "import sys; from phantomdocs.workflow_ledger import WorkflowLedger; "
        "from phantomdocs.workflow_sequence import SequenceReservations; "
        "l=WorkflowLedger(sys.argv[1]); "
        "print(SequenceReservations(l).reserve('AU','20261107',sys.argv[2],'b'*64))"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), f"process-{number}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for number in range(6)
    ]
    results = [process.communicate(timeout=20) for process in processes]
    assert all(process.returncode == 0 for process in processes), results
    assert {stdout.strip() for stdout, _ in results} == {
        f"AU-20261107-{number:03d}" for number in range(1, 7)
    }


def test_concurrent_retries_do_not_consume_extra_numbers(tmp_path):
    path = tmp_path / "ledger.sqlite"
    with WorkflowLedger(path) as ledger:
        SequenceReservations(ledger).initialize("AU", "20261107", 0, EVIDENCE)

    def retry(_):
        with WorkflowLedger(path) as ledger:
            return SequenceReservations(ledger).reserve(
                "AU", "20261107", "one-request", REQUEST
            )

    with ThreadPoolExecutor(max_workers=8) as workers:
        ids = list(workers.map(retry, range(16)))
    assert set(ids) == {"AU-20261107-001"}
    with WorkflowLedger(path) as ledger:
        assert (
            SequenceReservations(ledger).reserve("AU", "20261107", "next", REQUEST)
            == "AU-20261107-002"
        )


def test_failed_transaction_does_not_consume_a_number(tmp_path):
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        service = SequenceReservations(ledger)
        service.initialize("AU", "20261107", 0, EVIDENCE)
        ledger.connection.execute(
            "CREATE TRIGGER deny_update BEFORE UPDATE ON workflow_sequence_scopes "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="synthetic failure"):
            service.reserve("AU", "20261107", "request-1", REQUEST)
        ledger.connection.execute("DROP TRIGGER deny_update")
        assert (
            service.reserve("AU", "20261107", "request-1", REQUEST) == "AU-20261107-001"
        )


def test_validates_scope_and_does_not_wrap_exhausted_sequences(tmp_path):
    with WorkflowLedger(tmp_path / "ledger.sqlite") as ledger:
        service = SequenceReservations(ledger)
        for entity, day in (("au", "20261107"), ("AU", "20261301"), ("AU", "20260230")):
            with pytest.raises(WorkflowError):
                service.initialize(entity, day, 0, EVIDENCE)
        service.initialize("AU", "20261107", 999, EVIDENCE)
        with pytest.raises(WorkflowError, match="exhausted"):
            service.reserve("AU", "20261107", "request-1", REQUEST)
