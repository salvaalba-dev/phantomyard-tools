"""Trusted local identifier reservations; not an inbox or a matrix writer.

The caller owns authentication and must establish a complete initial watermark.
All allocators for a numbering scope must use this same durable ledger. This
module cannot prevent manual or external writers from assigning identifiers.
"""

import datetime
import re

from .workflow_ledger import WorkflowLedger
from .workflows import WorkflowError


def _scope(entity, day):
    if not isinstance(entity, str) or not re.fullmatch(r"[A-Z]{2,8}", entity):
        raise WorkflowError("invalid sequence entity")
    if not isinstance(day, str) or not re.fullmatch(r"[0-9]{8}", day):
        raise WorkflowError("invalid sequence date")
    try:
        datetime.datetime.strptime(day, "%Y%m%d")
    except ValueError as error:
        raise WorkflowError("invalid sequence date") from error


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise WorkflowError("invalid sequence evidence digest")


class SequenceReservations:
    """Reserve immutable IDs in an existing trusted private workflow ledger."""

    def __init__(self, ledger):
        if not isinstance(ledger, WorkflowLedger):
            raise WorkflowError("a trusted workflow ledger is required")
        self.db = ledger.connection
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("""CREATE TABLE IF NOT EXISTS workflow_sequence_scopes (
                entity TEXT NOT NULL, day TEXT NOT NULL, baseline INTEGER NOT NULL,
                evidence_sha256 TEXT NOT NULL, last_number INTEGER NOT NULL,
                PRIMARY KEY (entity, day))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS workflow_sequence_reservations (
                request_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL,
                entity TEXT NOT NULL, day TEXT NOT NULL, number INTEGER NOT NULL,
                UNIQUE (entity, day, number))""")
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def initialize(self, entity, day, baseline, evidence_sha256):
        """Record an operator-verified watermark, never infer completeness."""
        _scope(entity, day)
        _hash(evidence_sha256)
        if type(baseline) is not int or not 0 <= baseline <= 999:
            raise WorkflowError("invalid sequence baseline")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT baseline, evidence_sha256 FROM workflow_sequence_scopes "
                "WHERE entity=? AND day=?",
                (entity, day),
            ).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO workflow_sequence_scopes VALUES (?, ?, ?, ?, ?)",
                    (entity, day, baseline, evidence_sha256, baseline),
                )
            elif (row[0], row[1]) != (baseline, evidence_sha256):
                raise WorkflowError("sequence scope already has different evidence")
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def reserve(self, entity, day, request_id, request_sha256):
        """Reuse an identical request's number or atomically reserve the next."""
        _scope(entity, day)
        _hash(request_sha256)
        if not isinstance(request_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", request_id
        ):
            raise WorkflowError("invalid sequence request identity")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT entity, day, request_sha256, number "
                "FROM workflow_sequence_reservations WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if (row[0], row[1], row[2]) != (entity, day, request_sha256):
                    raise WorkflowError(
                        "sequence request conflicts with its reservation"
                    )
                number = row[3]
            else:
                state = self.db.execute(
                    "SELECT last_number FROM workflow_sequence_scopes "
                    "WHERE entity=? AND day=?",
                    (entity, day),
                ).fetchone()
                if state is None:
                    raise WorkflowError(
                        "sequence scope requires verified initialization"
                    )
                number = state[0] + 1
                if number > 999:
                    raise WorkflowError("daily sequence exhausted")
                self.db.execute(
                    "INSERT INTO workflow_sequence_reservations VALUES (?, ?, ?, ?, ?)",
                    (request_id, request_sha256, entity, day, number),
                )
                self.db.execute(
                    "UPDATE workflow_sequence_scopes SET last_number=? "
                    "WHERE entity=? AND day=?",
                    (number, entity, day),
                )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return f"{entity}-{day}-{number:03d}"
