"""Bind numbering scopes to explicitly selected PhantomOrg structures.

This is a trusted local adapter. It does not authorize a caller or classify a
file; callers must hold the policy lock and apply PhantomOrg access checks.
"""

from .access import validate_org_schema
from .workflow_sequence import SequenceReservations, _hash, _scope
from .workflows import WorkflowError


class OrganizationSequences:
    """Pin entity and scope codes to declared organizational identities."""

    def __init__(self, ledger):
        self.sequences = SequenceReservations(ledger)
        self.db = ledger.connection
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("""CREATE TABLE IF NOT EXISTS workflow_sequence_entities (
                organization TEXT PRIMARY KEY, entity TEXT NOT NULL UNIQUE)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS workflow_sequence_bindings (
                organization TEXT NOT NULL, kind TEXT NOT NULL, reference TEXT NOT NULL,
                code TEXT NOT NULL, PRIMARY KEY (organization, kind, reference),
                UNIQUE (organization, code))""")
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def _bind(self, org, entity, kind, reference, code, day, *, create):
        if not isinstance(org, dict):
            raise WorkflowError("invalid organization")
        try:
            validate_org_schema(org)
            organization = org["organization"]["id"]
        except (TypeError, KeyError, ValueError) as error:
            raise WorkflowError("invalid organization") from error
        if not isinstance(organization, str) or not organization:
            raise WorkflowError("invalid organization")
        _scope(entity, code, day)
        if not isinstance(reference, str) or not reference:
            raise WorkflowError("invalid organizational scope")
        if kind == "department":
            departments = org.get("departments")
            if not isinstance(departments, list):
                raise WorkflowError("invalid departments")
            matches = [
                d
                for d in departments
                if isinstance(d, dict) and d.get("id") == reference
            ]
            if len(matches) != 1:
                raise WorkflowError("unknown or ambiguous department")
        elif kind == "project-category":
            policies = org.get("policies")
            if not isinstance(policies, dict):
                raise WorkflowError("invalid security categories")
            categories = policies.get("security_categories", {})
            if not isinstance(categories, dict):
                raise WorkflowError("invalid security categories")
            category = categories.get(reference)
            if not isinstance(category, dict) or category.get("scope") != "project":
                raise WorkflowError("unknown project-scoped category")
        else:
            raise WorkflowError("unknown organizational scope kind")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute(
                "SELECT organization, entity FROM workflow_sequence_entities "
                "WHERE organization=? OR entity=?",
                (organization, entity),
            ).fetchall()
            if existing and (
                len(existing) != 1 or tuple(existing[0]) != (organization, entity)
            ):
                raise WorkflowError("entity code is already bound")
            if not existing:
                if not create:
                    raise WorkflowError("entity requires initialization")
                self.db.execute(
                    "INSERT INTO workflow_sequence_entities VALUES (?, ?)",
                    (organization, entity),
                )
            existing = self.db.execute(
                "SELECT kind, reference, code FROM workflow_sequence_bindings "
                "WHERE organization=? AND ((kind=? AND reference=?) OR code=?)",
                (organization, kind, reference, code),
            ).fetchall()
            if existing and (
                len(existing) != 1 or tuple(existing[0]) != (kind, reference, code)
            ):
                raise WorkflowError("scope code is already bound")
            if not existing:
                if not create:
                    raise WorkflowError("scope requires initialization")
                self.db.execute(
                    "INSERT INTO workflow_sequence_bindings VALUES (?, ?, ?, ?)",
                    (organization, kind, reference, code),
                )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def initialize(
        self, org, entity, kind, reference, code, day, baseline, evidence_sha256
    ):
        _hash(evidence_sha256)
        if type(baseline) is not int or not 0 <= baseline <= 999:
            raise WorkflowError("invalid sequence baseline")
        self._bind(org, entity, kind, reference, code, day, create=True)
        self.sequences.initialize(entity, code, day, baseline, evidence_sha256)

    def reserve(
        self, org, entity, kind, reference, code, day, request_id, request_sha256
    ):
        self._bind(org, entity, kind, reference, code, day, create=False)
        return self.sequences.reserve(entity, code, day, request_id, request_sha256)
