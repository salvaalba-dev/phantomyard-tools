from copy import deepcopy

import pytest

from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_org_sequence import OrganizationSequences
from phantomdocs.workflows import WorkflowError


@pytest.fixture
def org():
    return {
        "version": 1,
        "organization": {"id": "example"},
        "departments": [{"id": "finance", "parent": None}],
        "policies": {
            "security_categories": {
                "category-4-alpha": {"scope": "project"},
                "category-2": {},
            }
        },
    }


def test_department_and_project_reserve_independently(tmp_path, org):
    with WorkflowLedger(tmp_path / "ledger") as ledger:
        service = OrganizationSequences(ledger)
        for kind, ref, code in [
            ("department", "finance", "FINANCE"),
            ("project-category", "category-4-alpha", "ALPHA"),
        ]:
            service.initialize(org, "EX", kind, ref, code, "20261107", 0, "a" * 64)
            assert (
                service.reserve(org, "EX", kind, ref, code, "20261107", ref, "b" * 64)
                == f"EX-{code}-20261107-001"
            )


def test_bindings_are_durable_and_cannot_alias(tmp_path, org):
    path = tmp_path / "ledger"
    with WorkflowLedger(path) as ledger:
        OrganizationSequences(ledger).initialize(
            org, "EX", "department", "finance", "FINANCE", "20261107", 0, "a" * 64
        )
    with WorkflowLedger(path) as ledger:
        service = OrganizationSequences(ledger)
        for args in [
            (org, "EX", "department", "finance", "OTHER"),
            (org, "EX", "project-category", "category-4-alpha", "FINANCE"),
            (org, "AB", "department", "finance", "FINANCE"),
        ]:
            with pytest.raises(WorkflowError, match="bound"):
                service.initialize(*args, "20261108", 0, "a" * 64)
        other = deepcopy(org)
        other["organization"]["id"] = "another"
        with pytest.raises(WorkflowError, match="bound"):
            service.initialize(
                other, "EX", "department", "finance", "FINANCE", "20261108", 0, "a" * 64
            )


def test_unknown_scope_and_nonproject_category_fail_closed(tmp_path, org):
    with WorkflowLedger(tmp_path / "ledger") as ledger:
        service = OrganizationSequences(ledger)
        for kind, ref in [
            ("department", "missing"),
            ("project-category", "category-2"),
            ("project-category", "missing"),
            ("other", "finance"),
        ]:
            with pytest.raises(WorkflowError):
                service.initialize(org, "EX", kind, ref, "X", "20261107", 0, "a" * 64)
        with pytest.raises(WorkflowError, match="initialization"):
            service.reserve(
                org, "EX", "department", "finance", "FINANCE", "20261107", "r", "b" * 64
            )
        assert (
            ledger.connection.execute(
                "SELECT count(*) FROM workflow_sequence_entities"
            ).fetchone()[0]
            == 0
        )


def test_removed_scope_cannot_allocate_and_rename_does_not_change_code(tmp_path, org):
    with WorkflowLedger(tmp_path / "ledger") as ledger:
        service = OrganizationSequences(ledger)
        service.initialize(
            org, "EX", "department", "finance", "FINANCE", "20261107", 0, "a" * 64
        )
        org["departments"][0]["name"] = "New display name"
        assert service.reserve(
            org, "EX", "department", "finance", "FINANCE", "20261107", "r1", "b" * 64
        ).endswith("001")
        org["departments"] = []
        with pytest.raises(WorkflowError, match="department"):
            service.reserve(
                org,
                "EX",
                "department",
                "finance",
                "FINANCE",
                "20261107",
                "r2",
                "b" * 64,
            )
