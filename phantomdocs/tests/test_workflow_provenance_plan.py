"""Preparing provenance never changes the store or authorizes an audit write."""

from copy import deepcopy

import pytest
import test_workflow_reconcile as fixtures

from phantomdocs.workflow_provenance_plan import prepare_link
from phantomdocs.workflows import WorkflowError


@pytest.fixture
def system():
    return fixtures.system.__wrapped__()


def prepare(system, **changes):
    node = fixtures.index(system)
    args = {
        "org": system[2],
        "manifest": system[6],
        "actor": "coordinator",
        "urn": node["urn"],
        "inbox_ref": "gdrive://intake-copy",
        "archive_ref": "gdrive://example-file",
        "sha256": "3" * 64,
    }
    args.update(changes)
    before = deepcopy(system[6])
    result = prepare_link(**args)
    assert system[6] == before
    return result


def test_plan_pins_document_and_requires_review(system):
    result = prepare(system)
    assert result["execution_available"] is False
    assert result["document_mac"] == "2" * 64
    assert result["status"] == "review-required"


@pytest.mark.parametrize(
    "changes",
    [{"actor": "unmapped"}, {"archive_ref": "gdrive://other"}, {"sha256": "4" * 64}],
)
def test_untrusted_intent_does_not_make_a_plan(system, changes):
    with pytest.raises(WorkflowError):
        prepare(system, **changes)
