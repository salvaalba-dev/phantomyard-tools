"""Review-only matching must respect current and historical access."""

import yaml
from test_documents import ORG_YAML

from phantomdocs.documents import _readable_content_match


class Repo:
    def __init__(self, nodes, current):
        self.data = {"nodes": nodes}
        self.current = current

    def node_by_urn(self, urn):
        return self.current.get(urn)


def test_matching_readable_history_requires_review_without_identifying_node():
    org = yaml.safe_load(ORG_YAML)
    historic = {
        "kind": "doc",
        "urn": "urn:old",
        "category": "category-1",
        "contentHash": "a" * 64,
    }
    current = {**historic, "contentHash": "b" * 64}
    repo = Repo([historic, current], {"urn:old": current})
    assert _readable_content_match(repo, org, "roberto", "category-1", "a" * 64) is True
    assert (
        _readable_content_match(repo, org, "roberto", "category-1", "c" * 64) is False
    )
    assert (
        _readable_content_match(repo, org, "roberto", "category-2", "a" * 64) is False
    )


def test_unreadable_current_head_cannot_be_used_as_a_content_oracle():
    org = yaml.safe_load(ORG_YAML)
    org["policies"]["access_levels"]["level-2"]["categories"] = [1]
    historic = {
        "kind": "doc",
        "urn": "urn:old",
        "category": "category-1",
        "contentHash": "a" * 64,
    }
    current = {**historic, "category": "category-2", "contentHash": "b" * 64}
    repo = Repo([historic, current], {"urn:old": current})
    assert (
        _readable_content_match(repo, org, "roberto", "category-1", "a" * 64) is False
    )
