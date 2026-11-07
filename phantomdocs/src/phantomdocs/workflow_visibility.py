"""Apply current and historical document access to workflow observations."""

from .access import can_read
from .manifest import node_by_urn


def can_observe_node(org, actor, manifest, node):
    """Require access to the selected version and the current document head."""
    if not can_read(org, actor, node["category"]):
        return False
    if node.get("kind") != "doc":
        return True
    current = node_by_urn(manifest, node["urn"])
    return bool(current and can_read(org, actor, current["category"]))
