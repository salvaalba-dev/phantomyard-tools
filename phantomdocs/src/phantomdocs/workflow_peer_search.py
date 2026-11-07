"""ACL-filtered search for a kernel-authenticated local peer.

The host owns the policy, identity map and manifest loader. This module does
not itself protect the store from direct filesystem access or install a service.
"""

import json

from .manifest import structural_issues, validate
from .workflow_local_identity import resolve_peer_actor
from .workflow_visibility import can_observe_node

MAX_QUERY_BYTES = 512
MAX_SEARCH_RESPONSE_BYTES = 128 * 1024


def search_peer(connection, request, *, identity_map, org, load_manifest):
    """Return only the authenticated actor's permitted search results.

    The policy must remain stable under the host's shared lock until the reply
    has been sent. The caller supplies no actor, file path or category.
    """
    if not isinstance(request, dict) or set(request) != {"query"}:
        raise ValueError("invalid search request")
    query = request["query"]
    if not isinstance(query, str) or len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise ValueError("invalid search query")
    actor = resolve_peer_actor(identity_map, connection)
    if not any(a.get("id") == actor for a in org.get("actors", [])):
        raise ValueError("unknown actor")
    manifest = load_manifest()
    if (
        not isinstance(manifest, dict)
        or validate(manifest)
        or structural_issues(manifest)
    ):
        raise ValueError("invalid manifest")
    needle = query.lower()
    items = []
    for node in manifest["nodes"]:
        if not can_observe_node(org, actor, manifest, node):
            continue
        meta = node.get("meta") or {}
        haystack = " ".join(
            str(value)
            for value in (
                node.get("urn", ""),
                node.get("slug", ""),
                meta.get("title", ""),
            )
        ).lower()
        if needle in haystack:
            items.append({"kind": node["kind"], "urn": node["urn"]})
    response = {"status": "ok", "actor": actor, "items": items}
    encoded = json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_SEARCH_RESPONSE_BYTES:
        raise ValueError("search response exceeds limit")
    return response
