"""Bounded metadata and history lookup for a kernel-authenticated local peer."""

import json
import re

from .access import can_read
from .manifest import (
    node_by_mac,
    node_by_urn,
    ref_target_mac,
    resolve_node,
    validate,
    versions_of,
)
from .storage import location_uri
from .workflow_local_identity import resolve_peer_actor
from .workflow_peer_search import MAX_QUERY_BYTES, MAX_SEARCH_RESPONSE_BYTES


def lookup_peer(connection, request, *, identity_map, org, load_manifest):
    """Resolve authorized metadata while the host holds policy and store locks."""
    if not isinstance(request, dict) or set(request) not in (
        {"operation"},
        {"operation", "ref"},
        {"operation", "ref", "mac"},
    ):
        raise ValueError("invalid lookup request")
    operation, ref = request["operation"], request.get("ref")
    mac = request.get("mac")
    if (
        operation
        not in {"reference", "versions", "content-reference", "status", "refs"}
        or (operation in {"status", "refs"} and set(request) != {"operation"})
        or (
            operation not in {"status", "refs"}
            and (
                not isinstance(ref, str)
                or not ref
                or len(ref.encode("utf-8")) > MAX_QUERY_BYTES
            )
        )
        or (
            mac is not None
            and (
                operation not in {"reference", "content-reference"}
                or not isinstance(mac, str)
            )
        )
    ):
        raise ValueError("invalid lookup request")
    actor = resolve_peer_actor(identity_map, connection)
    if not any(a.get("id") == actor for a in org.get("actors", [])):
        raise ValueError("unknown actor")
    manifest = load_manifest()
    if not isinstance(manifest, dict) or validate(manifest):
        raise ValueError("invalid manifest")
    if operation in {"status", "refs"}:
        visible = [
            node for node in manifest["nodes"] if can_read(org, actor, node["category"])
        ]
        if operation == "status":
            header = manifest["manifest"]
            docs = [node for node in visible if node["kind"] == "doc"]
            result = {
                "org": header["org"],
                "namespace": header["namespace"],
                "tenant": header["tenant"],
                "nodes": len(visible),
                "docs": len(docs),
                "folders": len(visible) - len(docs),
                "bytes": sum(int(node.get("size") or 0) for node in docs),
            }
        else:
            result = []
            for name, value in manifest.get("refs", {}).items():
                target = ref_target_mac(value)
                node = node_by_mac(manifest, target) if target else None
                if node and can_read(org, actor, node["category"]):
                    result.append({"name": name, "mac": target, "urn": node["urn"]})
        response = {"status": "ok", "actor": actor, "result": result}
        if (
            len(json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode())
            > MAX_SEARCH_RESPONSE_BYTES
        ):
            raise ValueError("lookup response exceeds limit")
        return response
    node = resolve_node(manifest, ref)
    if mac:
        selected = node_by_mac(manifest, mac)
        if node is None or selected is None or node["urn"] != selected["urn"]:
            raise ValueError("document unavailable")
        node = selected
    if node is None or not can_read(org, actor, node["category"]):
        raise ValueError("document unavailable")
    if operation == "reference":
        locations = node.get("locations") or []
        location = locations[0] if locations else {}
        reference = (
            location_uri(location) if "ref" in location else location.get("path", "")
        )
        result = {"urn": node["urn"], "location": reference}
    elif operation == "content-reference":
        locations = node.get("locations") or []
        if node.get("kind") != "doc" or not locations:
            raise ValueError("document unavailable")
        location = locations[0]
        reference = location_uri(location) if "ref" in location else ""
        file_id = reference.removeprefix("gdrive://")
        if (
            not reference.startswith("gdrive://")
            or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,255}", file_id) is None
        ):
            raise ValueError("content reference unavailable")
        result = {
            "urn": node["urn"],
            "location": reference,
            "contentHash": node["contentHash"],
            "mac": node["mac"],
        }
    else:
        history = versions_of(manifest, node["urn"])
        if any(not can_read(org, actor, version["category"]) for version in history):
            raise ValueError("history unavailable")
        current = node_by_urn(manifest, node["urn"])
        current_mac = current["mac"] if current else None
        result = [
            {
                "mac": version["mac"],
                "size": version.get("size", 0),
                "current": version["mac"] == current_mac,
            }
            for version in history
        ]
    response = {"status": "ok", "actor": actor, "result": result}
    if (
        len(json.dumps(response, ensure_ascii=True, separators=(",", ":")).encode())
        > MAX_SEARCH_RESPONSE_BYTES
    ):
        raise ValueError("lookup response exceeds limit")
    return response
