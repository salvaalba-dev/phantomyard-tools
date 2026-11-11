"""Compose agent routes onto an independently protected human-route baseline.

This is a deterministic configuration transformation, not a provisioner or
authorization check. Inputs must come from the trusted installation and current
PhantomOrg reconciliation; callers must verify the rendered reader config.
"""

import copy
import re
from pathlib import PurePosixPath


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", value
    ):
        raise ValueError("Invalid actor")
    return value


def _socket(value):
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or str(PurePosixPath(value)) != value
        or ".." in PurePosixPath(value).parts
        or "\x00" in value
        or len(value.encode()) > 100
    ):
        raise ValueError("Invalid local socket path")
    return value


def _identities(value):
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v)
            for v in value
        )
        or len(value) != len(set(value))
    ):
        raise ValueError("Invalid issuer identities")
    return value


def compose_routes(human_baseline, agent_routes):
    """Preserve human routes and add only explicitly supplied agent signers."""
    if not isinstance(human_baseline, dict) or not isinstance(agent_routes, list):
        raise TypeError("Trusted baseline and routes required")
    if human_baseline.get("agent_actors") or human_baseline.get("mixed_agent_signers"):
        raise ValueError("Baseline must exclude managed agent issuers")
    result = copy.deepcopy(human_baseline)
    additional = result.setdefault("additional_issuers", [])
    if not isinstance(additional, list):
        raise TypeError("Invalid issuer baseline")
    by_actor = {}
    sockets = set()
    keys = set()
    for route in [result, *additional]:
        if not isinstance(route, dict):
            raise TypeError("Invalid issuer route")
        actor = _name(route.get("actor"))
        path = _socket(route.get("socket_path"))
        identities = _identities(route.get("identities"))
        if actor in by_actor or path in sockets or keys.intersection(identities):
            raise ValueError("Ambiguous baseline issuer")
        by_actor[actor] = route
        sockets.add(path)
        keys.update(identities)
    managed, mixed, managed_uids = [], {}, set()
    for route in sorted(
        agent_routes, key=lambda r: r.get("actor", "") if isinstance(r, dict) else ""
    ):
        if not isinstance(route, dict) or set(route) != {
            "actor",
            "issuer_uid",
            "socket_path",
            "socket_group",
            "signer",
        }:
            raise ValueError("Invalid agent route")
        actor = _name(route["actor"])
        path = _socket(route["socket_path"])
        signer = _identities([route["signer"]])[0]
        if (
            actor in managed
            or signer in keys
            or type(route["issuer_uid"]) is not int
            or route["issuer_uid"] <= 0
            or route["issuer_uid"] in managed_uids
            or type(route["socket_group"]) is not int
            or route["socket_group"] <= 0
        ):
            raise ValueError("Ambiguous agent route")
        if any(
            other != actor and item.get("issuer_uid") == route["issuer_uid"]
            for other, item in by_actor.items()
        ):
            raise ValueError("Agent UID belongs to another issuer")
        existing = by_actor.get(actor)
        if existing is not None:
            if any(
                existing.get(k) != route[k]
                for k in ("issuer_uid", "socket_path", "socket_group")
            ):
                raise ValueError("Shared actor route does not match human issuer")
            existing["identities"].append(signer)
            mixed[actor] = [signer]
        else:
            if path in sockets:
                raise ValueError("Agent socket belongs to another issuer")
            added = {
                k: route[k]
                for k in ("actor", "issuer_uid", "socket_path", "socket_group")
            }
            added.update({"identities": [signer], "conversation_socket": None})
            additional.append(added)
            by_actor[actor] = added
            sockets.add(path)
        keys.add(signer)
        managed.append(actor)
        managed_uids.add(route["issuer_uid"])
    result["agent_actors"] = managed
    if mixed:
        result["mixed_agent_signers"] = mixed
    else:
        result.pop("mixed_agent_signers", None)
    return result
