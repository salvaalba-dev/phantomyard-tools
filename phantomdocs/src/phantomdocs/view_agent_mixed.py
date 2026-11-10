"""Separate agent and human issuance on a trusted shared actor route.

Signer selection is not authentication: the existing issuer verifies the
complete signature and local peer before issuing either kind of session.
"""

import base64
import binascii
import json
import re

from .view_agent_gate import AgentGateMixin


def validate_mixed_signers(mapping, routes, enabled_actors):
    """Require an explicit proper subset of each route's verified signers."""
    if not isinstance(mapping, dict) or not isinstance(routes, (tuple, list)):
        raise TypeError("Invalid mixed issuer configuration")
    by_actor = {route["actor"]: set(route["identities"]) for route in routes}
    if len(by_actor) != len(routes):
        raise ValueError("Duplicate issuer actor")
    result = {}
    for actor, keys in mapping.items():
        if (
            actor not in enabled_actors
            or actor not in by_actor
            or not isinstance(keys, list)
            or not keys
            or any(
                not isinstance(k, str) or not re.fullmatch(r"[a-f0-9]{64}", k)
                for k in keys
            )
            or len(set(keys)) != len(keys)
            or not set(keys) < by_actor[actor]
        ):
            raise ValueError("Invalid mixed agent signers")
        result[actor] = frozenset(keys)
    return result


def _claimed_signer(authorization):
    if not isinstance(authorization, str) or not authorization.startswith("Nostr "):
        return None
    if len(authorization) > 32768:
        return None

    def unique(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise ValueError("Duplicate event field")
            data[key] = value
        return data

    try:
        raw = base64.b64decode(authorization[6:], validate=True)
        event = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        key = event.get("pubkey") if isinstance(event, dict) else None
        return (
            key if isinstance(key, str) and re.fullmatch(r"[a-f0-9]{64}", key) else None
        )
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        return None


class MixedAgentGateMixin(AgentGateMixin):
    """Keep human issuance unless a configured agent signer is presented."""

    def issue_identified(self, authorization, origin, **channel_context):
        actor = channel_context.get("persona")
        signers = getattr(self, "mixed_agent_signers", {})
        if actor in signers:
            if _claimed_signer(authorization) in signers[actor]:
                return self.issue_scoped_agent(
                    authorization,
                    origin,
                    actor=actor,
                    scope_id=channel_context.get("scope_id"),
                )
            return super(AgentGateMixin, self).issue_identified(
                authorization, origin, **channel_context
            )
        return super().issue_identified(authorization, origin, **channel_context)
