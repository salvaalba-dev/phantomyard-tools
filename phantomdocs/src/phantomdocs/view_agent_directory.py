"""Inactive adapter for agent-scoped viewer recipients.

The hosting reader must bind each actor to its trusted daemon account before
calling resolve. This class does not verify IPC peers or issue links, and it
must not be exposed directly to HTTP or model-controlled actor selection.
Agent-scoped sessions are read-only; viewer routes requiring a human identity,
including persona conversation and review, must remain disabled for them.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from phantomdocs.access import validate_org_schema
from phantomdocs.signing import npub_to_pubkey_hex
from phantomdocs.view_agent_scope import permits_view

ACTOR_SCOPE = "agent-all"


def has_declared_channel(actor):
    """Check channel declarations, without treating them as authentication."""
    if not isinstance(actor, dict):
        return False
    telegram = actor.get("telegram_bot")
    nostr = actor.get("npub")
    if isinstance(telegram, str) and re.fullmatch(r"@[A-Za-z0-9_]{5,32}", telegram):
        return True
    if not isinstance(nostr, str):
        return False
    try:
        npub_to_pubkey_hex(nostr)
        return True
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class AgentRecipient:
    organization: str
    persona: str
    scope_id: str
    policy_revision: str
    directory_revision: str
    human: None = None

    def metadata(self):
        return asdict(self)


class AgentScope:
    """Delegate human policy and resolve agent navigation from the same org."""

    def __init__(self, directory, human_scope):
        self.directory = directory
        self.human_scope = human_scope

    def __getattr__(self, name):
        return getattr(self.human_scope, name)

    @property
    def policy(self):
        """Describe the synthetic aggregate to the viewer's navigation only."""
        policy = json.loads(json.dumps(self.human_scope.policy, allow_nan=False))
        view = policy["view_access"]
        definitions = view["scope_definitions"]
        if ACTOR_SCOPE in definitions:
            return policy
        definitions[ACTOR_SCOPE] = {"kind": "organization", "label": "Agent access"}
        grants = view["persona_scope_grants"]
        for actor in self.directory.enabled_actors:
            if self.directory._scope_allowed(actor, ACTOR_SCOPE):
                grants[actor] = [*grants.get(actor, []), ACTOR_SCOPE]
        return policy

    def can_enter(self, human, persona, scope_id=None):
        if human is None:
            return self.directory._scope_allowed(persona, scope_id)
        return self.human_scope.can_enter(human, persona, scope_id)


class AgentDirectory:
    """Separate actor-scoped policy alongside an unchanged human directory."""

    def __init__(self, org, human_directory, enabled_actors):
        validate_org_schema(org)
        self.org = json.loads(json.dumps(org, sort_keys=True, allow_nan=False))
        if not isinstance(enabled_actors, frozenset) or any(
            not isinstance(a, str) or not a for a in enabled_actors
        ):
            raise ValueError("Explicit trusted actor bindings are required")
        self.enabled_actors = enabled_actors
        self.human_directory = human_directory
        self.scope = AgentScope(self, human_directory.scope)
        self.authority_revision = human_directory.authority_revision
        self.revision = hashlib.sha256(
            json.dumps(self.org, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _scope_allowed(self, actor, scope_id):
        try:
            actors = self.org["actors"]
            policy = self.org["policies"]["phantomview"]
            definition = policy["scope_definitions"].get(scope_id)
            grants = policy["persona_scope_grants"].get(actor)
            if (
                actor not in self.enabled_actors
                or not isinstance(scope_id, str)
                or not scope_id
                or not isinstance(actors, list)
                or sum(
                    isinstance(row, dict) and row.get("id") == actor for row in actors
                )
                != 1
            ):
                return False
            if not has_declared_channel(
                next(
                    row
                    for row in actors
                    if isinstance(row, dict) and row.get("id") == actor
                )
            ):
                return False
            if scope_id == ACTOR_SCOPE:
                # A real organization scope of the same name is ambiguous.
                return scope_id not in policy["scope_definitions"]
            if (
                not isinstance(definition, dict)
                or not isinstance(grants, list)
                or scope_id not in grants
            ):
                return False
            kind = definition.get("kind")
            if kind == "project":
                projects = policy["project_grants"].get(actor)
                return isinstance(projects, list) and scope_id in projects
            if kind == "organization":
                return scope_id == self.org["organization"]["id"]
            if kind == "department":
                departments = self.org.get("departments")
                return isinstance(departments, list) and any(
                    isinstance(row, dict) and row.get("id") == scope_id
                    for row in departments
                )
            return False
        except (KeyError, TypeError, AttributeError):
            return False

    def resolve_agent(self, actor, scope_id):
        """Resolve only an actor already bound by the reader's trusted route."""
        if not self._scope_allowed(actor, scope_id):
            raise ValueError("Agent is not eligible for this viewer scope")
        organization = self.org.get("organization", {}).get("id")
        if not isinstance(organization, str) or not organization:
            raise ValueError("Organization is unavailable")
        return AgentRecipient(
            organization, actor, scope_id, self.revision, self.revision
        )

    def resolve(self, **context):
        """Preserve the existing human-authenticated route unchanged."""
        return self.human_directory.resolve(**context)

    def validate(self, recipient):
        if not isinstance(recipient, AgentRecipient):
            return self.human_directory.validate(recipient)
        if (
            recipient.organization != self.org.get("organization", {}).get("id")
            or recipient.policy_revision != self.revision
            or recipient.directory_revision != self.revision
            or not self._scope_allowed(recipient.persona, recipient.scope_id)
        ):
            raise ValueError("Agent policy changed; request a new link")
        return recipient

    def permits(self, recipient, resource):
        if not isinstance(recipient, AgentRecipient):
            return self.human_directory.permits(recipient, resource)
        self.validate(recipient)
        if recipient.scope_id == ACTOR_SCOPE:
            return permits_view(self.org, recipient.persona, resource, actor_scope=True)
        return (
            isinstance(resource, dict)
            and isinstance(resource.get("scope"), dict)
            and resource["scope"].get("id") == recipient.scope_id
            and permits_view(self.org, recipient.persona, resource)
        )

    def allows_action(self, recipient, action, scope_id, **kwargs):
        if not isinstance(recipient, AgentRecipient):
            return self.human_directory.allows_action(
                recipient, action, scope_id, **kwargs
            )
        self.validate(recipient)
        return False
