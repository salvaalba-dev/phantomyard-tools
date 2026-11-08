"""Inactive agent-scoped issuance mixin for the identified viewer gate.

Only a reader route that has independently bound the connected agent account
to ``actor`` may call this method. Never expose it to HTTP or select that actor
from a request body. The host must deny human-only and write routes for agent
recipients before enabling it. No listener is installed by this module.
"""

import re

from phantomdocs.view_agent_directory import AgentDirectory


class AgentGateMixin:
    def issue_identified(self, authorization, origin, **channel_context):
        """Use actor scope only for routes explicitly enabled by the host."""
        directory = self.directory_loader()
        actor = channel_context.get("persona")
        if isinstance(directory, AgentDirectory) and actor in directory.enabled_actors:
            return self.issue_scoped_agent(
                authorization,
                origin,
                actor=actor,
                scope_id=channel_context.get("scope_id"),
            )
        return super().issue_identified(authorization, origin, **channel_context)

    def issue_scoped_agent(self, authorization, origin, *, actor, scope_id):
        """Use the existing signed-link verifier and bind an actor-only recipient."""
        directory = self.directory_loader()
        if not isinstance(directory, AgentDirectory):
            raise TypeError("Agent-scoped directory is not configured")
        recipient = directory.resolve_agent(actor, scope_id)
        links = self.issuer_links(actor)
        with self.recipient_lock:
            self._prune_recipients()
            if len(self.recipient_links) >= 1000:
                raise ValueError("Too many pending recipient links")
            link = links.issue(authorization, origin, self.origin)
            match = re.fullmatch(
                re.escape(self.origin) + r"/#c=([A-Za-z0-9_-]{43})", link
            )
            if not match:
                raise ValueError("Invalid signed access link response")
            digest = self.digest(match[1])
            if digest in self.recipient_links:
                raise ValueError("Recipient link collision")
            self.recipient_links[digest] = (recipient, self.clock() + 300)
            return link
