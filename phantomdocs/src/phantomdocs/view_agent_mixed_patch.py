"""Compose mixed human/agent issuers into pinned viewer components."""

import ast
import hashlib

READER_SHA256 = "2d2c47fac359fe5ca5eaa1801daf3ca1d23d70fb0ec8e5d82ca12a08b5e3a937"
LAUNCHER_SHA256 = "5b6337a1abd1fa23243cced88edb9f73ab453cffd676c7dfed599dc74fa63494"


def _replace(source, digest, replacements):
    if not isinstance(source, bytes) or hashlib.sha256(source).hexdigest() != digest:
        raise ValueError("Unsupported viewer revision")
    text = source.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    for old, new in replacements:
        if text.count(old) != 1:
            raise ValueError("Viewer composition changed")
        text = text.replace(old, new, 1)
    ast.parse(text)
    return text.replace("\n", newline).encode("utf-8")


def patch_reader(source):
    """Return a reader candidate; never modify a running release."""
    return _replace(
        source,
        READER_SHA256,
        [
            (
                "from phantomdocs.view_agent_gate import AgentGateMixin\n",
                "from phantomdocs.view_agent_mixed import MixedAgentGateMixin, validate_mixed_signers\n",
            ),
            (
                "class AgentRecipientGate(AgentGateMixin, RecipientGate):",
                "class AgentRecipientGate(MixedAgentGateMixin, RecipientGate):",
            ),
            (
                "class AgentMultiIssuerGate(AgentGateMixin, MultiIssuerGate):",
                "class AgentMultiIssuerGate(MixedAgentGateMixin, MultiIssuerGate):",
            ),
            (
                "additional_issuers=None, reviewed_knowledge=None, agent_actors=()):",
                "additional_issuers=None, reviewed_knowledge=None, agent_actors=(), mixed_agent_signers=None):",
            ),
            (
                "                              session_seconds=session_seconds, **route_options)\n",
                (
                    "                              session_seconds=session_seconds, **route_options)\n"
                    "        self.gate.mixed_agent_signers = validate_mixed_signers(\n"
                    "            mixed_agent_signers or {}, self.routes, enabled_actors)\n"
                ),
            ),
        ],
    )


def patch_launcher(source):
    """Return a launcher candidate accepting reviewed mixed signers."""
    return _replace(
        source,
        LAUNCHER_SHA256,
        [
            (
                "from trusted_handoff import DaemonPeerPolicy\n",
                (
                    "from trusted_handoff import DaemonPeerPolicy\n"
                    "from phantomdocs.view_agent_mixed import validate_mixed_signers\n"
                ),
            ),
            (
                "(FIELDS | {'additional_issuers', 'reviewed_knowledge', 'agent_actors'})",
                "(FIELDS | {'additional_issuers', 'reviewed_knowledge', 'agent_actors', 'mixed_agent_signers'})",
            ),
            (
                "    return result\n\n\ndef issuer_routes(config):\n",
                (
                    "    if 'mixed_agent_signers' in value:\n"
                    "        routes = [{key: result[key] for key in ISSUER_FIELDS}, *result.get('additional_issuers', [])]\n"
                    "        validate_mixed_signers(value['mixed_agent_signers'], routes, result.get('agent_actors', []))\n"
                    "        result['mixed_agent_signers'] = value['mixed_agent_signers']\n"
                    "    return result\n\n\ndef issuer_routes(config):\n"
                ),
            ),
            (
                "        options['agent_actors'] = config['agent_actors']\n",
                (
                    "        options['agent_actors'] = config['agent_actors']\n"
                    "    if 'mixed_agent_signers' in config:\n"
                    "        options['mixed_agent_signers'] = config['mixed_agent_signers']\n"
                ),
            ),
        ],
    )
