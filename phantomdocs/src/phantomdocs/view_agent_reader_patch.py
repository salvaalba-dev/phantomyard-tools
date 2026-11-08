"""Build a reviewed agent-scoped variant of one pinned PhantomView reader.

This returns candidate bytes only. It does not write to the installed reader,
change services or authorize deployment. A new reader release needs review and
its own expected source digest; unrecognized reader revisions are refused.
"""

import ast
import hashlib

SOURCE_SHA256 = "925efb3243ac025410b3df2941fac4128e91c94a7e745a6bb518557b528e9a59"
IMPORT_ANCHOR = "from trusted_handoff import DaemonPeerPolicy\n"
CLASS_ANCHOR = "\n\nclass PublishedReader:\n"
GATE_ANCHOR = (
    "        gate_type = MultiIssuerGate if len(self.routes) > 1 else RecipientGate\n"
)
LOADER_ANCHOR = "origin, port, directory_loader=authority, audit=audit,\n"
ASSISTANT_ANCHOR = "            from persona_conversation import NativePersonaClient, PersonaAssistant\n"


def patch_reader(source):
    """Return a candidate preserving the existing reader's projection and UI."""
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
    ):
        raise ValueError("Unsupported PhantomView reader revision")
    text = source.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    for anchor in (
        IMPORT_ANCHOR, CLASS_ANCHOR, GATE_ANCHOR, LOADER_ANCHOR, ASSISTANT_ANCHOR
    ):
        if text.count(anchor) != 1:
            raise ValueError("Reader composition changed")
    text = text.replace(
        IMPORT_ANCHOR,
        IMPORT_ANCHOR + "from phantomdocs.view_agent_gate import AgentGateMixin\n"
        "from phantomdocs.view_agent_directory import AgentDirectory\n"
        "from channel_identity import HumanDirectory\n",
        1,
    )
    text = text.replace(
        CLASS_ANCHOR,
        "\n\nclass AgentRecipientGate(AgentGateMixin, RecipientGate):\n"
        "    pass\n\n\nclass AgentMultiIssuerGate(AgentGateMixin, MultiIssuerGate):\n"
        "    pass\n\n\nclass ReaderAgentDirectory(AgentDirectory, HumanDirectory):\n"
        "    pass\n\n\ndef agent_directory_loader(authority, actors):\n"
        "    def load():\n"
        "        org = authority.read()\n"
        "        return ReaderAgentDirectory(org, HumanDirectory(org), actors)\n"
        "    return load\n" + CLASS_ANCHOR,
        1,
    )
    text = text.replace(
        GATE_ANCHOR,
        "        gate_type = AgentMultiIssuerGate if len(self.routes) > 1 else AgentRecipientGate\n",
        1,
    )
    text = text.replace(
        LOADER_ANCHOR,
        "origin, port, directory_loader=agent_directory_loader(\n"
        "                                      authority, frozenset(route['actor'] for route in self.routes)), audit=audit,\n",
        1,
    )
    text = text.replace(
        ASSISTANT_ANCHOR,
        "            from persona_conversation import NativePersonaClient, PersonaAssistant\n"
        "            class HumanOnlyPersonaAssistant(PersonaAssistant):\n"
        "                def available(self, headers):\n"
        "                    recipient, _ = self.gate.identified_scope(headers)\n"
        "                    return recipient.human is not None and super().available(headers)\n"
        "            PersonaAssistant = HumanOnlyPersonaAssistant\n",
        1,
    )
    ast.parse(text)
    return text.replace("\n", newline).encode("utf-8")
