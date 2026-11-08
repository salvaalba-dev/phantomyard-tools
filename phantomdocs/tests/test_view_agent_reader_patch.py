import hashlib

import pytest

from phantomdocs import view_agent_reader_patch as patcher


def test_rejects_unrecognized_reader():
    with pytest.raises(ValueError, match="Unsupported"):
        patcher.patch_reader(b"print('different')\n")


def test_candidate_preserves_source_and_patches_exact_composition(monkeypatch):
    source = (b"from trusted_handoff import DaemonPeerPolicy\n\n"
              b"class RecipientGate: pass\n\nclass MultiIssuerGate: pass\n\n"
              b"class PublishedReader:\n"
              b"    def build(self, authority, origin, port, audit):\n"
              b"        gate_type = MultiIssuerGate if len(self.routes) > 1 else RecipientGate\n"
              b"        return gate_type(origin, port, directory_loader=authority, audit=audit,\n"
              b"                         extra=True)\n")
    monkeypatch.setattr(patcher, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    result = patcher.patch_reader(source).decode()
    assert "AgentMultiIssuerGate if len(self.routes) > 1 else AgentRecipientGate" in result
    assert "ReaderAgentDirectory(org, HumanDirectory(org), actors)" in result
    assert "extra=True" in result


def test_rejects_missing_composition_anchor(monkeypatch):
    source = b"print('not the reader')\n"
    monkeypatch.setattr(patcher, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    with pytest.raises(ValueError, match="composition changed"):
        patcher.patch_reader(source)
