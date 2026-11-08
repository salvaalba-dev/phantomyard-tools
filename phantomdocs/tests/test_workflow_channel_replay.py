"""Synthetic tests for one-use channel proof admission."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from phantomdocs.workflow_channel_replay import ProofLedger


def consume(path, channel="telegram", digest="1" * 64, now=100, expires=200):
    ledger = ProofLedger(path)
    try:
        return ledger.consume(channel, digest, now=now, expires=expires)
    finally:
        ledger.close()


def test_replay_is_denied_after_reopen(tmp_path):
    path = tmp_path / "proofs.db"
    assert consume(path)
    assert not consume(path)
    assert consume(path, channel="nostr")


def test_concurrent_admission_is_unique(tmp_path):
    path = tmp_path / "proofs.db"
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: consume(path), range(8)))
    assert results.count(True) == 1
    assert results.count(False) == 7


def test_expired_and_unbounded_proofs_fail(tmp_path):
    path = tmp_path / "proofs.db"
    with pytest.raises(ValueError):
        consume(path, now=200, expires=200)
    with pytest.raises(ValueError):
        consume(path, now=100, expires=701)
    with pytest.raises(ValueError):
        consume(path, digest="not-a-proof")
