import json

import pytest

from phantomdocs.signing import npub_encode
from phantomdocs.view_agent_public_probe import public_identity


def test_explicit_public_identity_without_secrets():
    identity = npub_encode("11" * 32)
    payload = json.dumps([{"persona": "example", "npub": identity}]).encode()
    assert public_identity(payload, "example") == identity
    with pytest.raises(ValueError):
        public_identity(payload, "missing")


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b"[]",
        b"x" * 65537,
        b'[{"persona":"example","npub":null}]',
        b'[{"persona":"example","npub":"nsec1invalid"}]',
        b'[{"persona":"example","persona":"other"}]',
        b'[{"persona":"example"},{"persona":"example"}]',
    ],
)
def test_absent_malformed_or_ambiguous_identity_fails_closed(payload):
    with pytest.raises((ValueError, TypeError)):
        public_identity(payload, "example")
