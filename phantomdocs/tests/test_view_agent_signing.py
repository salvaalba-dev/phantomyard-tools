import base64
import hashlib
import json

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from phantomdocs.view_agent_signing import sign_viewer_request


def test_signed_event_has_expected_binding_and_fresh_nonce():
    secret = PrivateKey().secret
    first = sign_viewer_request(secret, "https://view.example:8790")
    second = sign_viewer_request(secret, "https://view.example:8790")
    event = json.loads(base64.b64decode(first.removeprefix("Nostr ")))
    other = json.loads(base64.b64decode(second.removeprefix("Nostr ")))
    assert ["u", "https://view.example:8790/api/access-link"] in event["tags"]
    assert ["method", "POST"] in event["tags"]
    assert event["tags"][-1] != other["tags"][-1]
    canonical = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    digest = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()
    ).digest()
    assert digest.hex() == event["id"]
    assert PublicKeyXOnly(bytes.fromhex(event["pubkey"])).verify(
        bytes.fromhex(event["sig"]), digest
    )


@pytest.mark.parametrize(
    "origin",
    [
        "http://view.example",
        "https://view.example/path",
        "https://user@view.example",
        "https://view.example?x=1",
    ],
)
def test_noncanonical_origins_are_rejected(origin):
    with pytest.raises(ValueError):
        sign_viewer_request(PrivateKey().secret, origin)
