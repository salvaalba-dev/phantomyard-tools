"""NIP-98 viewer request signing for a separately provisioned tool identity.

This primitive does not load or create keys, grant access, or invoke PhantomBot.
The private key must come from a protected tool-owned source in the fixed agent
account; it must never be supplied by a viewer request or stored in a prompt.
"""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit

from coincurve import PrivateKey


def sign_viewer_request(secret, origin):
    """Sign the existing viewer POST protocol with an explicit fixed origin."""
    if not isinstance(secret, bytes) or len(secret) != 32 or not isinstance(origin, str):
        raise ValueError("A fixed signer and HTTPS origin are required")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or parsed.netloc != parsed.hostname
            and not (parsed.port is not None and parsed.netloc == f"{parsed.hostname}:{parsed.port}")):
        raise ValueError("Canonical HTTPS origin required")
    try:
        signer = PrivateKey(secret)
    except ValueError:
        raise ValueError("Invalid tool signing key") from None
    event = {"pubkey": signer.public_key_xonly.format().hex(), "created_at": int(time.time()),
             "kind": 27235, "tags": [["u", origin + "/api/access-link"], ["method", "POST"],
                                     ["payload", hashlib.sha256(b"{}").hexdigest()],
                                     ["nonce", secrets.token_hex(16)]], "content": ""}
    canonical = [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]]
    event["id"] = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    event["sig"] = signer.sign_schnorr(bytes.fromhex(event["id"])).hex()
    encoded = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode()
    return "Nostr " + base64.b64encode(encoded).decode()
