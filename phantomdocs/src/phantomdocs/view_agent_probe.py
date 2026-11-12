"""Bounded identity probes; the caller owns credential access and lifecycle."""

import http.client
import json
import re

from coincurve import PrivateKey

from phantomdocs.signing import bech32_decode, npub_encode


def nostr_identity(nsec):
    """Derive only the public identity; never return the secret."""
    if not isinstance(nsec, str) or len(nsec) > 100:
        return None
    try:
        hrp, secret = bech32_decode(nsec)
        if hrp != "nsec" or len(secret) != 32:
            return None
        return npub_encode(PrivateKey(secret).public_key_xonly.format().hex())
    except (ValueError, TypeError):
        return None


def telegram_identity(token, *, connection_factory=http.client.HTTPSConnection):
    """Check the token against Telegram, returning only its public username."""
    if not isinstance(token, str) or not re.fullmatch(
        r"[0-9]{1,20}:[A-Za-z0-9_-]{20,100}", token
    ):
        return None
    conn = None
    try:
        conn = connection_factory("api.telegram.org", timeout=8)
        conn.request("POST", "/bot" + token + "/getMe", body=b"")
        response = conn.getresponse()
        if response.status != 200:
            return None
        data = response.read(16385)
        if len(data) > 16384:
            return None
        payload = json.loads(data)
        result = payload.get("result") if isinstance(payload, dict) else None
        name = result.get("username") if isinstance(result, dict) else None
        if (
            payload.get("ok") is not True
            or result.get("is_bot") is not True
            or not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", name)
        ):
            return None
        return "@" + name
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
        return None
    finally:
        if conn is not None:
            conn.close()
