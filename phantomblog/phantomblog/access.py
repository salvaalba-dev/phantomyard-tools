"""Short-lived dashboard grants issued to verified Nostr/PhantomChat identities."""

import base64
import hashlib
import json
import re
import secrets
import threading
import time
from http.client import HTTPConnection

from . import core

LIFETIME = 15 * 60
REQUEST_WINDOW = 60


def event_digest(event):
    """NIP-01 canonical event identifier; never includes the signature."""
    value = [
        0,
        event["pubkey"],
        event["created_at"],
        event["kind"],
        event["tags"],
        event["content"],
    ]
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


class AccessLinks:
    def __init__(self, identities=(), clock=time.monotonic, wall_clock=time.time):
        self.identities = frozenset(identities)
        if any(
            not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key)
            for key in self.identities
        ):
            raise core.Invalid(
                "Access identities must be lowercase 64-character Nostr public keys"
            )
        self.clock = clock
        self.wall_clock = wall_clock
        self.lock = threading.Lock()
        self.grants = {}
        self.requests = {}
        self.public_key = None
        if self.identities:
            try:
                from coincurve import PublicKeyXOnly
            except ImportError as exc:
                raise core.Invalid(
                    "Install phantomblog[access] to verify signed access requests"
                ) from exc
            self.public_key = PublicKeyXOnly

    def issue(self, authorization, origin):
        """Verify a fresh, single-use NIP-98 POST authorization before minting."""
        try:
            if (
                not self.identities
                or not authorization.startswith("Nostr ")
                or len(authorization) > 8192
            ):
                raise ValueError
            event = core.decode(base64.b64decode(authorization[6:], validate=True))
            if not isinstance(event, dict) or set(event) != {
                "id",
                "pubkey",
                "created_at",
                "kind",
                "tags",
                "content",
                "sig",
            }:
                raise ValueError
            if (
                event["pubkey"] not in self.identities
                or type(event["kind"]) is not int
                or event["kind"] != 27235
            ):
                raise ValueError
            if (
                type(event["created_at"]) is not int
                or abs(self.wall_clock() - event["created_at"]) > REQUEST_WINDOW
            ):
                raise ValueError
            tags = event["tags"]
            if (
                event["content"] != ""
                or not isinstance(tags, list)
                or not all(
                    isinstance(t, list) and all(isinstance(v, str) for v in t)
                    for t in tags
                )
            ):
                raise ValueError
            expected = {
                "u": origin + "/api/access-link",
                "method": "POST",
                "payload": hashlib.sha256(b"{}").hexdigest(),
            }
            for key, value in expected.items():
                if [t for t in tags if t and t[0] == key] != [[key, value]]:
                    raise ValueError
            if (
                not isinstance(event["id"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", event["id"])
                or event_digest(event) != event["id"]
            ):
                raise ValueError
            if not isinstance(event["sig"], str) or not re.fullmatch(
                r"[0-9a-f]{128}", event["sig"]
            ):
                raise ValueError
            if not self.public_key(bytes.fromhex(event["pubkey"])).verify(
                bytes.fromhex(event["sig"]), bytes.fromhex(event["id"])
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError, core.Invalid) as exc:
            raise core.Invalid("Signed access request refused") from exc
        with self.lock:
            now = self.clock()
            self.grants = {
                key: expires for key, expires in self.grants.items() if expires > now
            }
            self.requests = {
                key: expires for key, expires in self.requests.items() if expires > now
            }
            if (
                event["id"] in self.requests
                or len(self.grants) >= 1000
                or len(self.requests) >= 1000
            ):
                raise core.Invalid("Signed access request refused")
            code = secrets.token_urlsafe(32)
            self.grants[hashlib.sha256(code.encode()).digest()] = now + LIFETIME
            self.requests[event["id"]] = now + 2 * REQUEST_WINDOW + 1
            return origin + "/#c=" + code

    def redeem(self, code, create_session):
        """Consume only after session creation succeeds, atomically across threads."""
        if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", code):
            raise core.Invalid("Access link is invalid, expired or already used")
        digest = hashlib.sha256(code.encode()).digest()
        with self.lock:
            if self.grants.get(digest, 0) <= self.clock():
                self.grants.pop(digest, None)
                raise core.Invalid("Access link is invalid, expired or already used")
            session = create_session()
            del self.grants[digest]
            return session


def request_link(event, port):
    """Send an already-signed event to the fixed loopback issuer, without redirects."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise core.Invalid("Dashboard port must be between 1 and 65535")
    authorization = "Nostr " + base64.b64encode(core.encoded(event)).decode("ascii")
    if len(authorization) > 8192:
        raise core.Invalid("Signed access request is too large")
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(
            "POST",
            "/api/access-link",
            b"{}",
            {"Content-Type": "application/json", "Authorization": authorization},
        )
        response = connection.getresponse()
        value = core.decode(response.read(8193))
        if response.status != 200 or not isinstance(value, dict):
            raise core.Invalid("Signed access request refused")
        link = value.get("link")
        if not isinstance(link, str) or not re.fullmatch(
            rf"http://127\.0\.0\.1:{port}/#c=[A-Za-z0-9_-]{{43}}", link
        ):
            raise core.Invalid("Invalid access link response")
        return link
    finally:
        connection.close()
