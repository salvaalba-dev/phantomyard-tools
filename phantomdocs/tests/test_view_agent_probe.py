import json

from coincurve import PrivateKey

from phantomdocs.signing import _bech32_encode, _convertbits, npub_encode
from phantomdocs.view_agent_probe import nostr_identity, telegram_identity


def test_nostr_derives_public_identity():
    key = PrivateKey(b"\x01" * 32)
    nsec = _bech32_encode("nsec", _convertbits(list(key.secret), 8, 5))
    assert nostr_identity(nsec) == npub_encode(key.public_key_xonly.format().hex())
    assert nostr_identity(nsec[:-1] + "0") is None


def test_telegram_is_verified_without_redirects():
    class Response:
        status = 200

        def read(self, size):
            return json.dumps(
                {"ok": True, "result": {"is_bot": True, "username": "Example_bot"}}
            ).encode()

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.telegram.org" and timeout == 8

        def request(self, method, path, body):
            assert method == "POST" and path.endswith("/getMe")

        def getresponse(self):
            return Response()

        def close(self):
            pass

    assert (
        telegram_identity("123:" + "x" * 30, connection_factory=Connection)
        == "@Example_bot"
    )
    assert telegram_identity("invalid", connection_factory=Connection) is None
