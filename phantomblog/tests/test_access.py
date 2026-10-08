"""Signed identity and single-use access tests; all keys are ephemeral fixtures."""

import base64
import hashlib
import http.client
import json
import os
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest
from coincurve import PrivateKey
from fixtures import create

from phantomblog import access, cli, core, server


@pytest.fixture
def dashboard(tmp_path):
    create(tmp_path)
    key = PrivateKey()
    identity = key.public_key_xonly.format().hex()
    now = [1000.0, 1700000000]
    links = access.AccessLinks([identity], lambda: now[0], lambda: now[1])
    token = "synthetic-admin-only-server-fixture"
    with patch.object(server.access, "AccessLinks", return_value=links):
        httpd = server.make_server(tmp_path, token, 0, access_identities=[identity])
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{httpd.server_port}"

    def signed(**changes):
        event = {
            "pubkey": identity,
            "created_at": now[1],
            "kind": 27235,
            "tags": [
                ["u", origin + "/api/access-link"],
                ["method", "POST"],
                ["payload", hashlib.sha256(b"{}").hexdigest()],
                [
                    "nonce",
                    base64.b64encode(
                        key.sign_schnorr(hashlib.sha256(str(now).encode()).digest())
                    ).decode(),
                ],
            ],
            "content": "",
        }
        event.update(changes)
        event["id"] = access.event_digest(event)
        event["sig"] = key.sign_schnorr(bytes.fromhex(event["id"])).hex()
        return event

    def request(path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", httpd.server_port, timeout=5
        )
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or {})
        payload = json.dumps(body, separators=(",", ":")) if body is not None else None
        connection.request(
            "POST" if body is not None else "GET", path, payload, request_headers
        )
        response = connection.getresponse()
        result = (response.status, response.read(), dict(response.getheaders()))
        connection.close()
        return result

    def issue(event=None, headers=None):
        event = signed() if event is None else event
        authorization = "Nostr " + base64.b64encode(core.encoded(event)).decode()
        return request(
            "/api/access-link", {}, {"Authorization": authorization, **(headers or {})}
        )

    def code():
        status, body, _ = issue()
        assert status == 200
        url = json.loads(body)["link"]
        parsed = urlsplit(url)
        assert parsed.path == "/" and not parsed.query
        assert token not in url
        return parse_qs(parsed.fragment)["c"][0], url

    yield links, now, signed, request, issue, code, token, httpd, tmp_path
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=3)


def test_valid_link_authenticates_with_existing_session(dashboard):
    _, _, _, request, _, code, _, _, _ = dashboard
    value, url = code()
    assert request(urlsplit(url).path)[0] == 200
    assert request("/api/state")[0] == 401
    status, body, headers = request("/api/redeem", {"code": value})
    assert status == 200 and json.loads(body) == {"ok": True}
    cookie = headers["Set-Cookie"]
    for attribute in ("HttpOnly", "SameSite=Strict", "Secure", "Path=/"):
        assert attribute in cookie
    assert value not in cookie
    session = cookie.split(";")[0]
    assert request("/api/state", headers={"Cookie": session})[0] == 200
    assert request("/api/logout", {}, {"Cookie": session})[0] == 200
    assert request("/api/state", headers={"Cookie": session})[0] == 401


def test_expired_link(dashboard):
    _, now, _, request, _, code, _, _, _ = dashboard
    value, _ = code()
    now[0] += access.LIFETIME
    assert request("/api/redeem", {"code": value})[0] == 401


def test_used_and_invalid_links(dashboard):
    _, _, _, request, _, code, _, _, _ = dashboard
    value, _ = code()
    assert request("/api/redeem", {"code": value})[0] == 200
    assert request("/api/redeem", {"code": value})[0] == 401
    for invalid in ("invented", "a" * 43, None, 123, {}):
        assert request("/api/redeem", {"code": invalid})[0] == 401


def test_foreign_origin_and_host_cannot_issue_or_consume(dashboard):
    _, _, signed, request, issue, code, _, _, _ = dashboard
    event = signed()
    assert issue(event, {"Origin": "https://foreign.invalid"})[0] == 403
    assert issue(event, {"Host": "foreign.invalid"})[0] == 403
    assert issue(event)[0] == 200
    value, _ = code()
    assert (
        request("/api/redeem", {"code": value}, {"Origin": "https://foreign.invalid"})[
            0
        ]
        == 403
    )
    assert (
        request("/api/redeem", {"code": value}, {"Sec-Fetch-Site": "cross-site"})[0]
        == 403
    )
    assert request("/api/redeem", {"code": value})[0] == 200


def test_signature_allowlist_freshness_binding_and_replay(dashboard):
    _, now, signed, _, issue, _, token, _, _ = dashboard
    event = signed()
    assert issue(event)[0] == 200
    assert issue(event)[0] == 401
    for changes in (
        {"pubkey": PrivateKey().public_key_xonly.format().hex()},
        {"created_at": now[1] - 61},
        {"created_at": now[1] + 61},
        {"content": "request access"},
        {"kind": 1},
        {
            "tags": [
                ["u", "https://foreign.invalid/api/access-link"],
                ["method", "POST"],
            ]
        },
    ):
        assert issue(signed(**changes))[0] == 401
    bad = signed()
    bad["sig"] = "0" * 128
    assert issue(bad)[0] == 401
    bad = signed()
    bad["id"] = "0" * 64
    assert issue(bad)[0] == 401
    assert issue(headers={"Authorization": "Bearer " + token})[0] == 401


def test_credentials_never_in_query_response_or_logs(dashboard, capsys):
    _, _, _, request, _, code, token, _, _ = dashboard
    value, url = code()
    assert "#c=" in url and "?c=" not in url
    status, body, _ = request("/api/redeem?c=" + value, {"code": value})
    assert status == 400 and value.encode() not in body
    assert request("/api/redeem", {"code": value})[0] == 200
    assert request("/api/access-link?c=" + value, {})[0] == 400
    output = capsys.readouterr()
    assert value not in output.out + output.err
    assert token not in output.out + output.err
    assert value.encode() not in request("/dashboard.js")[1]


def test_only_first_concurrent_redeemer_succeeds(dashboard):
    _, _, _, request, _, code, _, _, _ = dashboard
    value, _ = code()
    with ThreadPoolExecutor(max_workers=8) as executor:
        statuses = list(
            executor.map(lambda _: request("/api/redeem", {"code": value})[0], range(8))
        )
    assert statuses.count(200) == 1
    assert statuses.count(401) == 7


def test_failed_session_creation_does_not_consume_code(dashboard):
    links, _, _, _, _, code, _, _, _ = dashboard
    value, _ = code()

    def fail():
        raise RuntimeError("Synthetic session failure")

    with pytest.raises(RuntimeError):
        links.redeem(value, fail)
    assert links.redeem(value, lambda: "synthetic-session") == "synthetic-session"


def test_cli_outputs_one_line_without_admin_token(dashboard, capsys, tmp_path):
    _, _, signed, _, _, _, token, httpd, _ = dashboard
    event = tmp_path / "signed-event.json"
    event.write_bytes(core.encoded(signed()))
    assert (
        cli.main(
            [
                "access-link",
                "--port",
                str(httpd.server_port),
                "--signed-event",
                str(event),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert len(output.splitlines()) == 1
    assert output.startswith(f"http://127.0.0.1:{httpd.server_port}/#c=")
    assert token not in output


def test_no_allowlist_fails_closed_and_restart_invalidates(dashboard):
    _, _, signed, _, _, code, _, _, _ = dashboard
    empty = access.AccessLinks()
    with pytest.raises(core.Invalid):
        empty.issue(
            "Nostr " + base64.b64encode(core.encoded(signed())).decode(),
            "http://127.0.0.1:8787",
        )
    value, _ = code()
    with pytest.raises(core.Invalid):
        empty.redeem(value, lambda: "session")
    with pytest.raises(core.Invalid):
        access.AccessLinks(["not-a-public-key"])


def test_frontend_cleans_fragment_before_fetch_and_never_persists():
    text = (core.RESOURCES / "dashboard.js").read_text(encoding="utf-8")
    assert text.index("history.replaceState") < text.index("fetch(")
    assert "api('redeem', {code})" in text
    assert "localStorage" not in text and "sessionStorage" not in text
    assert "accessCode = null;" in text


def test_dashboard_fragment_bootstrap_executes():
    node = os.environ.get("PHANTOMBLOG_TEST_NODE") or shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the dashboard JavaScript regression")
    subprocess.run(
        [
            node,
            str(Path(__file__).with_name("dashboard_access.cjs")),
            str(core.RESOURCES / "dashboard.js"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_existing_admin_login_also_keeps_secure_cookie(dashboard):
    _, _, _, request, _, _, token, _, _ = dashboard
    status, _, headers = request("/api/login", {"token": token})
    assert status == 200
    assert "Secure" in headers["Set-Cookie"]


def test_signed_payload_must_match_exact_request_bytes(dashboard):
    _, _, signed, _, issue, _, _, httpd, _ = dashboard
    event = signed()
    connection = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=5)
    try:
        connection.request(
            "POST",
            "/api/access-link",
            b"{ }",
            {
                "Content-Type": "application/json",
                "Authorization": "Nostr "
                + base64.b64encode(core.encoded(event)).decode(),
            },
        )
        response = connection.getresponse()
        response.read()
        assert response.status == 400
    finally:
        connection.close()
    assert issue(event)[0] == 200


def test_malformed_authorization_and_missing_allowlist_dependency(dashboard):
    _, _, _, _, issue, _, _, _, _ = dashboard
    for header in ("Nostr !!!", "Bearer fixture", "Nostr " + "a" * 8192, "Nostr e30="):
        assert issue(headers={"Authorization": header})[0] == 401
    with (
        patch.dict("sys.modules", {"coincurve": None}),
        pytest.raises(core.Invalid, match="Install phantomblog"),
    ):
        access.AccessLinks(["a" * 64])
