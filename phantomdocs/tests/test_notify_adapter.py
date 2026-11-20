"""Persona selection, provider receipts and secret-free durable-send intent."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from phantomdocs import notify_adapter as adapter

pytestmark = pytest.mark.skipif(
    adapter.tomllib is None, reason="standalone notify adapter requires Python 3.11+"
)


@pytest.fixture
def runtime():
    return {
        "schema_version": 1,
        "data_dir": "/srv/example/phantombot",
        "config_path": "/etc/example/phantombot.toml",
        "ledger_path": "/var/lib/example-alerts/sends.jsonl",
        "telegram_chat": "10001",
        "mail_to": "operator@example.invalid",
        "workspace_send_args": [
            "send",
            "{recipient}",
            "{subject}",
            "--body",
            "{message}",
        ],
        "workspace_sha256": "a" * 64,
        "workspace_receipt": "message-id-line",
    }


@pytest.mark.parametrize(
    "explicit,env,state,config,names,expected",
    [
        (
            "explicit",
            "env",
            {"default_persona": "state"},
            {"default_persona": "config"},
            [],
            "explicit",
        ),
        (
            None,
            "env",
            {"default_persona": "state"},
            {"default_persona": "config"},
            [],
            "env",
        ),
        (
            None,
            None,
            {"default_persona": "state"},
            {"default_persona": "config"},
            [],
            "state",
        ),
        (None, None, {}, {"default_persona": "config"}, [], "config"),
        (None, None, {}, {}, ["only"], "only"),
    ],
)
def test_persona_selection_uses_the_requested_precedence(
    explicit, env, state, config, names, expected
):
    assert adapter.select_persona(explicit, env, state, config, names) == expected


@pytest.mark.parametrize(
    "explicit,names",
    [
        (None, []),
        (None, ["one", "two"]),
        ("../other", ["only"]),
        ("", ["only"]),
        (123, ["only"]),
    ],
)
def test_invalid_or_ambiguous_persona_never_falls_back(explicit, names):
    with pytest.raises(ValueError):
        adapter.select_persona(explicit, None, {}, {}, names)


@pytest.fixture
def delivery(runtime, monkeypatch):
    entries, sends = [], []
    monkeypatch.setattr(
        adapter, "resolve", lambda *a: ("resolved", Path("/persona/resolved"), 1001)
    )
    monkeypatch.setattr(
        adapter, "append_ledger", lambda path, value: entries.append(value)
    )
    monkeypatch.setattr(
        adapter, "telegram", lambda *a: sends.append("telegram") or ("42", 1700000000)
    )
    monkeypatch.setattr(
        adapter, "email", lambda *a: sends.append("email") or ("provider-mail-42", None)
    )
    payload = {
        "schema_version": 1,
        "channel": "telegram",
        "recipient": "10001",
        "message": "unit=example.service host=example state=timeout time=synthetic",
    }
    return runtime, payload, entries, sends


def test_intent_precedes_send_and_provider_id_and_date_are_recorded_without_body(
    delivery, monkeypatch
):
    runtime, payload, entries, sends = delivery

    def telegram(*args):
        assert entries[0]["status"] == "attempting"
        sends.append("telegram")
        return "42", 1700000000

    monkeypatch.setattr(adapter, "telegram", telegram)
    ack = adapter.deliver(runtime, payload)
    assert ack["delivered"] and ack["recipient"] == "10001"
    assert [e["status"] for e in entries] == ["attempting", "accepted"]
    assert entries[0]["attempt_id"] == entries[1]["attempt_id"]
    assert (
        entries[1]["message_id"] == "42" and entries[1]["provider_date"] == 1700000000
    )
    assert all(e["persona"] == "resolved" for e in entries)
    assert "message" not in entries[1] and payload["message"] not in json.dumps(entries)


def test_unavailable_ledger_prevents_the_send(delivery, monkeypatch):
    runtime, payload, _, sends = delivery

    def fail(*args):
        raise OSError("disk unavailable")

    monkeypatch.setattr(adapter, "append_ledger", fail)
    with pytest.raises(OSError):
        adapter.deliver(runtime, payload)
    assert sends == []


def test_missing_persona_directory_prevents_credential_reads_and_all_sends(
    delivery, monkeypatch
):
    runtime, payload, entries, sends = delivery

    def absent(*args):
        raise FileNotFoundError("persona absent")

    monkeypatch.setattr(adapter, "resolve", absent)
    with pytest.raises((FileNotFoundError, ValueError)):
        adapter.deliver(runtime, payload)
    assert not entries and not sends


def test_timeout_records_unknown_delivery_without_exception_details_or_retry(
    delivery, monkeypatch
):
    runtime, payload, entries, sends = delivery

    def timeout(*args):
        sends.append("telegram")
        raise OSError("https://api.telegram.org/botPRIVATE-TOKEN/sendMessage")

    monkeypatch.setattr(adapter, "telegram", timeout)
    with pytest.raises(ValueError) as failure:
        adapter.deliver(runtime, payload)
    assert "PRIVATE-TOKEN" not in str(failure.value) + json.dumps(entries)
    assert entries[-1]["status"] == "failed-or-unknown" and sends == ["telegram"]


def test_mail_records_actual_message_id(delivery):
    runtime, payload, entries, _ = delivery
    payload.update(channel="email", recipient="operator@example.invalid")
    adapter.deliver(runtime, payload)
    assert entries[-1]["message_id"] == "provider-mail-42"


def test_payload_cannot_override_private_destinations(delivery):
    runtime, payload, entries, sends = delivery
    payload["recipient"] = "other"
    with pytest.raises(ValueError):
        adapter.deliver(runtime, payload)
    assert not entries and not sends


@pytest.mark.parametrize(
    "raw,format_name",
    [
        ("sent", "message-id-line"),
        ('{"ok":true}', "message-id-line"),
        ("Message ID: one\nMessage ID: two", "message-id-line"),
        (
            "\N{WHITE HEAVY CHECK MARK} Sent. Message ID: one\nMessage ID: two",
            "message-id-line",
        ),
        ("\N{WHITE HEAVY CHECK MARK} Sent. Message ID: ?", "message-id-line"),
        ('{"id":"bad\\nvalue"}', "message-id-line"),
    ],
)
def test_mail_exit_success_without_one_provider_message_id_is_insufficient(
    raw, format_name
):
    with pytest.raises(ValueError):
        adapter.parse_mail_receipt(raw, format_name)


def test_native_mail_receipt_is_a_single_Message_ID_line():
    with pytest.raises(ValueError):
        adapter.parse_mail_receipt('{"id":"gmail42"}', "json-id")
    assert (
        adapter.parse_mail_receipt(
            "Message ID: <example42@example.invalid>\n", "message-id-line"
        )
        == "<example42@example.invalid>"
    )


def test_installed_workspace_receipt_prefix_is_accepted():
    # The installed persona tool prints "✅ Sent. Message ID: <id>" (one line on
    # stdout), so the prefixed form must yield the provider id, not a failure.
    assert (
        adapter.parse_mail_receipt(
            "\N{WHITE HEAVY CHECK MARK} Sent. Message ID: 19a4c2f7b3e1d9a0\n",
            "message-id-line",
        )
        == "19a4c2f7b3e1d9a0"
    )


@pytest.mark.parametrize("change", ["chat", "date", "id", "ok"])
def test_telegram_requires_actual_private_chat_message_id_and_provider_date(
    monkeypatch, change
):
    config = b'[channels.telegram]\ntoken="123456:AAAAAAAAAAAAAAAAAAAAAAAA"\nallowed_user_ids=[10001]\n'
    monkeypatch.setattr(adapter, "read_file", lambda *a, **kw: config)
    result = {
        "ok": True,
        "result": {
            "message_id": 42,
            "date": 1700000000,
            "chat": {"id": 10001, "type": "private"},
        },
    }
    if change == "chat":
        result["result"]["chat"]["id"] = 10002
    elif change == "date":
        result["result"].pop("date")
    elif change == "id":
        result["result"]["message_id"] = True
    else:
        result["ok"] = False

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return json.dumps(result).encode()

    monkeypatch.setattr(
        adapter.urllib.request,
        "build_opener",
        lambda *a: SimpleNamespace(open=lambda *a, **kw: Response()),
    )
    with pytest.raises(ValueError):
        adapter.telegram(Path("/persona"), 1001, "10001", "synthetic state")


def test_telegram_never_borrows_a_global_token_or_adds_an_allowlist_entry(monkeypatch):
    monkeypatch.setattr(
        adapter,
        "read_file",
        lambda *a, **kw: (
            b'[channels.telegram]\ntoken="123456:AAAAAAAAAAAAAAAAAAAAAAAA"\nallowed_user_ids=[10002]\n'
        ),
    )

    def forbidden(*args):
        pytest.fail("unauthorized recipient reached network setup")

    monkeypatch.setattr(adapter.urllib.request, "build_opener", forbidden)
    with pytest.raises(ValueError, match="authorization"):
        adapter.telegram(Path("/persona"), 1001, "10001", "synthetic")


def test_telegram_uses_fixed_https_origin_and_keeps_token_out_of_request_body(
    monkeypatch,
):
    token = "123456:AAAAAAAAAAAAAAAAAAAAAAAA"
    monkeypatch.setattr(
        adapter,
        "read_file",
        lambda *a, **kw: (
            '[channels.telegram]\ntoken="' + token + '"\nallowed_user_ids=[10001]\n'
        ).encode(),
    )
    seen = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return b'{"ok":true,"result":{"message_id":42,"date":1700000000,"chat":{"id":10001,"type":"private"}}}'

    def opened(request, **kwargs):
        seen.append((request, kwargs))
        return Response()

    monkeypatch.setattr(
        adapter.urllib.request, "build_opener", lambda *a: SimpleNamespace(open=opened)
    )
    assert adapter.telegram(Path("/persona"), 1001, "10001", "synthetic") == (
        "42",
        1700000000,
    )
    request, options = seen[0]
    assert request.full_url == "https://api.telegram.org/bot" + token + "/sendMessage"
    assert json.loads(request.data) == {"chat_id": "10001", "text": "synthetic"}
    assert token.encode() not in request.data and options["timeout"] == 20


def test_workspace_runs_only_the_pinned_persona_tool_under_its_existing_uid(
    runtime, monkeypatch
):
    import hashlib
    import sys

    tool = b"# synthetic reviewed workspace"
    runtime["workspace_sha256"] = hashlib.sha256(tool).hexdigest()
    monkeypatch.setattr(adapter, "read_file", lambda *a, **kw: tool)
    monkeypatch.setitem(
        sys.modules,
        "pwd",
        SimpleNamespace(
            getpwuid=lambda uid: SimpleNamespace(pw_gid=1002, pw_dir="/home/example")
        ),
    )
    monkeypatch.setattr(adapter.os, "geteuid", lambda: 0, raising=False)
    seen = []
    monkeypatch.setattr(
        adapter.subprocess,
        "run",
        lambda *a, **kw: (
            seen.append((a, kw))
            or SimpleNamespace(returncode=0, stdout="Message ID: provider42\n")
        ),
    )
    assert adapter.email(
        runtime,
        "resolved",
        Path("/persona/resolved"),
        1001,
        "operator@example.invalid",
        "synthetic",
    ) == ("provider42", None)
    args, options = seen[0]
    assert args[0] == [
        "/usr/bin/python3",
        str(Path("/persona/resolved") / "tools" / "workspace.py"),
        "send",
        "operator@example.invalid",
        "Organization policy operational alert",
        "--body",
        "synthetic",
    ]
    assert (
        options["user"] == 1001
        and options["group"] == 1002
        and options["extra_groups"] == []
    )
    assert options["env"] == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/example",
        "LANG": "C.UTF-8",
        "PHANTOMBOT_PERSONA": "resolved",
    }
    assert "shell" not in options and options["timeout"] == 20


@pytest.mark.parametrize(
    "change", ["json-receipt", "guessed-options", "extra-argument"]
)
def test_only_the_confirmed_workspace_interface_is_accepted(runtime, change):
    if change == "json-receipt":
        runtime["workspace_receipt"] = "json-id"
    elif change == "guessed-options":
        runtime["workspace_send_args"] = [
            "send",
            "--to",
            "{recipient}",
            "--body",
            "{message}",
        ]
    else:
        runtime["workspace_send_args"].append("--extra")
    with pytest.raises(ValueError):
        adapter.validate_runtime(runtime)


def test_workspace_hash_mismatch_refuses_mail_before_subprocess(runtime, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace())
    monkeypatch.setattr(
        adapter, "read_file", lambda *a, **kw: b"different installed workspace"
    )

    def forbidden(*args, **kwargs):
        pytest.fail("unreviewed workspace must not execute")

    monkeypatch.setattr(adapter.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="reviewed source"):
        adapter.email(
            runtime,
            "resolved",
            Path("/persona/resolved"),
            1001,
            "operator@example.invalid",
            "synthetic",
        )


def test_cli_loads_the_root_controlled_profile_without_relaxing_secret_reader(
    runtime, monkeypatch, capsys
):
    import io
    import sys

    selected = []
    monkeypatch.setattr(
        sys,
        "argv",
        ["notify-adapter", "--runtime-config", "/etc/example-alerts/runtime.json"],
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(
        adapter, "read_runtime_config", lambda path: selected.append(path) or runtime
    )

    def secret_reader_must_not_be_reused(*args, **kwargs):
        pytest.fail("runtime metadata must not reuse or loosen the 0600 secret reader")

    monkeypatch.setattr(adapter, "read_file", secret_reader_must_not_be_reused)
    monkeypatch.setattr(
        adapter,
        "deliver",
        lambda config, payload, persona: {
            "delivered": True,
            "profile": config["schema_version"],
        },
    )
    adapter.main()
    assert selected == ["/etc/example-alerts/runtime.json"]
    assert json.loads(capsys.readouterr().out) == {"delivered": True, "profile": 1}
