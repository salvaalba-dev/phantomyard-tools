"""Version-controlled, stdlib-only persona-aware notification transport.

Python 3.11+; Linux protected paths and ledger. No CLI broadcast, permission
changes, automatic retries, credential discovery outside the selected persona,
or OAuth scope changes. Run only after separate installation/delivery approval.
"""

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess  # nosec B404 -- fixed interpreter and pinned persona tool, no shell
import sys
import urllib.request
import uuid

try:
    import tomllib
except ImportError:  # no optional dependency: standalone runtime must be Python 3.11+
    tomllib = None
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


class PersonaResolutionError(ValueError):
    """Safe diagnostic: no credential or provider exception text."""


MAX_BYTES = 131072
IDENTIFIER = r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}"
WORKSPACE_SEND_ARGS = ["send", "{recipient}", "{subject}", "--body", "{message}"]


@contextmanager
def directory(path, owner):
    path = Path(path)
    if not path.is_absolute() or any(p in (".", "..") for p in path.parts):
        raise ValueError("absolute protected path required")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            info = os.fstat(fd)
            if info.st_uid not in (0, owner) or info.st_mode & 0o022:
                raise ValueError("unprotected directory")
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid not in (0, owner) or info.st_mode & 0o022:
            raise ValueError("unprotected directory")
        yield fd
    finally:
        os.close(fd)


def read_file(path, owner, *, private=False, optional=False):
    path = Path(path)
    try:
        with directory(path.parent, owner) as parent:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=parent,
            )
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid not in (0, owner)
                    or before.st_mode & 0o022
                    or before.st_nlink != 1
                    or private
                    and stat.S_IMODE(before.st_mode) != 0o600
                ):
                    raise ValueError("unprotected file")
                raw = os.read(fd, MAX_BYTES + 1)
                after = os.fstat(fd)
                if len(raw) > MAX_BYTES or (
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("file changed or exceeded limit")
                return raw
            finally:
                os.close(fd)
    except FileNotFoundError:
        if optional:
            return None
        raise


def read_runtime_config(path):
    """Read root-controlled metadata, separately from 0600 persona secrets.

    A 0640 profile must belong to the caller's effective primary group. Root
    operators may also use root-owned 0600 profiles. Ancestors remain root-owned
    and protected; this reader never changes ownership, modes, ACLs or groups.
    """
    path = Path(path)
    with directory(path.parent, 0) as parent:
        fd = os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            before = os.fstat(fd)
            mode = stat.S_IMODE(before.st_mode)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0
                or before.st_nlink != 1
                or mode not in (0o600, 0o640)
                or mode == 0o640
                and before.st_gid != os.getegid()
            ):
                raise ValueError("unprotected root-owned runtime configuration")
            raw = os.read(fd, MAX_BYTES + 1)
            after = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            identity = tuple(getattr(before, key) for key in fields)
            if (
                len(raw) > MAX_BYTES
                or len(raw) != before.st_size
                or identity != tuple(getattr(after, key) for key in fields)
                or identity != tuple(getattr(named, key) for key in fields)
            ):
                raise ValueError("runtime configuration changed or exceeded limit")
            return json.loads(raw)
        finally:
            os.close(fd)


def select_persona(explicit, environment, state, config, available):
    """Do not skip a stated-but-invalid choice or invent a default persona."""
    for value in (
        explicit,
        environment,
        state.get("default_persona"),
        config.get("default_persona"),
    ):
        if value is not None:
            if not isinstance(value, str) or not re.fullmatch(IDENTIFIER, value):
                raise ValueError("invalid selected persona")
            return value
    if len(available) != 1:
        raise ValueError("persona is ambiguous; select --persona explicitly")
    value = available[0]
    if not re.fullmatch(IDENTIFIER, value):
        raise ValueError("invalid only persona")
    return value


def resolve(runtime, explicit=None, environ=None):
    environ = os.environ if environ is None else environ
    data = Path(runtime["data_dir"])
    owner = data.lstat().st_uid
    with directory(data, owner):
        pass
    config_raw = read_file(runtime["config_path"], owner, optional=True)
    config = tomllib.loads(config_raw.decode()) if config_raw is not None else {}
    if not isinstance(config, dict):
        raise TypeError("invalid global configuration")
    # An explicit/environment choice does not need lower-priority state to parse.
    selected = explicit if explicit is not None else environ.get("PHANTOMBOT_PERSONA")
    state = {}
    if selected is None:
        state_raw = read_file(data / "state.json", owner, optional=True)
        state = json.loads(state_raw) if state_raw is not None else {}
        if not isinstance(state, dict):
            raise ValueError("invalid persona state")
    personas = Path(config.get("personas_dir", data / "personas"))
    with directory(personas, owner) as fd:
        # O_PATH cannot list. Open this pinned directory for listing only when
        # the final unique-persona fallback is actually needed.
        available = []
        if (
            selected is None
            and state.get("default_persona") is None
            and config.get("default_persona") is None
        ):
            listing = os.open(
                ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd
            )
            try:
                available = [
                    name
                    for name in os.listdir(listing)
                    if stat.S_ISDIR(
                        os.stat(name, dir_fd=listing, follow_symlinks=False).st_mode
                    )
                ]
            finally:
                os.close(listing)
    name = select_persona(
        explicit, environ.get("PHANTOMBOT_PERSONA"), state, config, available
    )
    persona = personas / name
    # A root-controlled namespace can contain personas owned by different
    # existing accounts. Select the actual directory owner without following links.
    with directory(personas, owner) as parent:
        fd = os.open(
            name,
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            selected_owner = os.fstat(fd).st_uid
        finally:
            os.close(fd)
    # Existence and protection are verified before reading credentials or sending.
    with directory(persona, selected_owner):
        pass
    return name, persona, selected_owner


def validate_runtime(value):
    fields = {
        "schema_version",
        "data_dir",
        "config_path",
        "ledger_path",
        "telegram_chat",
        "mail_to",
        "workspace_send_args",
        "workspace_sha256",
        "workspace_receipt",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("invalid notify runtime configuration")
    for key in ("data_dir", "config_path", "ledger_path"):
        if (
            not isinstance(value[key], str)
            or not value[key].startswith("/")
            or ".." in Path(value[key]).parts
        ):
            raise ValueError("invalid notify runtime path")
    if not isinstance(value["telegram_chat"], str) or not re.fullmatch(
        r"[1-9][0-9]{0,19}", value["telegram_chat"]
    ):
        raise ValueError("direct Telegram user required")
    if not isinstance(value["mail_to"], str) or not re.fullmatch(
        r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value["mail_to"]
    ):
        raise ValueError("single mail recipient required")
    if value["workspace_receipt"] != "message-id-line":
        raise ValueError("reviewed workspace receipt format required")
    if not isinstance(value["workspace_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", value["workspace_sha256"]
    ):
        raise ValueError("reviewed workspace digest required")
    if value["workspace_send_args"] != WORKSPACE_SEND_ARGS:
        raise ValueError("workspace requires send <to> <subject> --body <msg>")
    return value


def record(persona, payload, attempt, status, *, message_id=None, provider_date=None):
    return {
        "date": datetime.now(timezone.utc).isoformat(),
        "attempt_id": attempt,
        "persona": persona,
        "channel": payload["channel"],
        "recipient": payload["recipient"],
        "message_id": message_id,
        "provider_date": provider_date,
        "status": status,
    }


def append_ledger(path, value):
    import fcntl

    path = Path(path)
    with directory(path.parent, os.geteuid()) as parent:
        fd = os.open(
            path.name,
            os.O_RDWR
            | os.O_APPEND
            | os.O_CREAT
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | os.O_CLOEXEC,
            0o600,
            dir_fd=parent,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise ValueError("private append-only ledger required")
            fcntl.flock(fd, fcntl.LOCK_EX)
            if (
                os.fstat(fd).st_size
                and os.pread(fd, 1, os.fstat(fd).st_size - 1) != b"\n"
            ):
                raise ValueError("ledger has a torn record; preserve for review")
            raw = (json.dumps(value, sort_keys=True) + "\n").encode()
            while raw:
                count = os.write(fd, raw)
                if count == 0:
                    raise OSError("ledger write failed")
                raw = raw[count:]
            os.fsync(fd)
            # O_PATH pins ancestry; a separate ordinary descriptor syncs creation.
            normal_parent = os.open(
                ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=parent
            )
            try:
                os.fsync(normal_parent)
            finally:
                os.close(normal_parent)
        finally:
            os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def telegram(persona, owner, recipient, message):
    config = tomllib.loads(
        read_file(persona / "config.toml", owner, private=True).decode()
    )
    account = config.get("channels", {}).get("telegram", {})
    token = account.get("token")
    if not isinstance(token, str) or not re.fullmatch(
        r"[0-9]{3,}:[A-Za-z0-9_-]{16,}", token
    ):
        raise ValueError("persona Telegram token unavailable")
    allowed = account.get("allowed_user_ids")
    if not isinstance(allowed, list) or recipient not in {
        str(i) for i in allowed if type(i) in (int, str)
    }:
        raise ValueError("recipient is outside existing persona authorization")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        data=json.dumps({"chat_id": recipient, "text": message}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    with opener.open(request, timeout=5) as response:  # nosec B310 -- fixed HTTPS Telegram origin, no redirects
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Telegram response exceeded limit")
    result = json.loads(raw)
    value = result.get("result", {})
    if (
        result.get("ok") is not True
        or not isinstance(value, dict)
        or value.get("chat", {}).get("type") != "private"
        or str(value.get("chat", {}).get("id")) != recipient
        or type(value.get("message_id")) is not int
        or value["message_id"] <= 0
        or type(value.get("date")) is not int
        or value["date"] <= 0
    ):
        raise ValueError("Telegram direct-message receipt unavailable")
    return str(value["message_id"]), value["date"]


def parse_mail_receipt(raw, format_name):
    if len(raw) > MAX_BYTES:
        raise ValueError("workspace output exceeded limit")
    if format_name != "message-id-line":
        raise ValueError("workspace requires a Message ID: receipt line")
    # The installed persona tool prints "✅ Sent. Message ID: <id>". The bare
    # form is still accepted so the contract does not depend on that prefix;
    # exactly one receipt line is required either way.
    matches = re.findall(
        r"^(?:\N{WHITE HEAVY CHECK MARK} Sent\. )?Message ID: ([A-Za-z0-9_.@<>:-]+)$",
        raw,
        re.MULTILINE,
    )
    identifier = matches[0] if len(matches) == 1 else None
    if not isinstance(identifier, str) or not re.fullmatch(
        r"[A-Za-z0-9_.@<>:-]{1,200}", identifier
    ):
        raise ValueError("workspace provider Message ID unavailable")
    return identifier


def email(runtime, name, persona, owner, recipient, message):
    import pwd

    tool = persona / "tools" / "workspace.py"
    if (
        hashlib.sha256(read_file(tool, owner)).hexdigest()
        != runtime["workspace_sha256"]
    ):
        raise ValueError("persona workspace tool differs from reviewed source")
    account = pwd.getpwuid(owner)
    options = (
        {"user": owner, "group": account.pw_gid, "extra_groups": []}
        if os.geteuid() == 0
        else {}
    )
    if os.geteuid() not in (0, owner):
        raise ValueError("existing persona execution identity required")
    substitutions = {
        "{recipient}": recipient,
        "{message}": message,
        "{subject}": "Organization policy operational alert",
    }
    args = [substitutions.get(arg, arg) for arg in runtime["workspace_send_args"]]
    result = subprocess.run(  # nosec B603 -- fixed system Python, pinned persona tool, no shell, existing UID
        ["/usr/bin/python3", str(tool), *args],
        cwd=persona,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": account.pw_dir,
            "LANG": "C.UTF-8",
            "PHANTOMBOT_PERSONA": name,
        },
        **options,
    )
    if result.returncode:
        raise ValueError("workspace send did not succeed")
    return parse_mail_receipt(result.stdout, runtime["workspace_receipt"]), None


def deliver(runtime, payload, explicit=None):
    validate_runtime(runtime)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "channel", "recipient", "message"}
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or payload["channel"] not in ("telegram", "email")
        or payload["recipient"]
        != runtime["telegram_chat" if payload["channel"] == "telegram" else "mail_to"]
        or not isinstance(payload["message"], str)
        or not 1 <= len(payload["message"]) <= 2048
        or any(c in payload["message"] for c in ("\n", "\r", "\x00"))
    ):
        raise ValueError("invalid bound notification payload")
    try:
        name, persona, owner = resolve(runtime, explicit)
    except (OSError, ValueError, KeyError, TypeError):
        raise PersonaResolutionError(
            "persona resolution failed; select --persona and verify its existing directory"
        ) from None
    attempt = uuid.uuid4().hex
    append_ledger(runtime["ledger_path"], record(name, payload, attempt, "attempting"))
    try:
        if payload["channel"] == "telegram":
            identifier, date = telegram(
                persona, owner, payload["recipient"], payload["message"]
            )
        else:
            identifier, date = email(
                runtime, name, persona, owner, payload["recipient"], payload["message"]
            )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        # A timeout can follow provider acceptance. Never auto-retry unknown sends.
        append_ledger(
            runtime["ledger_path"], record(name, payload, attempt, "failed-or-unknown")
        )
        raise ValueError("notification unavailable; inspect private ledger") from None
    append_ledger(
        runtime["ledger_path"],
        record(
            name,
            payload,
            attempt,
            "accepted",
            message_id=identifier,
            provider_date=date,
        ),
    )
    return {
        "delivered": True,
        "recipient": payload["recipient"],
        "receipt": "ledger:" + attempt,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--persona")
    args = parser.parse_args()
    if tomllib is None:
        parser.error("notify adapter requires Python 3.11 or newer")
    try:
        runtime = read_runtime_config(args.runtime_config)
        raw = sys.stdin.read(8193)
        if len(raw) > 8192:
            raise ValueError("oversized notification")
        print(json.dumps(deliver(runtime, json.loads(raw), args.persona)))
    except PersonaResolutionError:
        print(
            "persona resolution failed; select --persona and verify its existing directory",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        print(
            "notify adapter unavailable; inspect private configuration and ledger",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
