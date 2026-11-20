"""Standalone direct-recipient Telegram plus archival email routing.

Existing transport wrappers must acknowledge the exact recipient and provider
receipt. Generic phantombot notify broadcast output is deliberately insufficient.
"""

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404 -- fixed protected wrappers, JSON stdin, no shell
from datetime import datetime, timezone
from pathlib import PurePosixPath

if __package__:
    from .workflow_policy_alert import delivery_environment, protected_handler
else:
    from workflow_policy_alert import delivery_environment, protected_handler


def validate(config):
    fields = {
        "schema_version",
        "host",
        "telegram_chat",
        "mail_to",
        "telegram_handler",
        "mail_handler",
    }
    if (
        not isinstance(config, dict)
        or set(config) != fields
        or type(config["schema_version"]) is not int
        or config["schema_version"] != 1
    ):
        raise ValueError("invalid alert routing configuration")
    for key, pattern in (
        ("host", r"[A-Za-z0-9_.-]{1,253}"),
        ("telegram_chat", r"[1-9][0-9]{0,19}"),
        ("mail_to", r"[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}"),
    ):
        if not isinstance(config[key], str) or not re.fullmatch(pattern, config[key]):
            raise ValueError("invalid direct alert destination")
    # Positive Telegram IDs only: group delivery is not an implicit fallback.
    for key in ("telegram_handler", "mail_handler"):
        value = config[key]
        if (
            not isinstance(value, str)
            or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
            or any(p in ("", ".", "..") for p in value.split("/")[1:])
        ):
            raise ValueError("invalid existing transport wrapper")
    return config


def read_config(path):
    if (
        not isinstance(path, str)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
        or any(p in ("", ".", "..") for p in path.split("/")[1:])
    ):
        raise ValueError("invalid private routing path")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for component in PurePosixPath(path).parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("unprotected routing parent")
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unprotected routing parent")
        fd = os.open(
            PurePosixPath(path).name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o022
                or info.st_nlink != 1
            ):
                raise ValueError("unprotected routing file")
            raw = os.read(fd, 8193)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    if len(raw) > 8192:
        raise ValueError("oversized routing file")
    return validate(json.loads(raw))


def _deliver(handler, payload):
    protected_handler(handler)
    result = subprocess.run(  # nosec B603 -- protected wrapper, fixed argv, validated JSON only
        [handler],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=6,
        check=False,
        env=delivery_environment(),
    )
    if result.returncode or len(result.stdout) > 4096:
        raise ValueError("transport delivery unavailable")
    ack = json.loads(result.stdout)
    if (
        not isinstance(ack, dict)
        or set(ack) != {"delivered", "recipient", "receipt"}
        or ack["delivered"] is not True
        or ack["recipient"] != payload["recipient"]
        or not isinstance(ack["receipt"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", ack["receipt"])
    ):
        raise ValueError("exact recipient delivery was not acknowledged")
    return ack["receipt"]


def route(config, event, *, state, now=None):
    validate(config)
    if (
        not isinstance(event, dict)
        or set(event) != {"schema_version", "kind", "unit"}
        or type(event["schema_version"]) is not int
        or event["schema_version"] != 1
        or event["kind"] not in ("policy-unit-failed", "policy-alert-probe")
        or not isinstance(event["unit"], str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(service|timer|path)", event["unit"]
        )
        or not isinstance(state, str)
        or not re.fullmatch(r"[a-z0-9-]{1,48}", state)
    ):
        raise ValueError("invalid policy alert event")
    stamp = (
        (now or datetime.now(timezone.utc))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    message = f"unit={event['unit']} host={config['host']} state={state} time={stamp}"
    receipts, failed = [], []
    # Email is attempted for every incident, even after Telegram succeeds/fails.
    for channel, key in (("telegram", "telegram_chat"), ("email", "mail_to")):
        try:
            receipt = _deliver(
                config["telegram_handler" if channel == "telegram" else "mail_handler"],
                {
                    "schema_version": 1,
                    "channel": channel,
                    "recipient": config[key],
                    "message": message,
                },
            )
            receipts.append(receipt)
        except (OSError, ValueError, subprocess.SubprocessError):
            failed.append(channel)
    if failed:
        # An email may have landed after Telegram failed. Keep the unit failed
        # rather than hiding degraded delivery behind an aggregate exit code.
        raise ValueError("required alert route unavailable: " + ",".join(failed))
    import hashlib

    return {
        "delivered": True,
        "receipt": "routes:"
        + hashlib.sha256(json.dumps(receipts).encode()).hexdigest(),
    }


def unit_result(unit):
    try:
        result = subprocess.run(  # nosec B603 -- fixed executable, unit validated by the caller
            ["/usr/bin/systemctl", "show", unit, "--property=Result", "--value"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    state = result.stdout.strip() if result.returncode == 0 else ""
    return state if re.fullmatch(r"[a-z0-9-]{1,48}", state) else "unknown"


def main():
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        config = read_config(args.config)
        raw = sys.stdin.read(8193)
        if len(raw) > 8192:
            raise ValueError("oversized event")
        event = json.loads(raw)
        unit = event.get("unit") if isinstance(event, dict) else None
        if not isinstance(unit, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(service|timer|path)", unit
        ):
            raise ValueError("invalid unit")
        state = "probe"
        if event.get("kind") != "policy-alert-probe":
            state = unit_result(unit)
        print(json.dumps(route(config, event, state=state)))
    except (OSError, ValueError, subprocess.SubprocessError):
        print("alert routing unavailable", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
