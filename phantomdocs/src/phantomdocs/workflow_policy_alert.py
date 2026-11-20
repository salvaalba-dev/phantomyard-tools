"""Standalone stdlib alert adapter; require delivery acknowledgement, not logging.

Copy this reviewed file to the separate alert runtime during an approved install.
It deliberately has no publisher/package imports, so a broken publisher venv
does not prevent OnFailure from attempting delivery through the existing route.
"""

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404 -- protected operator-selected executable, no shell
from pathlib import PurePosixPath


def protected_handler(path):
    if (
        not isinstance(path, str)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", path)
        or any(p in ("", ".", "..") for p in path.split("/")[1:])
    ):
        raise ValueError("invalid alert handler")
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for component in PurePosixPath(path).parts[1:-1]:
            info = os.fstat(directory)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("unprotected alert handler parent")
            child = os.open(component, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unprotected alert handler parent")
        info = os.stat(
            PurePosixPath(path).name, dir_fd=directory, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_nlink != 1
            or not info.st_mode & stat.S_IXUSR
        ):
            raise ValueError("unprotected or non-executable alert handler")
    finally:
        os.close(directory)


def delivery_environment():
    value = os.environ.get("PHANTOMBOT_PERSONA")
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    if value is not None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
            raise ValueError("invalid persona routing environment")
        environment["PHANTOMBOT_PERSONA"] = value
    return environment


def notify(handler, unit, *, probe=False):
    if not isinstance(unit, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(service|timer|path)", unit
    ):
        raise ValueError("invalid failed unit")
    protected_handler(handler)
    event = {
        "schema_version": 1,
        "kind": "policy-alert-probe" if probe else "policy-unit-failed",
        "unit": unit,
    }
    result = subprocess.run(  # nosec B603 -- root-protected fixed handler, JSON input, no shell
        [handler],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
        env=delivery_environment(),
    )
    if result.returncode or len(result.stdout) > 4096:
        raise ValueError("alert delivery failed")
    ack = json.loads(result.stdout)
    if (
        not isinstance(ack, dict)
        or set(ack) != {"delivered", "receipt"}
        or ack["delivered"] is not True
        or not isinstance(ack["receipt"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", ack["receipt"])
    ):
        raise ValueError("alert delivery was not acknowledged")
    return ack["receipt"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--handler", required=True)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--probe", action="store_true")
    args = parser.parse_args()
    try:
        notify(args.handler, args.unit, probe=args.probe)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("alert delivery unavailable")
        raise SystemExit(2) from None
    print("alert delivery acknowledged")


if __name__ == "__main__":
    main()
