"""Reviewed publisher entry point; never discovers or changes host permissions."""

import argparse
import hashlib
import json
import re
import subprocess  # nosec B404 -- fixed systemctl executable, no shell
from datetime import datetime, timezone
from pathlib import PurePosixPath

from . import workflow_bridge_policy as publisher
from .workflow_admission_config import _read_protected, _unique
from .workflow_policy_environment import verify
from .workflow_policy_fanout import destinations
from .workflow_policy_watchdog import check

MODULE = "phantomdocs.workflow_policy_operations"
UNIT = r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(?:service|timer|path)"
SHA = r"[0-9a-f]{64}"
FIELDS = {
    "schema_version",
    "source",
    "destinations",
    "policy_lock",
    "resolver",
    "bridge_unit",
    "organization",
    "python",
    "runtime_seal",
    "runtime_seal_sha256",
    "inventory",
    "inventory_sha256",
}


def _path(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
        or any(x in ("", ".", "..") for x in value.split("/")[1:])
    ):
        raise ValueError("unsafe installation path")
    return value


def validate_config(value):
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("invalid publisher configuration")
    for name in (
        "source",
        "policy_lock",
        "resolver",
        "python",
        "runtime_seal",
        "inventory",
    ):
        _path(value[name])
    if not isinstance(value["destinations"], list):
        raise TypeError("ordered destinations required")
    for path in value["destinations"]:
        _path(path)
    destinations(value["source"], value["destinations"], value["policy_lock"])
    paths = [
        value[k]
        for k in (
            "source",
            "policy_lock",
            "resolver",
            "python",
            "runtime_seal",
            "inventory",
        )
    ]
    paths += value["destinations"]
    if len(set(paths)) != len(paths):
        raise ValueError("installation paths overlap")
    for name in ("runtime_seal_sha256", "inventory_sha256"):
        if not isinstance(value[name], str) or not re.fullmatch(SHA, value[name]):
            raise ValueError("reviewed artifact digest required")
    if not isinstance(value["organization"], str) or not re.fullmatch(
        r"[A-Za-z0-9_-]+", value["organization"]
    ):
        raise ValueError("invalid organization")
    if (
        not isinstance(value["bridge_unit"], str)
        or not re.fullmatch(UNIT, value["bridge_unit"])
        or not value["bridge_unit"].endswith(".service")
    ):
        raise ValueError("invalid bridge unit")
    if PurePosixPath(value["python"]).parts[-2:] != ("bin", "python"):
        raise ValueError("dedicated publisher interpreter required")
    return value


def _artifact(path, expected):
    raw = _read_protected(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("reviewed artifact changed")
    return json.loads(raw, object_pairs_hook=_unique)


def _systemctl(*args):
    result = subprocess.run(  # nosec B603 -- fixed executable, validated units, no shell
        ["/usr/bin/systemctl", "--no-pager", *args],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    return result.returncode, result.stdout.strip()


def validate_inventory(value, config, config_path, *, now=None):
    fields = {
        "schema_version",
        "owner",
        "expires_utc",
        "manual_source_writes",
        "external_writers_reviewed",
        "writers",
        "retired_units",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("invalid writer inventory")
    if (
        not isinstance(value["owner"], str)
        or not value["owner"].strip()
        or value["manual_source_writes"] != "prohibited"
        or value["external_writers_reviewed"] is not True
    ):
        raise ValueError("writer closure is not approved")
    expires = datetime.fromisoformat(value["expires_utc"].replace("Z", "+00:00"))
    if expires.tzinfo is None or expires <= (now or datetime.now(timezone.utc)):
        raise ValueError("writer review expired")
    writers = value["writers"]
    if not isinstance(writers, list) or not writers:
        raise ValueError("writer inventory is empty")
    roles, units = [], []
    prefix = [config["python"], "-m", MODULE, "--config", config_path]
    for writer in writers:
        if (
            not isinstance(writer, dict)
            or set(writer) != {"role", "owner", "unit", "unit_sha256", "command"}
            or not isinstance(writer["owner"], str)
            or not writer["owner"].strip()
            or not isinstance(writer["unit"], str)
            or not re.fullmatch(UNIT, writer["unit"])
            or not isinstance(writer["unit_sha256"], str)
            or not re.fullmatch(SHA, writer["unit_sha256"])
        ):
            raise ValueError("invalid writer entry")
        role, command = writer["role"], writer["command"]
        if role in ("publish", "reconcile", "prestart"):
            if not isinstance(command, list) or command != prefix + [role]:
                raise ValueError("writer bypasses the common publisher entry point")
        elif role == "collect":
            if (
                not isinstance(command, list)
                or not command
                or any(not isinstance(x, str) for x in command)
            ):
                raise ValueError("collector command required")
        else:
            raise ValueError("unrecognized policy writer")
        roles.append(role)
        units.append(writer["unit"])
    if set(roles) != {"publish", "reconcile", "prestart", "collect"} or len(
        units
    ) != len(set(units)):
        raise ValueError("all writer roles and distinct units must be reviewed")
    retired = value["retired_units"]
    if (
        not isinstance(retired, list)
        or len(set(retired)) != len(retired)
        or any(
            not isinstance(u, str) or not re.fullmatch(UNIT, u) or u in units
            for u in retired
        )
    ):
        raise ValueError("invalid retired writer units")
    return value


def check_inventory(value, config, config_path):
    validate_inventory(value, config, config_path)
    for writer in value["writers"]:
        code, definition = _systemctl("cat", writer["unit"])
        if (
            code
            or hashlib.sha256(definition.encode()).hexdigest() != writer["unit_sha256"]
        ):
            raise ValueError("effective writer unit differs from review")
    for unit in value["retired_units"]:
        code, state = _systemctl("show", unit, "--property=ActiveState", "--value")
        if code not in (0, 4) or state not in ("inactive", "failed"):
            raise ValueError("legacy writer has not stopped")
        code, enabled = _systemctl("is-enabled", unit)
        if enabled not in ("disabled", "masked", "not-found") or code not in (0, 1, 4):
            raise ValueError("legacy writer can still be triggered")


def load_ready(path):
    _path(path)
    config = validate_config(
        json.loads(_read_protected(path), object_pairs_hook=_unique)
    )
    if path in [config["source"], config["policy_lock"], *config["destinations"]]:
        raise ValueError("configuration overlaps policy")
    verify(
        _artifact(config["runtime_seal"], config["runtime_seal_sha256"]),
        config["python"],
    )
    check_inventory(
        _artifact(config["inventory"], config["inventory_sha256"]), config, path
    )
    return config


def execute(config, operation, **review):
    if operation == "check":
        if review:
            raise ValueError("watchdog is read-only")
        result = check(
            source=config["source"],
            destination=config["destinations"],
            lock_path=config["policy_lock"],
            require_committed=True,
        )
        if result["status"] != "ok":
            raise ValueError("policy drift or uncommitted source detected")
        return "ok"
    if operation not in ("publish", "reconcile", "prestart", "bootstrap"):
        raise ValueError("unknown publisher operation")
    if operation == "publish":
        if set(review) != {"candidate", "expected_source_sha256", "candidate_sha256"}:
            raise ValueError("reviewed candidate and both digests required")
    elif operation == "bootstrap":
        if set(review) != {"bootstrap_source_sha256"}:
            raise ValueError("explicit source review required for bootstrap")
    elif review:
        raise ValueError("review options do not apply to this operation")
    return publisher.refresh(
        source=config["source"],
        destination=config["destinations"],
        lock_path=config["policy_lock"],
        node="/usr/bin/node",
        resolver=config["resolver"],
        unit=config["bridge_unit"],
        organization=config["organization"],
        commit_witness=True,
        require_committed_source=True,
        prestart=operation == "prestart",
        **review,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "operation",
        choices=("publish", "reconcile", "prestart", "bootstrap", "check", "audit"),
    )
    parser.add_argument("--candidate")
    parser.add_argument("--expected-source-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--bootstrap-source-sha256")
    args = parser.parse_args()
    review = {
        k: v
        for k, v in vars(args).items()
        if k not in ("config", "operation") and v is not None
    }
    try:
        config = load_ready(args.config)
        if args.operation == "audit":
            if review:
                raise ValueError("audit is read-only")
            result = "writer-review-current"
        else:
            result = execute(config, args.operation, **review)
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        # Keep operational paths, policy bytes and journal contents out of alerts.
        print("publisher operation unavailable")
        raise SystemExit(2) from None
    print(result)


if __name__ == "__main__":
    main()
