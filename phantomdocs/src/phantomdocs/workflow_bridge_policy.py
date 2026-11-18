"""Refresh a bridge routing snapshot under the PhantomOrg policy lock."""

import argparse
import json
import os
import re
import subprocess  # nosec B404 -- fixed commands with validated arguments
from contextlib import nullcontext

from . import workflow_policy_fanout as fanout
from .workflow_admission_config import parse_policy
from .workflow_policy_guard import policy_guard
from .workflow_policy_sync import (
    MAX_BYTES,
    _identity,
    _synchronize_locked,
    policy_permissions,
)
from .workflow_protected_paths import open_protected_file, protected_parent


class BridgeRefreshError(RuntimeError):
    """The bridge could not be reconciled safely."""


def _read_policy(path):
    with protected_parent(path) as (directory, name):
        fd = open_protected_file(directory, name)
        try:
            before = os.fstat(fd)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_BYTES + 1)
            if (
                not data
                or len(data) > MAX_BYTES
                or _identity(os.fstat(fd)) != _identity(before)
                or _identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                != _identity(before)
            ):
                raise BridgeRefreshError("policy changed while reading")
            return data
        finally:
            os.close(fd)


_DERIVE = r"""
const m = require(process.argv[1]);
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
function derive(text) {
  const org = m.parseOrgYaml(text);
  m.validateOrgReferences(org);
  return {agents: m.deriveAgents(org), routing: m.deriveRouting(org),
          actorsByRole: m.actorsByRole(org)};
}
process.stdout.write(JSON.stringify(input.map(derive)));
"""


def _derive_both(source, destination, *, node, resolver):
    if node != "/usr/bin/node" or not os.path.isabs(resolver):
        raise BridgeRefreshError("invalid bridge resolver configuration")
    with protected_parent(resolver) as (directory, name):
        fd = open_protected_file(directory, name)
        os.close(fd)
    try:
        payload = json.dumps([source.decode("utf-8"), destination.decode("utf-8")])
        result = subprocess.run(  # nosec B603 -- fixed executable, protected resolver, no shell
            [node, "-e", _DERIVE, resolver],
            input=payload,
            text=True,
            capture_output=True,
            check=True,
            timeout=20,
        )
        values = json.loads(result.stdout)
    except (ValueError, subprocess.SubprocessError, OSError) as error:
        raise BridgeRefreshError("bridge policy validation failed") from error
    if not isinstance(values, list) or len(values) != 2:
        raise BridgeRefreshError("invalid bridge policy derivation")
    return values


def _systemctl(action, unit):
    if action not in {"is-active", "start", "stop"} or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service", unit
    ):
        raise BridgeRefreshError("invalid service operation")
    if action == "is-active":
        result = subprocess.run(  # nosec B603 -- fixed executable and validated unit
            ["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        state = result.stdout.strip()
        if result.returncode == 0 and state == "active":
            return True
        if result.returncode == 0 and state in ("inactive", "failed"):
            return False
        raise BridgeRefreshError("bridge service state is uncertain")
    result = subprocess.run(  # nosec B603 -- fixed executable and validated arguments
        ["/usr/bin/systemctl", action, unit],
        capture_output=True,
        timeout=45,
        check=False,
    )
    if result.returncode:
        raise BridgeRefreshError("bridge service operation failed: " + action)
    return True


def refresh(*, source, destination, lock_path, node, resolver, unit, prestart=False):
    """Publish all snapshots under one policy lock; retry only our own journal.

    A separate pre-existing publisher lock serializes service orchestration.
    Prestart skips that outer lock to avoid a systemd dependency deadlock; it
    still holds the common policy lock for every destination and verification.
    """
    paths = fanout.destinations(source, destination, lock_path)
    serial = (
        nullcontext()
        if prestart
        else policy_guard(lock_path + ".publisher", exclusive=True)
    )
    with serial:
        active = False
        stopped = False
        published = False
        try:
            active = False if prestart else _systemctl("is-active", unit)
            # Recovery is confined to the strictly validated fanout record.
            # A marker from manual source publication is never adopted here.
            with policy_guard(lock_path, exclusive=True, recovering=True):
                record = fanout.read_pending(lock_path)
                inherited = record is not None
                fanout.ensure_independent(
                    [source, lock_path, lock_path + ".publisher", *paths]
                )
                before = _read_policy(source)
                parse_policy(before)
                old = [_read_policy(path) for path in paths]
                current, previous = _derive_both(
                    before, before if prestart else old[0], node=node, resolver=resolver
                )
                changed = current != previous
                if record is None:
                    if all(data == before for data in old):
                        return "synchronized"
                    record = fanout.make_record(
                        source=source,
                        paths=paths,
                        payload=before,
                        old=old,
                        unit=unit,
                        resolver=resolver,
                        node=node,
                        active=active,
                        changed=changed,
                    )
                    fanout.create_pending(lock_path, record)
                fanout.verify_record(
                    record,
                    source=source,
                    paths=paths,
                    payload=before,
                    old=old,
                    unit=unit,
                    resolver=resolver,
                    node=node,
                )
                if record["restart"] and active and not prestart:
                    _systemctl("stop", unit)
                    stopped = True
                for path, data, entry in zip(
                    paths, old, record["destinations"], strict=True
                ):
                    if data != before:
                        _synchronize_locked(
                            source,
                            path,
                            expected_source=before,
                            expected_destination=data,
                            expected_permissions=entry["permissions"],
                        )
                _verify_copies(source, paths, before, record)
                restart = (
                    not prestart
                    and record["resume"]
                    and (record["restart"] or not active)
                )
                if not restart:
                    # A nested bridge ExecStartPre must not erase the outer
                    # publisher's restart intent before systemctl start returns.
                    if not (prestart and inherited):
                        published = True
                        fanout.clear_pending(lock_path, record)
                    return "synchronized"
            # Never start a unit while holding the lock its ExecStartPre needs.
            # Keep pending durable until start succeeds; a failed/killed start
            # can therefore be retried even though the bridge is now inactive.
            stopped = False
            _systemctl("start", unit)
            with policy_guard(lock_path, exclusive=True, recovering=True):
                _verify_copies(source, paths, before, record)
                published = True
                fanout.clear_pending(lock_path, record)
            return "restarted"
        except Exception:
            if not prestart and not stopped and not published:
                _systemctl("stop", unit)
            raise


def _verify_copies(source, paths, payload, record):
    if _read_policy(source) != payload:
        raise BridgeRefreshError("policy source changed during refresh")
    for path, entry in zip(paths, record["destinations"], strict=True):
        if (
            _read_policy(path) != payload
            or policy_permissions(path) != entry["permissions"]
        ):
            raise BridgeRefreshError("policy destination changed during refresh")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument(
        "--destination",
        required=True,
        action="append",
        help="Repeat for every destination; the first is the bridge snapshot",
    )
    parser.add_argument("--policy-lock", required=True)
    parser.add_argument("--resolver", required=True)
    parser.add_argument("--node", default="/usr/bin/node")
    parser.add_argument("--unit", required=True)
    parser.add_argument("--prestart", action="store_true")
    args = parser.parse_args()
    print(
        refresh(
            source=args.source,
            destination=args.destination,
            lock_path=args.policy_lock,
            node=args.node,
            resolver=args.resolver,
            unit=args.unit,
            prestart=args.prestart,
        )
    )


if __name__ == "__main__":
    main()
