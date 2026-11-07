"""Refresh a bridge routing snapshot under the PhantomOrg policy lock."""

import argparse
import json
import os
import re
import subprocess  # nosec B404 -- fixed commands with validated arguments

from .workflow_admission_config import parse_policy
from .workflow_policy_guard import policy_guard
from .workflow_policy_sync import MAX_BYTES, _identity, _synchronize_locked
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
    """Sync snapshot and restart for effective changes; watcher is eventual.

    The service must start from this protected snapshot and no other writer may
    alter it. Root edits can bypass the lock and cannot be made atomic here.
    """
    try:
        was_active = False if prestart else _systemctl("is-active", unit)
    except Exception:
        if not prestart:
            _systemctl("stop", unit)
        raise
    stopped = False
    try:
        with policy_guard(lock_path, exclusive=True):
            if os.path.lexists(lock_path + ".pending"):
                raise BridgeRefreshError("policy publication requires recovery")
            before = _read_policy(source)
            parse_policy(before)
            old = _read_policy(destination)
            current, previous = _derive_both(
                before, before if prestart else old, node=node, resolver=resolver
            )
            changed = current != previous
            if changed and was_active:
                _systemctl("stop", unit)
                stopped = True
            if before != old:
                _synchronize_locked(
                    source,
                    destination,
                    expected_source=before,
                    expected_destination=old,
                )
            if _read_policy(source) != before or _read_policy(destination) != before:
                raise BridgeRefreshError("policy changed during refresh")
    except Exception:
        if was_active and not stopped:
            _systemctl("stop", unit)
        raise
    if stopped:
        _systemctl("start", unit)
    return "restarted" if stopped else "synchronized"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
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
