"""Refresh a bridge routing snapshot under the PhantomOrg policy lock."""

import argparse
import json
import os
import re
import subprocess  # nosec B404 -- fixed commands with validated arguments
from contextlib import nullcontext

from . import workflow_phantomorg_candidate as source_publication
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


def refresh(
    *,
    source,
    destination,
    lock_path,
    node,
    resolver,
    unit,
    prestart=False,
    candidate=None,
    expected_source_sha256=None,
    candidate_sha256=None,
    organization=None,
):
    """Publish all snapshots under one policy lock; retry only our own journal.

    A separate pre-existing publisher lock serializes service orchestration.
    Prestart skips that outer lock to avoid a systemd dependency deadlock; it
    still holds the common policy lock for every destination and verification.
    """
    source_publication.review_options(
        candidate, expected_source_sha256, candidate_sha256, organization, prestart
    )
    paths = fanout.destinations(source, destination, lock_path)
    if candidate is not None:
        fanout.destinations(source, [candidate], lock_path)
        if candidate in paths:
            raise ValueError("candidate must be independent of every destination")
    serial = (
        nullcontext()
        if prestart
        else policy_guard(lock_path + ".publisher", exclusive=True)
    )
    with serial:
        active = False
        stopped = False
        published = False
        reject_candidate = False
        try:
            active = False if prestart else _systemctl("is-active", unit)
            # Recovery is confined to the strictly validated fanout record.
            # A marker from the legacy two-file publisher is never adopted here.
            with policy_guard(lock_path, exclusive=True, recovering=True):
                record = fanout.read_pending(lock_path)
                inherited = record is not None
                reject_candidate = candidate is not None and not inherited
                identities = [source, lock_path, lock_path + ".publisher", *paths]
                if candidate is not None and not inherited:
                    identities.append(candidate)
                fanout.ensure_independent(identities)
                before = _read_policy(source)
                parse_policy(before)
                old = [_read_policy(path) for path in paths]
                settings = {
                    "source": source,
                    "paths": paths,
                    "unit": unit,
                    "resolver": resolver,
                    "node": node,
                }
                source_record = (
                    inherited and record.get("kind") == source_publication.KIND
                )
                if source_record:
                    target = source_publication.recover_payload(
                        record,
                        before=before,
                        old=old,
                        organization=organization,
                        **settings,
                    )
                    if candidate is not None and (
                        candidate_sha256 != record["source_sha256"]
                        or expected_source_sha256 != record["source_before_sha256"]
                    ):
                        raise ValueError(
                            "review does not match pending source publication"
                        )
                elif candidate is not None:
                    if inherited:
                        raise ValueError("another policy publication is pending")
                    target = _read_policy(candidate)
                    if fanout.digest(target) != candidate_sha256:
                        raise ValueError("candidate differs from reviewed bytes")
                    source_publication.validate(target, organization)
                    source_publication.source_identity(before, organization)
                    if (
                        fanout.digest(before) != expected_source_sha256
                        and before != target
                    ):
                        raise ValueError("reviewed source revision is stale")
                else:
                    target = before
                    if organization is not None:
                        source_publication.source_identity(before, organization)
                current, previous = _derive_both(
                    target, target if prestart else old[0], node=node, resolver=resolver
                )
                changed = current != previous
                if record is None:
                    if before == target and all(data == target for data in old):
                        return "synchronized"
                    if candidate is not None:
                        record = source_publication.make_record(
                            payload=target,
                            before=before,
                            old=old,
                            organization=organization,
                            active=active,
                            changed=changed,
                            **settings,
                        )
                    else:
                        record = fanout.make_record(
                            payload=target,
                            old=old,
                            active=active,
                            changed=changed,
                            **settings,
                        )
                    fanout.create_pending(lock_path, record)
                    reject_candidate = False
                source_record = record.get("kind") == source_publication.KIND
                if source_record:
                    source_publication.recover_payload(
                        record,
                        before=before,
                        old=old,
                        organization=organization,
                        **settings,
                    )
                else:
                    fanout.verify_record(record, payload=target, old=old, **settings)
                if record["restart"] and active and not prestart:
                    _systemctl("stop", unit)
                    stopped = True
                if source_record:
                    with source_publication.payload_file(lock_path, target) as staged:
                        if before != target:
                            _synchronize_locked(
                                staged,
                                source,
                                expected_source=target,
                                expected_destination=before,
                                expected_permissions=record["source_permissions"],
                            )
                        _copy_destinations(staged, paths, old, target, record)
                else:
                    _copy_destinations(source, paths, old, target, record)
                _verify_copies(source, paths, target, record)
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
                _verify_copies(source, paths, target, record)
                published = True
                fanout.clear_pending(lock_path, record)
            return "restarted"
        except Exception:
            if not prestart and not stopped and not published and not reject_candidate:
                _systemctl("stop", unit)
            raise


def _copy_destinations(source, paths, old, payload, record):
    for path, data, entry in zip(paths, old, record["destinations"], strict=True):
        if data != payload:
            _synchronize_locked(
                source,
                path,
                expected_source=payload,
                expected_destination=data,
                expected_permissions=entry["permissions"],
            )


def _verify_copies(source, paths, payload, record):
    if _read_policy(source) != payload:
        raise BridgeRefreshError("policy source changed during refresh")
    if (
        record.get("kind") == source_publication.KIND
        and policy_permissions(source) != record["source_permissions"]
    ):
        raise BridgeRefreshError("source permissions changed during publication")
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
    parser.add_argument("--candidate")
    parser.add_argument("--expected-source-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--organization")
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
            candidate=args.candidate,
            expected_source_sha256=args.expected_source_sha256,
            candidate_sha256=args.candidate_sha256,
            organization=args.organization,
        )
    )


if __name__ == "__main__":
    main()
