"""Fail-closed startup checks for a trusted, agent-scoped viewer configuration.

This function is not a systemd hook. Its caller must read root-controlled
files while holding the same organization lock used by policy publishers.
"""

import argparse
import hashlib
import json

from phantomdocs.access import validate_org_schema
from phantomdocs.view_agent_directory import has_declared_channel
from phantomdocs.view_agent_journal import read_journal
from phantomdocs.workflow_admission_config import _read_protected, _unique, parse_policy
from phantomdocs.workflow_policy_guard import policy_guard


def check_startup(org, config, config_bytes, revision, *, committed, pending=None):
    """Reject stale routes and incomplete recovery before starting a viewer."""
    validate_org_schema(org)
    if not isinstance(config, dict) or not isinstance(config_bytes, bytes):
        raise TypeError("Trusted viewer configuration required")
    organization = org.get("organization")
    if (
        not isinstance(organization, dict)
        or not isinstance(organization.get("id"), str)
        or not organization["id"]
        or config.get("organization") != organization["id"]
    ):
        raise ValueError("Viewer belongs to a different organization")
    if not isinstance(revision, str) or not revision:
        raise ValueError("Trusted organization revision required")
    if pending is not None:
        if pending != (config_bytes, revision):
            raise ValueError("Viewer recovery must complete before startup")
    elif committed != (config_bytes, revision):
        raise ValueError("Viewer configuration is not bound to current authority")
    raw_actors = org.get("actors")
    configured = config.get("agent_actors")
    additional = config.get("additional_issuers", [])
    if (
        not isinstance(raw_actors, list)
        or not isinstance(configured, list)
        or not isinstance(additional, list)
    ):
        raise TypeError("Invalid organization or route configuration")
    actors = {}
    for actor in raw_actors:
        if (
            not isinstance(actor, dict)
            or not isinstance(actor.get("id"), str)
            or actor["id"] in actors
        ):
            raise ValueError("Invalid or duplicate organization actor")
        actors[actor["id"]] = actor
    if any(not isinstance(actor, str) or not actor for actor in configured) or len(
        set(configured)
    ) != len(configured):
        raise ValueError("Invalid configured agent actors")
    routes = [config.get("actor")]
    for issuer in additional:
        if not isinstance(issuer, dict):
            raise TypeError("Invalid issuer route")
        routes.append(issuer.get("actor"))
    if any(not isinstance(actor, str) or not actor for actor in routes) or len(
        set(routes)
    ) != len(routes):
        raise ValueError("Invalid or duplicate issuer routes")
    for actor in configured:
        if actor not in routes or not has_declared_channel(actors.get(actor)):
            raise ValueError("Agent route is no longer authorized")


def check_protected_startup(
    *, org_path, config_path, journal_path, committed_path, policy_lock
):
    """Check protected files under the cooperating shared policy lock.

    A caller must keep authority stable through actual startup and runtime;
    completing this check alone does not provide that guarantee.
    """
    with policy_guard(policy_lock, exclusive=False):
        _check_locked(org_path, config_path, journal_path, committed_path)


def _check_locked(org_path, config_path, journal_path, committed_path):
    org_bytes = _read_protected(org_path)
    config_bytes = _read_protected(config_path)
    config = json.loads(config_bytes, object_pairs_hook=_unique)
    check_startup(
        parse_policy(org_bytes),
        config,
        config_bytes,
        hashlib.sha256(org_bytes).hexdigest(),
        committed=read_journal(committed_path),
        pending=read_journal(journal_path),
    )


def launch_protected(
    *, org_path, config_path, journal_path, committed_path, policy_lock, start_and_wait
):
    """Hold the shared policy lock until the launcher's bounded readiness check.

    The host must kill the child on readiness failure, and the reader must
    recheck live policy for every request once the lock is released.
    """
    if not callable(start_and_wait):
        raise TypeError("Trusted launcher required")
    with policy_guard(policy_lock, exclusive=False):
        _check_locked(org_path, config_path, journal_path, committed_path)
        return start_and_wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--committed", required=True)
    parser.add_argument("--policy-lock", required=True)
    args = parser.parse_args()
    try:
        check_protected_startup(
            org_path=args.org,
            config_path=args.config,
            journal_path=args.journal,
            committed_path=args.committed,
            policy_lock=args.policy_lock,
        )
    except (OSError, ValueError, TypeError, RecursionError):
        parser.exit(1, "Viewer startup check failed\n")


if __name__ == "__main__":
    main()
