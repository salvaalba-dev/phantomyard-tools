"""Reconcile a trusted viewer candidate under the organization lock.

The caller must supply a builder which independently verifies the installed
accounts and derives routes from the supplied organization bytes. This module
does not install itself, create accounts, or authorize new documents.
"""

from phantomdocs.view_agent_recovery import (
    RecoveryRequired,
    _apply_locked,
    _complete_pending,
    _pending_or_stop,
    _stop_or_raise,
)


def reconcile_once(host, build):
    """Recover matching transactions and apply a verified candidate safely."""
    if not callable(build):
        raise TypeError("A trusted candidate builder is required")
    try:
        return _reconcile_locked(host, build)
    except RecoveryRequired:
        raise
    except Exception as exc:
        _stop_or_raise(host)
        raise RecoveryRequired("Reconciliation lock failed; viewer stopped") from exc


def _reconcile_locked(host, build):
    with host.lock():
        pending = _pending_or_stop(host)
        try:
            org_bytes, revision = host.authority()
            if pending is not None or not host.committed_revision_is(revision):
                host.stop()
            candidate = build(org_bytes)
            if not isinstance(candidate, bytes) or not candidate:
                raise ValueError("Invalid candidate")
            if not host.current_revision_is(revision):
                raise ValueError("Organization changed during reconciliation")
            if pending is not None:
                if pending != (candidate, revision):
                    raise ValueError("Pending transaction requires new review")
                _complete_pending(host, candidate, revision)
                return "recovered"
            if host.configuration_is_committed(candidate, revision) and host.healthy():
                return "unchanged"
            _apply_locked(host, candidate, revision)
            return "updated"
        except Exception as exc:
            _stop_or_raise(host)
            raise RecoveryRequired("Reconciliation failed; viewer stopped") from exc
