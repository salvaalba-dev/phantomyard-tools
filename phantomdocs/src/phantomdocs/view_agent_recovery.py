"""Fail-closed route transaction logic for a host-specific supervisor.

The host adapter must provide a durable journal, atomic file replacement,
exclusive locking, a startup guard and an authority lock. This module is not
an installer and cannot by itself make those guarantees.
"""


class RecoveryRequired(RuntimeError):
    """The viewer is stopped and the pending transaction needs recovery."""


def apply_route_change(host, candidate, authority_revision):
    """Install a validated candidate while holding the host's authority lock.

    A previous configuration is never restarted after a failed change: it may
    contain an access grant that the current organization has revoked.
    """
    if not isinstance(candidate, bytes) or not candidate:
        raise ValueError("A nonempty candidate is required")
    if not isinstance(authority_revision, str) or not authority_revision:
        raise ValueError("An authority revision is required")
    with host.lock():
        _apply_locked(host, candidate, authority_revision)


def _apply_locked(host, candidate, authority_revision):
    if _pending_or_stop(host):
        _stop_or_raise(host)
        raise RecoveryRequired("A previous transaction requires recovery")
    try:
        current = host.current_revision_is(authority_revision)
    except Exception as exc:
        _stop_or_raise(host)
        raise RecoveryRequired("Organization unavailable; viewer stopped") from exc
    if not current:
        _stop_or_raise(host)
        raise RecoveryRequired("Organization revision changed; viewer stopped")
    try:
        # Stop before writing the journal: old routes may have been revoked.
        host.stop()
        host.validate(candidate)
        host.write_journal(candidate, authority_revision)
    except Exception as exc:
        _stop_or_raise(host)
        raise RecoveryRequired("Journal failed; viewer stopped") from exc
    _complete_pending(host, candidate, authority_revision)


def recover_route_change(host):
    """Retry a journaled candidate, or keep the viewer stopped if stale."""
    with host.lock():
        pending = _pending_or_stop(host)
        if pending is None:
            return False
        candidate, revision = pending
        _complete_pending(host, candidate, revision)
        return True


def _complete_pending(host, candidate, revision):
    try:
        host.stop()
        if not host.current_revision_is(revision):
            raise ValueError("Organization revision changed")
        host.validate(candidate)
        host.replace(candidate)
        if not host.current_revision_is(revision):
            raise ValueError("Organization revision changed")
        host.start()
        if not host.healthy() or not host.current_revision_is(revision):
            raise ValueError("Viewer failed its health or authority check")
        # Persist the authority binding before removing the recovery record.
        # The host must atomically replace and fsync this record.
        host.write_committed(candidate, revision)
        host.clear_journal()
    except Exception as exc:
        _stop_or_raise(host)
        raise RecoveryRequired("Viewer stopped; transaction requires recovery") from exc


def _stop_or_raise(host):
    try:
        host.stop()
    except Exception as exc:
        raise RecoveryRequired(
            "Viewer stop failed; manual intervention required"
        ) from exc


def _pending_or_stop(host):
    try:
        return host.pending()
    except Exception as exc:
        _stop_or_raise(host)
        raise RecoveryRequired("Journal unreadable; viewer stopped") from exc
