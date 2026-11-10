"""Hold the current organization and native catalog during matrix delivery."""

from contextlib import contextmanager

from .manifest import load, manifest_lock
from .workflow_admission_config import _read_protected, parse_policy
from .workflow_policy_guard import policy_guard


@contextmanager
def guarded_matrix_authority(*, policy_lock, org_path, native_manifest, reader):
    """Yield current policy and catalog; ``reader`` is a trusted actor-bound adapter.

    The caller must authenticate and bind the actor before invoking this
    context, protect configuration and bound the reader and response I/O.
    """
    if not callable(reader):
        raise TypeError("trusted matrix reader required")
    with policy_guard(policy_lock, exclusive=False):
        org = parse_policy(_read_protected(org_path))
        with manifest_lock(native_manifest):
            yield org, load(native_manifest), reader
