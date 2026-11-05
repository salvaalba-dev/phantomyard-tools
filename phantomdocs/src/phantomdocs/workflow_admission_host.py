"""Experimental wiring for a supervised local admission host.

This does not create a daemon, configure the OS, authorize a remote human,
execute jobs, move files, or register documents. Every argument must originate
from protected deployment configuration, never from a connected peer.
"""

from contextlib import contextmanager
from copy import deepcopy

from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_local_peer_service import serve_one
from phantomdocs.workflows import load_registry, plan, validate_contract


def serve_admission_once(
    listener,
    *,
    identity_map,
    ledger_path,
    policy_lock,
    load_org,
    load_installation,
    processor,
):
    """Admit one kernel-identified peer using fresh policy and private ledger.

    The deployment must protect the socket, ledger, identity map, policy,
    installation and configuration, and all policy writers must cooperate
    on the same lock. This function does not enforce those external conditions.
    No archive context is supplied; archive requests are always rejected.
    """
    if (
        not isinstance(processor, tuple)
        or len(processor) != 2
        or not all(isinstance(part, str) and part for part in processor)
    ):
        raise ValueError("trusted processor descriptor is required")

    @contextmanager
    def context_factory(org):
        installation = deepcopy(load_installation())
        validate_contract(installation, "installation")
        registry = load_registry()

        def make_plan(job):
            # accept_local independently binds this requester to SO_PEERCRED.
            return plan(job, installation, org, registry, processor, job["requester"])

        with WorkflowLedger(ledger_path) as ledger:
            yield {
                "identity_map": identity_map,
                "ledger": ledger,
                "org": org,
                "make_plan": make_plan,
            }

    return serve_one(
        listener, context_factory, policy_lock=policy_lock, load_org=load_org
    )
