"""Experimental wiring for a supervised local admission and search host.

This does not create a daemon, configure the OS, authorize a remote human,
execute jobs, move files, or register documents. Every argument must originate
from protected deployment configuration, never from a connected peer.
"""

from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

from phantomdocs.manifest import load, manifest_lock
from phantomdocs.workflow_ledger import WorkflowLedger
from phantomdocs.workflow_local_peer_service import serve_one
from phantomdocs.workflow_peer_audit import load_audit_file
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
    search_store_path=None,
):
    """Serve one kernel-identified peer using fresh policy and private ledger.

    The deployment must protect the socket, ledger, identity map, policy,
    installation and configuration, and all policy writers must cooperate
    on the same lock. This function does not enforce those external conditions.
    No archive context is supplied; archive requests are always rejected.
    """
    if processor is not None and (
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
            context = {
                "identity_map": identity_map,
                "ledger": ledger,
                "org": org,
                "make_plan": make_plan,
            }
            if search_store_path is not None:
                context["load_search_manifest"] = lambda: load(
                    str(Path(search_store_path) / "manifest.yaml")
                )
                context["search_guard"] = lambda: manifest_lock(
                    str(Path(search_store_path) / "manifest.yaml")
                )
                context["load_audit"] = lambda: load_audit_file(
                    str(Path(search_store_path) / "audit.log")
                )
            yield context

    return serve_one(
        listener, context_factory, policy_lock=policy_lock, load_org=load_org
    )
