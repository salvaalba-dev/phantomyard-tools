"""Fail closed before releasing a mixed-source review snapshot to an agent."""

from contextlib import contextmanager

from .access import can_read, policy_hash
from .manifest import load, manifest_lock
from .workflow_admission_config import _json, _read_protected, parse_policy
from .workflow_audit_native_acl import authorize_observations
from .workflow_local_identity import resolve_local_actor, resolve_peer_actor
from .workflow_policy_guard import policy_guard
from .workflows import WorkflowError


def bind_authority(
    evidence, org, actor, categories, matrix_category, *, inherited_category=None
):
    """Require trusted classifications for the matrix and every observed item.

    The matrix may itself mention every item, so omitting denied items from the
    inventory alone would not prevent disclosure through the matrix body.
    """
    if not isinstance(categories, dict) or not isinstance(actor, str) or not actor:
        raise WorkflowError("trusted actor and classification map required")
    items = evidence.get("items")
    if not isinstance(items, list) or not isinstance(matrix_category, str):
        raise WorkflowError("classified review evidence required")
    item_ids = {item.get("id") for item in items if isinstance(item, dict)}
    if len(item_ids) != len(items) or not set(categories) <= item_ids:
        raise WorkflowError("classification map contains an unknown item")
    if inherited_category is None and set(categories) != item_ids:
        raise WorkflowError("every observed item needs one trusted classification")
    if inherited_category is not None and not isinstance(inherited_category, str):
        raise WorkflowError("invalid inherited project category")
    if not can_read(org, actor, matrix_category) or (
        inherited_category is not None and not can_read(org, actor, inherited_category)
    ):
        raise WorkflowError("review evidence is not fully authorized")
    for value in categories.values():
        restrictions = value if isinstance(value, list) else [value]
        if not restrictions or any(
            not isinstance(category, str) or not can_read(org, actor, category)
            for category in restrictions
        ):
            raise WorkflowError("review evidence is not fully authorized")
    return {
        **evidence,
        "authority": {
            "actor": actor,
            "policy_hash": policy_hash(org),
            "matrix_category": matrix_category,
            "categories": dict(categories),
            "inherited_category": inherited_category,
        },
    }


def recheck_authority(evidence, org, actor):
    authority = evidence.get("authority") if isinstance(evidence, dict) else None
    if not isinstance(authority, dict) or authority.get("actor") != actor:
        raise WorkflowError("review authority does not match agent")
    if authority.get("policy_hash") != policy_hash(org):
        raise WorkflowError("review authority has changed")
    bind_authority(
        evidence,
        org,
        actor,
        authority.get("categories"),
        authority.get("matrix_category"),
        inherited_category=authority.get("inherited_category"),
    )


@contextmanager
def guarded_authorizer(config_path):
    """Hold the cooperating PhantomOrg policy lock until delivery finishes.

    Both the identity map and classification manifest must be root-controlled.
    A caller cannot choose the actor or supply its own labels.
    """
    config = _json(config_path)
    fields = {"version", "identity_map", "policy_lock", "org_path", "classifications"}
    if (
        not isinstance(config, dict)
        or set(config) != fields
        or type(config["version"]) is not int
        or config["version"] != 1
    ):
        raise WorkflowError("invalid review authorization configuration")
    with policy_guard(config["policy_lock"], exclusive=False):
        actor = resolve_local_actor(config["identity_map"])
        org = parse_policy(_read_protected(config["org_path"]))
        manifest = _json(config["classifications"])
        expected = {"version", "root_ref", "matrix_ref", "matrix_category", "items"}
        if (
            not isinstance(manifest, dict)
            or set(manifest) != expected
            or type(manifest["version"]) is not int
            or manifest["version"] != 1
        ):
            raise WorkflowError("invalid protected classification manifest")

        def authorize(evidence):
            if (
                evidence.get("root_ref") != manifest["root_ref"]
                or evidence.get("matrix_ref") != manifest["matrix_ref"]
            ):
                raise WorkflowError(
                    "review source does not match protected classification"
                )
            bind_authority(
                evidence, org, actor, manifest["items"], manifest["matrix_category"]
            )

        yield authorize


@contextmanager
def guarded_peer_authorizer(config_path, connection):
    """Bind a local peer and project to the locked current policy and catalog.

    The supervised host must protect the socket, bound request/response time,
    and keep this context open until delivery. The project binding is an
    administrator-reviewed, root-owned configuration, never peer input.
    """
    config = _json(config_path)
    fields = {
        "version",
        "identity_map",
        "policy_lock",
        "org_path",
        "native_manifest",
        "root_ref",
        "matrix_ref",
        "project_category",
    }
    if (
        not isinstance(config, dict)
        or set(config) != fields
        or type(config["version"]) is not int
        or config["version"] != 1
        or any(
            not isinstance(config[k], str) or not config[k]
            for k in fields - {"version"}
        )
    ):
        raise WorkflowError("invalid review peer configuration")
    actor = resolve_peer_actor(config["identity_map"], connection)
    with policy_guard(config["policy_lock"], exclusive=False):
        org = parse_policy(_read_protected(config["org_path"]))
        with manifest_lock(config["native_manifest"]):
            manifest = load(config["native_manifest"])

            def authorize(evidence):
                authorize_observations(
                    evidence,
                    org,
                    actor,
                    manifest,
                    root_ref=config["root_ref"],
                    matrix_ref=config["matrix_ref"],
                    project_category=config["project_category"],
                )

            yield authorize
