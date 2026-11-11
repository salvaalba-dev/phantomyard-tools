"""Derive a read-only catalog from existing approvals and current policy.

The host must validate the approval bundle and authenticate stable organization
and source snapshots before calling. This module never publishes or approves a
resource, and cannot replace the host's per-request authorization checks.
"""

import copy


def revalidate_catalog(
    bundle, draft, view_policy, categories, authority_revision, organization_id
):
    """Retain unchanged approved rows whose classifications still exist.

    No draft-only row may enter the result. A missing or changed dependency
    recursively excludes its dependents; previous approval data is untouched.
    """
    if not all(
        isinstance(value, dict) for value in (bundle, draft, view_policy, categories)
    ):
        raise TypeError("Validated projection and current policy are required")
    if not isinstance(authority_revision, str) or not authority_revision:
        raise ValueError("Current authority revision is required")
    catalog = bundle.get("catalog")
    if (
        not isinstance(organization_id, str)
        or not organization_id
        or not isinstance(catalog, dict)
        or catalog.get("organization") != organization_id
        or draft.get("organization") != organization_id
    ):
        raise ValueError("Projection belongs to a different organization")
    approved = catalog.get("resources") if isinstance(catalog, dict) else None
    sources = bundle.get("sources")
    candidates = draft.get("resources")
    definitions = view_policy.get("scope_definitions")
    if (
        not isinstance(approved, list)
        or not isinstance(sources, list)
        or not isinstance(candidates, list)
        or not isinstance(definitions, dict)
    ):
        raise TypeError("Invalid projection inputs")

    def index(rows):
        result = {}
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("id"), str)
                or not row["id"]
                or row["id"] in result
            ):
                raise ValueError("Invalid or duplicate projection resource")
            result[row["id"]] = row
        return result

    old = index(approved)
    source = index(sources)
    current = index(candidates)
    if set(source) != set(old):
        raise ValueError("Approval provenance does not match resources")
    keep = set()
    for ident, row in old.items():
        now = current.get(ident)
        scope = row.get("scope")
        category = row.get("category")
        if (
            not isinstance(now, dict)
            or not isinstance(source[ident].get("provenance"), dict)
            or source[ident]["provenance"] != now.get("provenance")
        ):
            continue
        if any(
            row.get(key) != now.get(key)
            for key in ("kind", "payload_sha256", "requires", "endpoints")
        ):
            continue
        if (
            not isinstance(category, str)
            or category == "category-0"
            or category not in categories
            or not isinstance(scope, dict)
        ):
            continue
        definition = definitions.get(scope.get("id"))
        if not isinstance(definition, dict) or definition.get("kind") != scope.get(
            "kind"
        ):
            continue
        category_definition = categories.get(category)
        if not isinstance(category_definition, dict):
            continue
        category_scope = category_definition.get("scope")
        if category_scope not in (None, "project"):
            continue
        if scope.get("kind") == "project" and row.get("project") != scope.get("id"):
            continue
        if category_scope == "project" and (
            scope.get("kind") != "project" or row.get("project") != scope.get("id")
        ):
            continue
        if category.startswith("category-4") and row.get("project") is None:
            continue
        if any(
            not isinstance(row.get(key, []), list) for key in ("requires", "endpoints")
        ):
            continue
        keep.add(ident)
    while True:
        remaining = {
            ident
            for ident in keep
            if all(
                dep in keep
                for dep in old[ident].get("requires", [])
                + old[ident].get("endpoints", [])
            )
        }
        if remaining == keep:
            break
        keep = remaining
    result = copy.deepcopy(catalog)
    result["authority_revision"] = authority_revision
    result["resources"] = [copy.deepcopy(row) for row in approved if row["id"] in keep]
    return result
