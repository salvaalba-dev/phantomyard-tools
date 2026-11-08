"""Actor-scoped viewer authorization from PhantomOrg.

This policy helper does not authenticate a process, create sessions or connect
to PhantomView. Callers must bind the actor to a trusted local agent separately
and re-evaluate the current organization policy on each request.
"""

from phantomdocs.access import can_read, validate_org_schema


def permits_view(org, actor, resource):
    """Check exact scope and category grants for an agent, without human identity."""
    try:
        validate_org_schema(org)
        if not isinstance(actor, str) or not actor or not isinstance(resource, dict):
            return False
        actors = org["actors"]
        if (
            not isinstance(actors, list)
            or sum(isinstance(a, dict) and a.get("id") == actor for a in actors) != 1
        ):
            return False
        organization = org["organization"]["id"]
        scope = resource.get("scope")
        if (
            not isinstance(organization, str)
            or not organization
            or resource.get("organization") != organization
            or resource.get("secret") is not False
            or not isinstance(scope, dict)
            or set(scope) != {"id", "kind"}
            or not isinstance(scope["id"], str)
            or not isinstance(scope["kind"], str)
            or scope["kind"] not in {"project", "department", "organization"}
        ):
            return False
        policy = org["policies"]["phantomview"]
        definition = policy["scope_definitions"].get(scope["id"])
        grants = policy["persona_scope_grants"].get(actor)
        if (
            not isinstance(definition, dict)
            or definition.get("kind") != scope["kind"]
            or not isinstance(grants, list)
            or scope["id"] not in grants
        ):
            return False
        if scope["kind"] == "organization" and scope["id"] != organization:
            return False
        if scope["kind"] == "department":
            departments = org.get("departments")
            if not isinstance(departments, list) or not any(
                isinstance(d, dict) and d.get("id") == scope["id"] for d in departments
            ):
                return False
        if scope["kind"] == "project":
            projects = policy["project_grants"].get(actor)
            if (
                not isinstance(projects, list)
                or scope["id"] not in projects
                or resource.get("project") != scope["id"]
            ):
                return False
        elif resource.get("project") is not None:
            return False
        category = resource.get("category")
        if not isinstance(category, str) or category == "category-0":
            return False
        definition = org["policies"]["security_categories"].get(category)
        if not isinstance(definition, dict):
            return False
        if definition.get("scope") == "project" and (
            scope["kind"] != "project"
            or resource.get("project") != scope["id"]
            or definition.get("owner", scope["id"]) != scope["id"]
        ):
            return False
        return can_read(org, actor, category)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
