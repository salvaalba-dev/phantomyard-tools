"""Plan viewer route changes from trusted bindings and current PhantomOrg.

This module performs no host changes. Its caller must authenticate the
binding inventory and enforce the resulting plan atomically.
"""

import re

from phantomdocs.access import validate_org_schema
from phantomdocs.view_agent_directory import has_declared_channel
from phantomdocs.view_agent_probe import nostr_identity, telegram_identity
from phantomdocs.view_agent_routes import compose_routes


def plan_with_probes(org, bindings, account_credentials, current):
    """Build observations from credentials supplied by a trusted host adapter.

    Credentials remain in memory and are never placed in the returned plan.
    The adapter must verify file ownership and bind each UID before calling.
    """
    if not isinstance(account_credentials, list):
        raise TypeError("Trusted account credentials required")
    observed = []
    for account in account_credentials:
        if not isinstance(account, dict) or set(account) != {
            "account",
            "uid",
            "nsec",
            "telegram_token",
        }:
            raise ValueError("Invalid account credential record")
        observed.append(
            {
                "account": account["account"],
                "uid": account["uid"],
                "npub": nostr_identity(account["nsec"]),
                "telegram_bot": telegram_identity(account["telegram_token"]),
            }
        )
    return plan_routes(org, bindings, observed, current)


def compose_plan(human_baseline, current, plan, provisioned):
    """Render a plan only with separately provisioned, UID-matched routes."""
    if not all(isinstance(value, dict) for value in (current, plan, provisioned)):
        raise TypeError("Trusted route plan required")
    if (
        set(plan) != {"add", "remove", "unverified"}
        or not isinstance(plan["add"], dict)
        or not isinstance(plan["remove"], list)
        or not isinstance(plan["unverified"], list)
    ):
        raise ValueError("Invalid route plan")
    desired = {
        key: value for key, value in current.items() if key not in plan["remove"]
    }
    desired.update(plan["add"])
    if any(actor in desired for actor in plan["unverified"]):
        raise ValueError("Unverified actors cannot receive routes")
    routes = []
    for actor, binding in desired.items():
        route = provisioned.get(actor)
        if (
            not isinstance(binding, dict)
            or not isinstance(route, dict)
            or route.get("actor") != actor
            or type(binding.get("uid")) is not int
            or route.get("issuer_uid") != binding["uid"]
        ):
            raise ValueError("Agent route is not provisioned for the verified UID")
        routes.append(route)
    return compose_routes(human_baseline, routes)


def plan_routes(org, bindings, observed, current):
    """Return route additions and removals without guessing local accounts.

    Bindings and observations are operator-controlled input, not evidence on
    their own. Each binding maps an actor to an account and the independently
    verified public identity used to identify that actor on this host.
    """
    validate_org_schema(org)
    if not isinstance(bindings, list) or not isinstance(observed, list):
        raise TypeError("Trusted bindings and account observations required")
    if not isinstance(current, dict):
        raise TypeError("Current tool-owned routes required")
    rows = org.get("actors")
    if not isinstance(rows, list):
        raise TypeError("Invalid organization actors")
    actors = {}
    for actor in rows:
        if not isinstance(actor, dict) or not isinstance(actor.get("id"), str):
            raise TypeError("Invalid actor")
        actor_id = actor["id"]
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", actor_id)
            or actor_id in actors
        ):
            raise ValueError("Invalid or duplicate actor")
        actors[actor_id] = actor
    accounts = {}
    uids = set()
    for item in observed:
        if not isinstance(item, dict) or set(item) != {
            "account",
            "uid",
            "npub",
            "telegram_bot",
        }:
            raise ValueError("Invalid account observation")
        name, uid = item["account"], item["uid"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,63}", name)
            or type(uid) is not int
            or uid <= 0
            or name in accounts
            or uid in uids
        ):
            raise ValueError("Ambiguous account observation")
        accounts[name] = item
        uids.add(uid)
    desired = {}
    bound_accounts = set()
    seen = set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"actor", "account"}:
            raise TypeError("Invalid actor binding")
        actor_id, name = binding["actor"], binding["account"]
        if not isinstance(actor_id, str) or not isinstance(name, str):
            raise TypeError("Invalid actor binding")
        if actor_id in seen or name in bound_accounts:
            raise ValueError("Ambiguous actor binding")
        seen.add(actor_id)
        bound_accounts.add(name)
        actor = actors.get(actor_id)
        if actor is None or not has_declared_channel(actor):
            continue
        account = accounts.get(name)
        if account is None or not (
            (
                has_declared_channel({"npub": actor.get("npub")})
                and account["npub"] == actor["npub"]
            )
            or (
                has_declared_channel({"telegram_bot": actor.get("telegram_bot")})
                and isinstance(account["telegram_bot"], str)
                and account["telegram_bot"].lower() == actor["telegram_bot"].lower()
            )
        ):
            continue
        desired[actor_id] = {"account": name, "uid": account["uid"]}
    if any(
        not isinstance(k, str) or not isinstance(v, dict) for k, v in current.items()
    ):
        raise ValueError("Invalid current route inventory")
    return {
        "add": {
            key: value for key, value in desired.items() if current.get(key) != value
        },
        "remove": sorted(
            key for key, value in current.items() if desired.get(key) != value
        ),
        "unverified": sorted(
            key
            for key, actor in actors.items()
            if has_declared_channel(actor) and key not in desired
        ),
    }
