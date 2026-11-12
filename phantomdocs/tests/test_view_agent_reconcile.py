import copy

import pytest

from phantomdocs.signing import npub_encode
from phantomdocs.view_agent_reconcile import compose_plan, plan_routes, plan_with_probes


def setup():
    npub = npub_encode("11" * 32)
    org = {"version": 1, "actors": [{"id": "agent", "npub": npub}]}
    bindings = [{"actor": "agent", "account": "account"}]
    observed = [{"account": "account", "uid": 1001, "npub": npub, "telegram_bot": None}]
    return org, bindings, observed


def test_add_keep_remove_and_rebind():
    org, bindings, observed = setup()
    route = {"account": "account", "uid": 1001}
    assert plan_routes(org, bindings, observed, {}) == {
        "add": {"agent": route},
        "remove": [],
        "unverified": [],
    }
    assert plan_routes(org, bindings, observed, {"agent": route})["add"] == {}
    changed = copy.deepcopy(org)
    changed["actors"] = []
    assert plan_routes(changed, bindings, observed, {"agent": route})["remove"] == [
        "agent"
    ]
    observed[0]["uid"] = 1002
    plan = plan_routes(org, bindings, observed, {"agent": route})
    assert plan["remove"] == ["agent"]
    assert plan["add"]["agent"]["uid"] == 1002


def test_mismatched_identity_and_independent_telegram():
    org, bindings, observed = setup()
    old = {"agent": {"account": "account", "uid": 1001}}
    observed[0]["npub"] = npub_encode("22" * 32)
    assert plan_routes(org, bindings, observed, old) == {
        "add": {},
        "remove": ["agent"],
        "unverified": ["agent"],
    }
    org["actors"][0] = {"id": "agent", "telegram_bot": "@example_bot"}
    assert plan_routes(org, bindings, observed, old)["unverified"] == ["agent"]
    observed[0]["telegram_bot"] = "@example_bot"
    assert plan_routes(org, bindings, observed, old)["unverified"] == []


def test_ambiguous_accounts_rejected():
    org, bindings, observed = setup()
    observed.append(
        {
            "account": "other",
            "uid": 1001,
            "npub": observed[0]["npub"],
            "telegram_bot": None,
        }
    )
    with pytest.raises(ValueError):
        plan_routes(org, bindings, observed, {})


def test_probed_identity_is_used_without_returning_credentials(monkeypatch):
    org, bindings, _ = setup()
    monkeypatch.setattr(
        "phantomdocs.view_agent_reconcile.nostr_identity",
        lambda _: org["actors"][0]["npub"],
    )
    monkeypatch.setattr(
        "phantomdocs.view_agent_reconcile.telegram_identity", lambda _: None
    )
    result = plan_with_probes(
        org,
        bindings,
        [
            {
                "account": "account",
                "uid": 1001,
                "nsec": "synthetic-secret",
                "telegram_token": None,
            }
        ],
        {},
    )
    assert result["add"]["agent"]["uid"] == 1001
    assert "synthetic-secret" not in repr(result)


def test_plan_composes_only_uid_verified_provisioned_routes():
    org, bindings, observed = setup()
    base = {
        "actor": "human",
        "issuer_uid": 2001,
        "socket_path": "/run/human.sock",
        "socket_group": 3001,
        "identities": ["a" * 64],
        "conversation_socket": None,
    }
    plan = plan_routes(org, bindings, observed, {})
    route = {
        "actor": "agent",
        "issuer_uid": 1001,
        "socket_path": "/run/agent.sock",
        "socket_group": 3001,
        "signer": "b" * 64,
    }
    assert compose_plan(base, {}, plan, {"agent": route})["agent_actors"] == ["agent"]
    route["issuer_uid"] = 1002
    with pytest.raises(ValueError):
        compose_plan(base, {}, plan, {"agent": route})
