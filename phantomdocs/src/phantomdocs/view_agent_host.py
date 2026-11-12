"""Root-managed route reconciliation for separately provisioned agent accounts.

Unknown accounts receive no route. This adapter never installs personas, reads
their private identity files, or approves resources. All installation inputs
must be root-controlled and updated under the same transaction lock.
"""

import argparse
import json
import os
import secrets
import subprocess  # nosec B404
from concurrent.futures import ThreadPoolExecutor

from phantomdocs.view_agent_directory import has_declared_channel
from phantomdocs.view_agent_guarded_launch import http_ready
from phantomdocs.view_agent_public_probe import query_public_identity
from phantomdocs.view_agent_reconcile import compose_plan, plan_routes
from phantomdocs.view_agent_supervisor import reconcile_once
from phantomdocs.view_agent_systemd import SystemdRouteHost
from phantomdocs.workflow_admission_config import _read_protected, _unique, parse_policy
from phantomdocs.workflow_protected_paths import protected_parent


def build_candidate(org_bytes, baseline, inventory, observe):
    """Bind every requested route to an independently queried runtime identity."""
    org = parse_policy(org_bytes)
    if not isinstance(inventory, list) or len(inventory) > 64:
        raise ValueError("Bounded protected account inventory required")
    actors = {row["id"]: row for row in org["actors"]}
    bindings, provisioned, current, identities = [], {}, {}, []
    for row in inventory:
        if not isinstance(row, dict) or set(row) != {
            "actor",
            "account",
            "persona",
            "route",
        }:
            raise ValueError("Invalid account inventory entry")
        actor, account, persona, route = (
            row[k] for k in ("actor", "account", "persona", "route")
        )
        if (
            not all(isinstance(x, str) and x for x in (actor, account, persona))
            or not isinstance(route, dict)
            or actor in provisioned
            or route.get("actor") != actor
        ):
            raise ValueError("Ambiguous protected route inventory")
        bindings.append({"actor": actor, "account": account})
        provisioned[actor] = route
        current[actor] = {"account": account, "uid": route.get("issuer_uid")}
        if has_declared_channel(actors.get(actor)):
            identities.append(row)

    def observation(row):
        uid, npub = observe(row["account"], row["persona"])
        if type(uid) is not int or uid != row["route"].get("issuer_uid"):
            raise ValueError("Account no longer matches provisioned Unix identity")
        if sum(actor.get("npub") == npub for actor in actors.values()) > 1:
            raise ValueError("Public identity belongs to multiple organization actors")
        return {
            "account": row["account"],
            "uid": uid,
            "npub": npub,
            "telegram_bot": None,
        }

    with ThreadPoolExecutor(max_workers=8) as executor:
        observed = list(executor.map(observation, identities))
    plan = plan_routes(org, bindings, observed, current)
    result = compose_plan(baseline, current, plan, provisioned)
    return json.dumps(result, sort_keys=True, separators=(",", ":")).encode()


def read_json(path):
    return json.loads(_read_protected(path), object_pairs_hook=_unique)


def validate_reader(candidate, settings):
    """Run the pinned schema loader before systemd creates runtime directories.

    Full preflight runs inside the guarded launcher after those directories
    exist. It must not bind sockets or require live runtime paths here.
    """
    import pwd

    config = json.loads(candidate, object_pairs_hook=_unique)
    account = pwd.getpwuid(config["reader_uid"])
    if account.pw_uid <= 0:
        raise ValueError("Unprivileged reader required")
    with protected_parent(settings["config"]) as (parent, _name):
        name = ".supervisor-validate-" + secrets.token_hex(16) + ".json"
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            os.fchown(fd, 0, account.pw_gid)
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(candidate)
                stream.flush()
                os.fsync(fd)
            path = settings["config"].rsplit("/", 1)[0] + "/" + name
            # Pinned operator-controlled loader, protected config, explicit UID.
            subprocess.run(  # nosec B603
                [
                    settings["python"],
                    "-B",
                    "-c",
                    (
                        "import os,runpy,sys; sys.path.insert(0,os.path.dirname(sys.argv[1])); "
                        "runpy.run_path(sys.argv[1])['load'](sys.argv[2])"
                    ),
                    settings["reader"],
                    path,
                ],
                user=account.pw_uid,
                group=account.pw_gid,
                extra_groups=sorted(
                    set(os.getgrouplist(account.pw_name, account.pw_gid))
                    | set(settings["supplementary_groups"])
                ),
                env={
                    "HOME": account.pw_dir,
                    "PATH": "/usr/bin:/bin",
                    "PYTHONNOUSERSITE": "1",
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=25,
                cwd="/",
            )
        finally:
            os.close(fd)
            os.unlink(name, dir_fd=parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "A root-managed supervisor is required\n")
    settings = read_json(args.settings)
    fields = {
        "org",
        "config",
        "journal",
        "committed",
        "policy_lock",
        "transaction_lock",
        "unit",
    }
    if (
        not isinstance(settings, dict)
        or set(settings)
        != fields
        | {
            "baseline",
            "inventory",
            "runtime",
            "python",
            "reader",
            "supplementary_groups",
        }
        or not isinstance(settings["supplementary_groups"], list)
        or any(type(g) is not int or g <= 0 for g in settings["supplementary_groups"])
    ):
        parser.exit(1, "Invalid protected supervisor settings\n")
    baseline = read_json(settings["baseline"])
    port = baseline["port"]
    host = SystemdRouteHost(
        **{key: settings[key] for key in fields},
        validate=lambda data: validate_reader(data, settings),
        health=lambda: http_ready(port),
    )

    def build(org_bytes):
        return build_candidate(
            org_bytes,
            read_json(settings["baseline"]),
            read_json(settings["inventory"]),
            lambda account, persona: query_public_identity(
                account, persona, settings["runtime"]
            ),
        )

    try:
        if args.apply:
            status = reconcile_once(host, build)
        else:
            with host.lock():
                org_bytes, _revision = host.authority()
                candidate = build(org_bytes)
                host.validate(candidate)
            status = "candidate-schema-valid"
        print(json.dumps({"status": status}))
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError):
        # Deliberately omit configuration, identity values and exception text.
        print(json.dumps({"status": "reconciliation-refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
