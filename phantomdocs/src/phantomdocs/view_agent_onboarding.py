"""Read-only onboarding diagnostics for separately provisioned viewer routes.

The candidate must already have passed public-identity and reader validation.
This report grants nothing and never prints identities, signer keys or paths.
"""

import subprocess  # nosec B404
from pathlib import PurePosixPath

from phantomdocs.view_agent_directory import has_declared_channel


def runtime_directories(unit):
    """Read systemd's effective runtime-directory declarations for the target."""
    # The host adapter validates the unit before calling this helper.
    result = subprocess.run(  # nosec B603
        [
            "/usr/bin/systemctl",
            "--system",
            "--no-ask-password",
            "show",
            unit,
            "--property=RuntimeDirectory",
            "--value",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=10,
    )
    if len(result.stdout) > 65536:
        raise ValueError("Bounded runtime declarations required")
    return set(result.stdout.split())


def onboarding_report(org, inventory, candidate, groups, directories):
    """Explain missing preparation without inferring authority from inventory."""
    provisioned = {row["actor"]: row for row in inventory}
    verified = set(candidate["agent_actors"])
    rows = []
    for actor in sorted(org["actors"], key=lambda row: row["id"]):
        actor_id = actor["id"]
        if not has_declared_channel(actor):
            status = "no-declared-channel"
        elif actor_id not in provisioned:
            status = "not-provisioned"
        elif actor_id not in verified:
            status = "identity-unverified"
        else:
            route = provisioned[actor_id]["route"]
            parent = PurePosixPath(route["socket_path"]).parent
            relative = (
                str(parent.relative_to("/run"))
                if parent.is_relative_to("/run")
                else None
            )
            if relative not in directories or route["socket_group"] not in groups:
                status = "runtime-not-prepared"
            else:
                status = "ready"
        rows.append({"actor": actor_id, "status": status})
    return {
        "status": "onboarding-checked",
        "ready": all(row["status"] in {"ready", "no-declared-channel"} for row in rows),
        "actors": rows,
        "guard_arguments_and_client_config_require_operator_review": True,
    }
