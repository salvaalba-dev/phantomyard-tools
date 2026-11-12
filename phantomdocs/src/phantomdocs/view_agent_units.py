"""Render inactive systemd drafts for a protected, provisioned route inventory.

This module does not install files, create accounts, or grant document approval.
The operator must review the owned /run paths before installing the drafts.
"""

import re
from pathlib import PurePosixPath


def _argument(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
        raise ValueError("Explicit systemd-safe installation value required")
    return value


def render_units(
    settings, config, *, settings_path, module_path, reader_group, tmpfiles_path
):
    """Return service, timer and runtime metadata drafts without host changes."""
    for path in (settings_path, module_path, tmpfiles_path):
        if not _argument(path).startswith("/") or ".." in PurePosixPath(path).parts:
            raise ValueError("Canonical absolute installation paths required")
    if type(reader_group) is not int or reader_group <= 0:
        raise ValueError("Explicit unprivileged reader group required")
    routes = [config, *config.get("additional_issuers", [])]
    directories, rules = [], []
    groups = settings["supplementary_groups"]
    if not isinstance(groups, list) or any(
        type(g) is not int or g <= 0 for g in groups
    ):
        raise ValueError("Explicit unprivileged supplementary groups required")
    for route in routes:
        directory = PurePosixPath(route["socket_path"]).parent
        if (
            not re.fullmatch(r"/run/phantomview-[a-z0-9_-]+/reader", str(directory))
            or str(directory) in directories
            or type(route["issuer_uid"]) is not int
            or route["issuer_uid"] <= 0
            or route["socket_group"] not in groups
        ):
            raise ValueError(
                "Only distinct, explicitly owned viewer runtime paths are supported"
            )
        directories.append(str(directory))
        uid, gid = route["issuer_uid"], route["socket_group"]
        rules.extend(
            [
                f"a+ {directory.parent} - - - - u:{uid}:--x",
                f"d {directory} 0750 {config['reader_uid']} {gid} -",
                f"a+ {directory} - - - - u:{uid}:--x,d:u:{uid}:rw-",
            ]
        )
    guard = [
        _argument(settings["python"]),
        "-B",
        "-m",
        "phantomdocs.view_agent_guarded_launch",
    ]
    for key, option in (
        ("org", "org"),
        ("config", "config"),
        ("journal", "journal"),
        ("committed", "committed"),
        ("policy_lock", "policy-lock"),
        ("python", "python"),
        ("reader", "reader"),
    ):
        guard.extend(["--" + option, _argument(settings[key])])
    for group in sorted(set(groups)):
        guard.extend(["--supplementary-group", str(group)])
    for directory in directories:
        guard.extend(["--runtime-directory", directory])
    runtime = " ".join(str(PurePosixPath(d).relative_to("/run")) for d in directories)
    runtime_parents = " ".join(
        sorted({str(PurePosixPath(d).parent) for d in directories})
    )
    override = (
        "[Service]\nUser=root\nGroup="
        + str(reader_group)
        + "\nProtectHome=read-only\nKillMode=control-group\n"
        "# Guard and child seal privileges after the one UID transition.\nNoNewPrivileges=false\n"
        "RuntimeDirectory=\nRuntimeDirectory="
        + runtime
        + "\nRuntimeDirectoryPreserve=no\nEnvironment=PYTHONPATH="
        + module_path
        + "\nReadWritePaths="
        + runtime_parents
        + "\nExecStartPre=/usr/bin/systemd-tmpfiles --create "
        + tmpfiles_path
        + "\nExecStart=\nExecStart="
        + " ".join(guard)
        + "\n"
    )
    write_paths = " ".join(
        sorted(
            {
                str(PurePosixPath(settings[k]).parent)
                for k in ("config", "journal", "committed")
            }
        )
    )
    for path in write_paths.split():
        _argument(path)
    supervisor = (
        "[Unit]\nDescription=Reconcile provisioned PhantomView agent routes\nAfter=network.target\n"
        "[Service]\nType=oneshot\nUser=root\nEnvironment=PYTHONPATH="
        + module_path
        + "\nExecStart="
        + _argument(settings["python"])
        + " -B -m phantomdocs.view_agent_host --settings "
        + settings_path
        + " --apply\n"
        "Restart=on-failure\nRestartSec=15s\nTimeoutStartSec=180s\n"
        "NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\n"
        "ReadWritePaths=" + write_paths + "\n"
    )
    timer = (
        "[Unit]\nDescription=Refresh provisioned PhantomView agent routes\n"
        "[Timer]\nOnBootSec=15s\nOnUnitInactiveSec=30s\nAccuracySec=1s\n"
        "Unit=phantomview-agent-supervisor.service\n[Install]\nWantedBy=timers.target\n"
    )
    return {
        "reader.override.conf": override,
        "phantomview-agent-supervisor.service": supervisor,
        "phantomview-agent-supervisor.timer": timer,
        "runtime.conf": "\n".join(rules) + "\n",
    }
