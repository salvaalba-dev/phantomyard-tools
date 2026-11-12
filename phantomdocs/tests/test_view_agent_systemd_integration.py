"""Opt-in root/systemd trial against an explicitly selected installed reader.

Creates one disposable unit and private runtime files. It never changes the
production unit, live organization, approved projection, or persona files.
"""

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from phantomdocs.view_agent_guarded_launch import http_ready
from phantomdocs.view_agent_host import build_candidate, read_json, validate_reader
from phantomdocs.view_agent_public_probe import query_public_identity
from phantomdocs.view_agent_recovery import RecoveryRequired
from phantomdocs.view_agent_supervisor import reconcile_once
from phantomdocs.view_agent_systemd import SystemdRouteHost


@pytest.mark.skipif(
    os.environ.get("PHANTOMVIEW_SYSTEMD_TRIAL") != "1" or os.name != "posix",
    reason="Explicit root/systemd reader trial required",
)
def test_real_reader_recovers_and_refuses_stale_startup():
    assert os.geteuid() == 0
    from phantomdocs.workflow_admission_config import _read_protected

    paths = {
        name: os.environ["PHANTOMVIEW_TRIAL_" + name]
        for name in (
            "CONFIG",
            "ORG",
            "PYTHON",
            "READER",
            "POLICY_LOCK",
        )
    }
    assert all(re.fullmatch(r"/[A-Za-z0-9_./-]+", p) for p in paths.values())
    initial = json.loads(_read_protected(paths["CONFIG"]))
    org_bytes = _read_protected(paths["ORG"])
    tag = "pv-supervisor-test-" + uuid.uuid4().hex
    root = Path("/run") / tag
    root.mkdir(mode=0o750)
    import pwd

    reader = pwd.getpwuid(initial["reader_uid"])
    os.chown(root, 0, reader.pw_gid)
    unit_path = Path("/run/systemd/system") / (tag + ".service")
    assert not unit_path.exists()

    def systemctl(*args, check=True):
        return subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            check=check,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=35,
        )

    try:
        audit = root / "audit"
        audit.mkdir(mode=0o700)
        os.chown(audit, reader.pw_uid, reader.pw_gid)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        candidate = json.loads(json.dumps(initial))
        candidate["port"] = port
        candidate["audit_path"] = str(audit / "sessions.sqlite")
        runtime_directories = []
        all_routes = [candidate, *candidate.get("additional_issuers", [])]
        traversal = ",".join(
            f"u:{uid}:--x" for uid in sorted({r["issuer_uid"] for r in all_routes})
        )
        tmpfiles = [f"a+ {root} - - - - {traversal}"]
        for index, route in enumerate(
            [candidate, *candidate.get("additional_issuers", [])]
        ):
            directory = root / ("issuer-" + str(index))
            directory.mkdir(mode=0o700)
            os.chown(directory, reader.pw_uid, reader.pw_gid)
            runtime_directories.append(tag + "/" + directory.name)
            tmpfiles.append(f"d {directory} 0700 {reader.pw_uid} {reader.pw_gid} -")
            tmpfiles.append(
                f"a+ {directory} - - - - u:{route['issuer_uid']}:--x,d:u:{route['issuer_uid']}:rw-"
            )
            route["socket_path"] = str(directory / "link.sock")
            route["conversation_socket"] = None
        config_path = root / "reader.json"
        config_path.write_text(json.dumps(candidate))
        os.chown(config_path, 0, reader.pw_gid)
        config_path.chmod(0o640)
        org_path = root / "org.yaml"
        org_path.write_bytes(org_bytes)
        org_path.chmod(0o600)
        pending, committed = root / "pending.json", root / "committed.json"
        transaction = root / "transaction.lock"
        transaction.touch(mode=0o600)
        directory_rules = root / "directories.conf"
        directory_rules.write_text("\n".join(tmpfiles) + "\n")
        module_path = str(
            Path(sys.modules["phantomdocs"].__file__).resolve().parent.parent
        )
        diagnostic_reader = root / "diagnostic_reader.py"
        diagnostic_reader.write_text(
            "import sys,traceback\nsys.path.insert(0,"
            + repr(str(Path(paths["READER"]).parent))
            + ")\n"
            "import reader_launch as reader\n"
            "def report(function):\n"
            " def checked(*args,**kwargs):\n"
            "  try:\n   return function(*args,**kwargs)\n"
            "  except BaseException as error:\n"
            "   for frame in traceback.extract_tb(error.__traceback__):\n"
            "    print('trial-runtime',frame.name,frame.lineno,flush=True)\n"
            "   raise\n return checked\n"
            "reader.build=report(reader.build)\n"
            "reader.PublishedReader.serve=report(reader.PublishedReader.serve)\n"
            "try:\n reader.preflight(reader.load(sys.argv[sys.argv.index('--config')+1]))\n"
            "except BaseException as error:\n"
            " for frame in traceback.extract_tb(error.__traceback__):\n"
            "  print('trial-preflight',frame.name,frame.lineno,flush=True)\n"
            " raise SystemExit(1)\nraise SystemExit(reader.main())\n"
        )
        os.chown(diagnostic_reader, 0, reader.pw_gid)
        diagnostic_reader.chmod(0o640)
        command = [
            sys.executable,
            "-m",
            "phantomdocs.view_agent_guarded_launch",
            "--org",
            str(org_path),
            "--config",
            str(config_path),
            "--journal",
            str(pending),
            "--committed",
            str(committed),
            "--policy-lock",
            paths["POLICY_LOCK"],
            "--python",
            paths["PYTHON"],
            "--reader",
            str(diagnostic_reader),
        ]
        for group in sorted(
            {
                r["socket_group"]
                for r in [candidate, *candidate.get("additional_issuers", [])]
            }
        ):
            command.extend(["--supplementary-group", str(group)])
        for directory in runtime_directories:
            command.extend(["--runtime-directory", "/run/" + directory])
        assert all(re.fullmatch(r"[A-Za-z0-9_./-]+", p) for p in command)
        unit_path.write_text(
            "[Service]\nType=simple\nUser=root\nGroup="
            + str(reader.pw_gid)
            + "\nKillMode=control-group\n"
            "RuntimeDirectory=" + " ".join(runtime_directories) + "\n"
            "ProtectSystem=strict\nProtectHome=read-only\nNoNewPrivileges=false\nPrivateTmp=true\n"
            "RestrictAddressFamilies=AF_INET AF_UNIX\n"
            "ReadWritePaths=" + str(root) + "\n"
            "ExecStartPre=/usr/bin/systemd-tmpfiles --create "
            + str(directory_rules)
            + "\n"
            "Environment=PYTHONPATH="
            + module_path
            + "\nExecStart="
            + " ".join(command)
            + "\nTimeoutStopSec=10\n"
        )
        systemctl("daemon-reload")
        host = SystemdRouteHost(
            org=str(org_path),
            config=str(config_path),
            journal=str(pending),
            committed=str(committed),
            policy_lock=paths["POLICY_LOCK"],
            transaction_lock=str(transaction),
            unit=unit_path.name,
            validate=lambda data: validate_reader(
                data,
                {
                    "config": str(config_path),
                    "python": paths["PYTHON"],
                    "reader": paths["READER"],
                    "supplementary_groups": sorted(
                        {
                            r["socket_group"]
                            for r in [
                                candidate,
                                *candidate.get("additional_issuers", []),
                            ]
                        }
                    ),
                },
            ),
            health=lambda: http_ready(port),
        )
        encoded = json.dumps(candidate, sort_keys=True).encode()
        assert reconcile_once(host, lambda _: encoded) == "updated"
        assert host.healthy() and not pending.exists()
        candidate["session_seconds"] -= 1
        encoded = json.dumps(candidate, sort_keys=True).encode()
        host._health = lambda: False
        host.readiness_seconds = 1
        with pytest.raises(RecoveryRequired):
            reconcile_once(host, lambda _: encoded)
        assert pending.exists() and not http_ready(port)
        host._health = lambda: http_ready(port)
        host.readiness_seconds = 20
        assert reconcile_once(host, lambda _: encoded) == "recovered"
        assert host.healthy() and not pending.exists()
        systemctl("restart", unit_path.name)
        assert host.healthy()
        main_pid = int(
            subprocess.check_output(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--value",
                    "-p",
                    "MainPID",
                    unit_path.name,
                ],
                text=True,
                timeout=5,
            )
        )
        assert main_pid > 0
        assert "NoNewPrivs:\t1" in Path(f"/proc/{main_pid}/status").read_text()
        child_pids = (
            Path(f"/proc/{main_pid}/task/{main_pid}/children").read_text().split()
        )
        assert len(child_pids) == 1
        child_status = Path(f"/proc/{child_pids[0]}/status").read_text()
        assert (
            f"Uid:\t{reader.pw_uid}\t{reader.pw_uid}\t{reader.pw_uid}\t{reader.pw_uid}"
            in child_status
        )
        assert "NoNewPrivs:\t1" in child_status
        # Some VPS kernels reject signalling auxiliary cgroup processes even
        # after killing both the launcher and reader. Verify the outcome below.
        systemctl("kill", "--signal=SIGKILL", unit_path.name, check=False)
        deadline = time.monotonic() + 5
        while http_ready(port) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not http_ready(port)
        deadline = time.monotonic() + 5
        while Path(f"/proc/{main_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        with pytest.raises(ProcessLookupError):
            os.kill(main_pid, 0)
        assert reconcile_once(host, lambda _: encoded) == "updated"
        assert host.healthy()
        if os.environ.get("PHANTOMVIEW_TRIAL_SUPERVISOR_SETTINGS"):
            exercise_account_withdrawal_and_return(
                root, host, candidate, org_path, org_bytes
            )
        # Simulate an authority revision change only in the private trial file.
        org_path.write_bytes(org_bytes + b"\n# trial revision changed\n")
        assert (
            hashlib.sha256(org_path.read_bytes()).hexdigest()
            != hashlib.sha256(org_bytes).hexdigest()
        )
        systemctl("restart", unit_path.name)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if systemctl("is-active", unit_path.name, check=False).returncode:
                break
            time.sleep(0.1)
        assert systemctl("is-active", unit_path.name, check=False).returncode != 0
        assert not http_ready(port)
        assert reconcile_once(host, lambda _: encoded) == "updated"
        assert host.healthy()
    finally:
        systemctl("stop", unit_path.name, check=False)
        systemctl("reset-failed", unit_path.name, check=False)
        if unit_path.exists():
            unit_path.unlink()
        systemctl("daemon-reload")
        shutil.rmtree(root)


def exercise_account_withdrawal_and_return(root, host, candidate, org_path, org_bytes):
    """Use one real existing account against an isolated organization copy."""
    import pwd

    import yaml

    settings = read_json(os.environ["PHANTOMVIEW_TRIAL_SUPERVISOR_SETTINGS"])
    client = read_json(os.environ["PHANTOMVIEW_TRIAL_LINK_CONFIG"])
    routes = {
        r["actor"]: r for r in [candidate, *candidate.get("additional_issuers", [])]
    }
    matches = [r for r in routes.values() if r["issuer_uid"] == client["agent_uid"]]
    assert len(matches) == 1
    actor = matches[0]["actor"]
    assert actor in candidate["agent_actors"] and actor not in candidate.get(
        "mixed_agent_signers", {}
    )
    account = pwd.getpwuid(client["agent_uid"])
    client["socket_path"] = matches[0]["socket_path"]
    client_path = root / "client.json"
    client_path.write_text(json.dumps(client))
    os.chown(client_path, 0, account.pw_gid)
    client_path.chmod(0o640)

    def issue():
        return subprocess.run(
            [
                os.environ["PHANTOMVIEW_TRIAL_LINK_PYTHON"],
                "-B",
                "-m",
                "phantomdocs.view_agent_link",
                "--config",
                str(client_path),
            ],
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=os.getgrouplist(account.pw_name, account.pw_gid),
            env={
                "HOME": account.pw_dir,
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": os.environ["PHANTOMVIEW_TRIAL_LINK_MODULE_PATH"],
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )

    def request(path, *, cookie=None, body=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", candidate["port"], timeout=3
        )
        try:
            headers = {
                "Origin": candidate["origin"],
                "Host": urlsplit(candidate["origin"]).netloc,
            }
            if cookie:
                headers["Cookie"] = cookie
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(
                "GET" if body is None else "POST",
                path,
                body=None if body is None else json.dumps(body),
                headers=headers,
            )
            response = connection.getresponse()
            status, set_cookie = response.status, response.getheader("Set-Cookie")
            response.read(2 * 1024 * 1024)
            return status, set_cookie
        finally:
            connection.close()

    def login():
        result = issue()
        if result.returncode or not result.stdout.strip().startswith(
            candidate["origin"] + "/#c="
        ):
            raise RuntimeError("Isolated account link refused")
        code = parse_qs(urlsplit(result.stdout.strip()).fragment)["c"][0]
        status, cookie = request("/api/redeem", body={"code": code})
        if status != 200 or not cookie:
            raise RuntimeError("Isolated account redemption refused")
        return cookie.split(";", 1)[0]

    baseline = read_json(settings["baseline"])
    for key in ("port", "audit_path", "session_seconds"):
        baseline[key] = candidate[key]
    for row in [baseline, *baseline.get("additional_issuers", [])]:
        row["socket_path"] = routes[row["actor"]]["socket_path"]
        row["conversation_socket"] = None
    inventory = read_json(settings["inventory"])
    for row in inventory:
        row["route"]["socket_path"] = routes[row["actor"]]["socket_path"]

    def build(data):
        return build_candidate(
            data,
            baseline,
            inventory,
            lambda a, p: query_public_identity(a, p, settings["runtime"]),
        )

    cookie = login()
    assert request("/api/state", cookie=cookie)[0] == 200
    org = yaml.safe_load(org_bytes)
    removed = next(row for row in org["actors"] if row["id"] == actor)
    removed.pop("npub", None)
    removed.pop("telegram_bot", None)
    org_path.write_text(yaml.safe_dump(org))
    assert reconcile_once(host, build) == "updated"
    assert issue().returncode != 0
    assert request("/api/state", cookie=cookie)[0] in {401, 403}
    org_path.write_bytes(org_bytes)
    assert reconcile_once(host, build) == "updated"
    cookie = login()
    assert request("/api/state", cookie=cookie)[0] == 200
