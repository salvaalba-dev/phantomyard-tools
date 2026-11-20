"""Opt-in real systemd rehearsal; only generated /run units and /var/lib fixtures.

No production units, users, ACLs, policies or remote notification routes are used.
Service orchestration, prestart, timers, path activation and OnFailure are real.
The bridge, guarded collector and alert endpoint are synthetic consumers.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from source_publication_fixture import model
from test_notify_adapter_linux import root as root  # noqa: PLC0414 -- pytest fixture
from test_notify_adapter_linux import (
    root_profile as root_profile,  # noqa: PLC0414 -- pytest fixture
)

from phantomdocs.workflow_policy_operations import MODULE
from phantomdocs.workflow_policy_sync import policy_permissions

ENABLED = os.environ.get("PHANTOM_POLICY_SYSTEMD_TRIAL") == "1"
pytestmark = pytest.mark.skipif(
    not ENABLED, reason="explicit disposable root/systemd rehearsal required"
)


def test_real_service_reads_root_owned_runtime_as_the_existing_unprivileged_uid(
    root_profile,
):
    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    code, profile = root_profile
    script = code / "read_runtime.py"
    script.write_text(
        "import sys\nfrom notify_adapter import read_runtime_config\n"
        "assert read_runtime_config(sys.argv[1]) == {'profile':'synthetic-root-controlled'}\n"
    )
    name = "pd-policy-runtime-" + uuid.uuid4().hex + ".service"
    unit = Path("/run/systemd/system") / name

    def ctl(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    assert not unit.exists()
    with unit.open("x") as stream:
        stream.write(
            "[Service]\nType=oneshot\nUser=65534\nGroup=65534\nNoNewPrivileges=yes\n"
            f"ExecStart=/usr/bin/python3 -B {script} {profile}\nTimeoutStartSec=15\n"
        )
    try:
        assert ctl("daemon-reload").returncode == 0
        started = ctl("start", name)
        assert started.returncode == 0, started.stderr
        assert (
            ctl("show", name, "--property=Result", "--value").stdout.strip()
            == "success"
        )
        before = profile.stat()
        assert (
            before.st_uid == 0
            and before.st_gid == 65534
            and before.st_mode & 0o777 == 0o640
        )
        # The service must fail rather than silently accepting public metadata.
        profile.chmod(0o644)
        assert ctl("start", name).returncode != 0
        assert (
            ctl("show", name, "--property=Result", "--value").stdout.strip()
            == "exit-code"
        )
        assert profile.stat().st_mode & 0o777 == 0o644
    finally:
        ctl("stop", name)
        ctl("reset-failed", name)
        assert unit.parent == Path("/run/systemd/system") and unit.name.startswith(
            "pd-policy-runtime-"
        )
        unit.unlink()
        ctl("daemon-reload")


def test_real_systemd_writer_closure_recovery_drift_and_alert_delivery():
    assert sys.platform == "linux" and os.geteuid() == 0
    python = os.environ["PHANTOM_POLICY_TRIAL_PYTHON"]
    assert Path(python).is_absolute() and Path(python).name == "python"
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    assert shutil.which("setfacl") and Path("/usr/bin/node").exists()
    runtime_env = {
        k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")
    }
    tag = "pd-policy-systemd-" + uuid.uuid4().hex
    units_dir = Path("/run/systemd/system")
    installed = []

    def ctl(*args, good=True):
        result = subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if good:
            assert result.returncode == 0, result.stderr
        return result

    def wait_for(predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        pytest.fail("disposable systemd transition timed out")

    with tempfile.TemporaryDirectory(prefix=tag + "-", dir="/var/lib") as folder:
        root = Path(folder)
        names = {
            role: f"{tag}-{role}.service"
            for role in ("bridge", "publish", "reconcile", "collect", "check")
        }
        timer, watcher = f"{tag}-retry.timer", f"{tag}-source.path"
        alert_template = f"{tag}-alert@.service"
        legacy = f"{tag}-retired.service"
        source, bridge, docs, lock = [
            root / name
            for name in ("source.json", "bridge.json", "docs.json", "policy.lock")
        ]
        config_path, inventory_path, seal = [
            root / name for name in ("operations.json", "writers.json", "seal.json")
        ]
        candidate, denied, alerts = (
            root / "candidate.json",
            root / "deny-start",
            root / "alerts.jsonl",
        )
        old_model, new_model = model(), model()
        new_model["actors"][0]["actor_exceptions"] = []
        old, new = json.dumps(old_model).encode(), json.dumps(new_model).encode()
        for path, mode in ((source, 0o644), (bridge, 0o600), (docs, 0o640)):
            path.write_bytes(old)
            path.chmod(mode)
        os.chown(docs, 0, 65533)
        subprocess.run(["setfacl", "-m", "u:65534:r--", str(docs)], check=True)
        metadata = {str(p): policy_permissions(str(p)) for p in (source, bridge, docs)}
        lock.touch(mode=0o644)
        lock.with_name("policy.lock.publisher").touch(mode=0o600)
        candidate.write_bytes(new)
        resolver = root / "resolver.js"
        resolver.write_text(
            "exports.parseOrgYaml=JSON.parse;exports.validateOrgReferences=()=>{};exports.deriveAgents=o=>o;exports.deriveRouting=()=>({});exports.actorsByRole=()=>({});"
        )
        bridge_script = root / "bridge.py"
        bridge_script.write_text(
            f"import os,pathlib,signal,socket\nif pathlib.Path({str(denied)!r}).exists(): raise SystemExit(3)\npathlib.Path({str(root / 'loaded')!r}).write_bytes(pathlib.Path({str(bridge)!r}).read_bytes())\na=os.environ['NOTIFY_SOCKET']\na='\\0'+a[1:] if a.startswith('@') else a\ns=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)\ns.sendto(b'READY=1',a)\ns.close()\nsignal.pause()\n"
        )
        collector = root / "collector.py"
        collector.write_text(
            f"from pathlib import Path\nfrom phantomdocs.workflow_policy_commit import committed_guard\nwith committed_guard({str(lock)!r},{str(source)!r}) as r:\n Path({str(root / 'collected')!r}).write_text(r['sha256'])\n"
        )
        handler = root / "deliver"
        handler.write_text(
            f"#!/usr/bin/python3\nimport json,pathlib,sys\ne=json.load(sys.stdin)\nwith open({str(alerts)!r},'a') as f: f.write(json.dumps(e)+'\\n')\nprint(json.dumps(dict(delivered=not pathlib.Path({str(root / 'bad-ack')!r}).exists(),receipt='synthetic:accepted')))\n"
        )
        handler.chmod(0o700)
        adapter = root / "alert.py"
        from phantomdocs import workflow_policy_alert

        shutil.copyfile(workflow_policy_alert.__file__, adapter)
        prefix = f"{python} -m {MODULE} --config {config_path}"

        def install(name, body):
            path = units_dir / name
            assert (
                path.parent == units_dir
                and path.name.startswith(tag + "-")
                and not path.exists()
            )
            # Exclusive creation never overwrites a host unit or another trial.
            with path.open("x") as stream:
                installed.append(path)
                stream.write(body)

        def service(command, *, extra="", kind="oneshot"):
            return f"[Unit]\nOnFailure={tag}-alert@%n.service\n[Service]\nType={kind}\nUMask=0077\nTimeoutStartSec=45\n{extra}ExecStart={command}\n"

        try:
            install(
                alert_template,
                f"[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {adapter} --handler {handler} --unit %i\nTimeoutStartSec=30\n",
            )
            install(
                names["bridge"],
                service(
                    f"{python} {bridge_script}",
                    kind="notify",
                    extra=f"ExecStartPre={prefix} prestart\n",
                ),
            )
            install(
                names["publish"],
                service(
                    f"{prefix} publish --candidate {candidate} --expected-source-sha256 {hashlib.sha256(old).hexdigest()} --candidate-sha256 {hashlib.sha256(new).hexdigest()}"
                ),
            )
            install(names["reconcile"], service(f"{prefix} reconcile"))
            install(names["collect"], service(f"{python} {collector}"))
            install(names["check"], service(f"{prefix} check"))
            install(
                timer,
                f"[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=1s\nAccuracySec=100ms\nUnit={names['reconcile']}\n",
            )
            install(
                watcher, f"[Path]\nPathChanged={source}\nUnit={names['reconcile']}\n"
            )
            install(
                legacy,
                "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n",
            )
            ctl("daemon-reload")
            seal_result = subprocess.run(
                [
                    python,
                    "-m",
                    "phantomdocs.workflow_policy_environment",
                    "--output",
                    str(seal),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                env=runtime_env,
            )
            assert seal_result.returncode == 0, seal_result.stderr
            command = [python, "-m", MODULE, "--config", str(config_path)]
            inventory = {
                "schema_version": 1,
                "owner": "Disposable CI operator",
                "expires_utc": (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(),
                "manual_source_writes": "prohibited",
                "external_writers_reviewed": True,
                "retired_units": [legacy],
                "writers": [],
            }
            for role, unit in (
                ("publish", names["publish"]),
                ("reconcile", names["reconcile"]),
                ("prestart", names["bridge"]),
                ("collect", names["collect"]),
            ):
                definition = ctl("cat", unit).stdout.strip()
                inventory["writers"].append(
                    {
                        "role": role,
                        "unit": unit,
                        "owner": "Disposable CI operator",
                        "unit_sha256": hashlib.sha256(definition.encode()).hexdigest(),
                        "command": command + [role]
                        if role != "collect"
                        else [python, str(collector)],
                    }
                )
            inventory_path.write_text(json.dumps(inventory))
            config = {
                "schema_version": 1,
                "source": str(source),
                "destinations": [str(bridge), str(docs)],
                "policy_lock": str(lock),
                "resolver": str(resolver),
                "bridge_unit": names["bridge"],
                "organization": "sample-org",
                "python": python,
                "runtime_seal": str(seal),
                "runtime_seal_sha256": hashlib.sha256(seal.read_bytes()).hexdigest(),
                "inventory": str(inventory_path),
                "inventory_sha256": hashlib.sha256(
                    inventory_path.read_bytes()
                ).hexdigest(),
            }
            config_path.write_text(json.dumps(config))
            bootstrap = subprocess.run(
                [
                    *command,
                    "bootstrap",
                    "--bootstrap-source-sha256",
                    hashlib.sha256(old).hexdigest(),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=45,
                env=runtime_env,
            )
            assert bootstrap.returncode == 0, bootstrap.stdout + bootstrap.stderr
            ctl("start", legacy)
            audit = subprocess.run(
                [*command, "audit"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
                env=runtime_env,
            )
            assert audit.returncode == 2  # real active legacy writer blocks closure
            ctl("stop", legacy)
            ctl("start", names["bridge"], names["collect"])
            assert (root / "collected").read_text() == hashlib.sha256(old).hexdigest()

            # A real systemd start failure leaves a durable pending transaction.
            denied.touch()
            assert ctl("start", names["publish"], good=False).returncode != 0
            pending = lock.with_name("policy.lock.pending")
            assert pending.exists()
            assert ctl("start", names["collect"], good=False).returncode != 0
            wait_for(
                lambda: (
                    alerts.exists()
                    and names["publish"] in alerts.read_text()
                    and names["collect"] in alerts.read_text()
                )
            )
            denied.unlink()
            ctl("start", timer)
            wait_for(
                lambda: (
                    not pending.exists()
                    and ctl("is-active", names["bridge"], good=False).stdout.strip()
                    == "active"
                )
            )
            ctl("stop", timer)
            ctl("start", names["collect"], names["check"])
            assert (root / "collected").read_text() == hashlib.sha256(new).hexdigest()
            assert (root / "loaded").read_bytes() == new
            assert all(p.read_bytes() == new for p in (source, bridge, docs))
            assert {p: policy_permissions(p) for p in metadata} == metadata

            # Actual .path activation refuses a manual edit; it cannot bless it.
            ctl("start", watcher)
            source.write_bytes(old)
            wait_for(
                lambda: (
                    ctl(
                        "show", names["reconcile"], "--property=Result", "--value"
                    ).stdout.strip()
                    == "exit-code"
                )
            )
            assert bridge.read_bytes() == docs.read_bytes() == new
            assert (
                json.loads(lock.read_bytes())["sha256"]
                == hashlib.sha256(new).hexdigest()
            )
            assert ctl("start", names["check"], good=False).returncode != 0
            wait_for(lambda: names["check"] in alerts.read_text())

            # Successful execution without a delivery acknowledgement fails.
            (root / "bad-ack").touch()
            instance = f"{tag}-alert@{names['check']}.service"
            wait_for(
                lambda: (
                    ctl(
                        "show", instance, "--property=ActiveState", "--value"
                    ).stdout.strip()
                    == "inactive"
                )
            )
            assert ctl("start", instance, good=False).returncode != 0
            assert (
                ctl("show", instance, "--property=Result", "--value").stdout.strip()
                == "exit-code"
            )
        finally:
            # Generated names only. No enable/disable operations or host units.
            ctl("stop", watcher, timer, legacy, *names.values(), good=False)
            for path in installed:
                if path.name == alert_template:
                    continue
                ctl("reset-failed", path.name, good=False)
            for name in names.values():
                ctl("stop", f"{tag}-alert@{name}.service", good=False)
                ctl("reset-failed", f"{tag}-alert@{name}.service", good=False)
            for path in installed:
                assert path.parent == units_dir and path.name.startswith(tag + "-")
                path.unlink()
            ctl("daemon-reload")
