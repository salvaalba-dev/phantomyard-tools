"""Real systemd, protected profiles and wrappers; synthetic transport, no providers."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

from phantomdocs import notify_adapter

TEMPLATES = (
    Path(__file__).resolve().parents[1] / "contrib/bridge-policy/disabled-alerts"
)
ENABLED = os.environ.get("PHANTOM_POLICY_SYSTEMD_TRIAL") == "1"


def render(text, code, config, home):
    return (
        text.replace("/usr/local/lib/example-alerts", str(code))
        .replace("/etc/example-alerts", str(config))
        .replace("/home/example-user", str(home))
        .replace("User=example-user", "User=65534")
        .replace("Group=example-user", "Group=65534")
    )


def test_disabled_template_has_no_install_or_automatic_activation():
    text = (TEMPLATES / "example-policy-alert@.service.disabled").read_text()
    directives = [s for s in text.splitlines() if s and not s.startswith("#")]
    assert "[Install]" not in directives
    assert "User=example-user" in directives and "Group=example-user" in directives
    assert "ConditionPathExists=/etc/example-alerts/delivery-enabled" in directives
    assert not any(
        s.startswith(("OnFailure=", "WantedBy=", "RequiredBy=", "Wants=", "Requires="))
        for s in directives
    )


@pytest.mark.skipif(
    not ENABLED, reason="explicit disposable root/systemd trial required"
)
def test_disabled_wrappers_routes_and_real_unit_fail_closed_without_network():
    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    tag = "pd-disabled-alert-" + uuid.uuid4().hex
    unit = Path("/run/systemd/system") / (tag + "@.service")
    instance = tag + "@synthetic-failed.service.service"

    def ctl(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    with tempfile.TemporaryDirectory(prefix=tag, dir="/var/lib") as folder:
        root = Path(folder)
        root.chmod(0o711)
        code, config, ledger, home = (
            root / n for n in ("code", "config", "ledger", "home")
        )
        for path in (code, home):
            path.mkdir(mode=0o755)
        config.mkdir(mode=0o750)
        os.chown(config, 0, 65534)
        ledger.mkdir(mode=0o700)
        os.chown(ledger, 65534, 65534)
        for name in (
            "notify_adapter.py",
            "workflow_policy_alert.py",
            "workflow_policy_alert_routes.py",
        ):
            shutil.copyfile(Path(notify_adapter.__file__).with_name(name), code / name)
        # Replace only the provider-facing entry point. The reviewed config reader,
        # schema, root path checks, routing, wrapper exec and ledger remain real.
        (code / "synthetic_transport.py").write_text(
            "import argparse,json,os,sys\n"
            "from notify_adapter import read_runtime_config,validate_runtime,append_ledger\n"
            "p=argparse.ArgumentParser();p.add_argument('--runtime-config',required=True)\n"
            "r=read_runtime_config(p.parse_args().runtime_config);validate_runtime(r)\n"
            "e=json.load(sys.stdin)\n"
            "assert e['recipient']==r['telegram_chat' if e['channel']=='telegram' else 'mail_to']\n"
            "assert os.geteuid()==65534 and os.getegid()==65534\n"
            "assert os.environ['HOME']==" + repr(str(home)) + "\n"
            "assert not any(k.startswith(('GOOGLE_','PHANTOMBOT_','PYTHON')) or k=='VAULT_SENTINEL' for k in os.environ)\n"
            "append_ledger(r['ledger_path'],dict(channel=e['channel'],recipient=e['recipient'],message=e['message']))\n"
            "print(json.dumps(dict(delivered=True,recipient=e['recipient'],receipt='synthetic:accepted')))\n"
        )
        for name in ("notify-adapter", "deliver-policy-alert"):
            text = render(
                (TEMPLATES / (name + ".example")).read_text(), code, config, home
            )
            if name == "notify-adapter":
                text = text.replace("/notify_adapter.py", "/synthetic_transport.py")
            (code / name).write_text(text)
            (code / name).chmod(0o755)
        runtime = {
            "schema_version": 1,
            "data_dir": str(home),
            "config_path": str(home / "config.toml"),
            "ledger_path": str(ledger / "sends.jsonl"),
            "telegram_chat": "123456789",
            "mail_to": "operator@example.invalid",
            "workspace_send_args": notify_adapter.WORKSPACE_SEND_ARGS,
            "workspace_sha256": "a" * 64,
            "workspace_receipt": "message-id-line",
        }
        routes = {
            "schema_version": 1,
            "host": "synthetic.invalid",
            "telegram_chat": runtime["telegram_chat"],
            "mail_to": runtime["mail_to"],
            "telegram_handler": str(code / "notify-adapter"),
            "mail_handler": str(code / "notify-adapter"),
        }
        for name, data in (
            ("notify-runtime.json", runtime),
            ("alert-routes.json", routes),
        ):
            path = config / name
            path.write_text(json.dumps(data))
            os.chown(path, 0, 65534)
            path.chmod(0o640)
        unit_text = render(
            (TEMPLATES / "example-policy-alert@.service.disabled").read_text(),
            code,
            config,
            home,
        )
        # Network isolation is rehearsal-only; even an accidental provider call
        # cannot leave this disposable service's private network namespace.
        unit_text += (
            "\nPrivateNetwork=yes\nEnvironment=VAULT_SENTINEL=must-not-inherit\n"
        )
        marker = config / "delivery-enabled"
        receipt = ledger / "sends.jsonl"
        with unit.open("x") as stream:
            stream.write(unit_text)
        try:
            verified = subprocess.run(
                ["/usr/bin/systemd-analyze", "verify", str(unit)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert verified.returncode == 0, verified.stderr
            assert ctl("daemon-reload").returncode == 0
            assert ctl("is-enabled", instance).stdout.strip() == "static"
            # No marker: systemd skips, and direct invocation cannot bypass it.
            assert ctl("start", instance).returncode == 0
            assert (
                ctl("show", instance, "-p", "ConditionResult", "--value").stdout.strip()
                == "no"
            )
            assert not receipt.exists()
            for name in ("notify-adapter", "deliver-policy-alert"):
                result = subprocess.run(
                    [str(code / name)],
                    user=65534,
                    group=65534,
                    extra_groups=[],
                    input="{}",
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                assert result.returncode == 78 and "disabled" in result.stderr
            assert not receipt.exists()
            # This marker is only in the generated fixture, never a host profile.
            marker.touch(mode=0o600)
            result = ctl("start", instance)
            assert result.returncode == 0, (
                result.stderr + ctl("status", instance).stdout
            )
            rows = [json.loads(line) for line in receipt.read_text().splitlines()]
            assert [r["channel"] for r in rows] == ["telegram", "email"]
            assert all("unit=synthetic-failed.service" in r["message"] for r in rows)
            assert receipt.stat().st_uid == 65534
            assert receipt.stat().st_mode & 0o777 == 0o600
            before = receipt.read_bytes()
            # Group-readable runtime is accepted, world-readable runtime fails.
            (config / "notify-runtime.json").chmod(0o644)
            assert ctl("start", instance).returncode != 0
            assert receipt.read_bytes() == before
            assert (
                ctl("show", instance, "-p", "Result", "--value").stdout.strip()
                == "exit-code"
            )
            (config / "notify-runtime.json").chmod(0o640)
            # A user-controlled route parent cannot authorize either destination.
            os.chown(config, 65534, 65534)
            assert ctl("start", instance).returncode != 0
            assert receipt.read_bytes() == before
            os.chown(config, 0, 65534)
            # Non-root wrapper ownership is refused by the real handler guard.
            os.chown(code / "notify-adapter", 65534, 65534)
            assert ctl("start", instance).returncode != 0
            assert receipt.read_bytes() == before
            os.chown(code / "notify-adapter", 0, 0)
            # Removing the fixture gate leaves no armed service or queued retry.
            marker.unlink()
            assert ctl("start", instance).returncode == 0
            assert receipt.read_bytes() == before
        finally:
            ctl("stop", instance)
            ctl("reset-failed", instance)
            assert unit.parent == Path("/run/systemd/system") and unit.name.startswith(
                tag
            )
            unit.unlink()
            ctl("daemon-reload")
        assert not unit.exists()
        assert ctl("is-active", instance).stdout.strip() == "inactive"
