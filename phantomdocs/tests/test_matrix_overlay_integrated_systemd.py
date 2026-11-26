"""Full overlay process rehearsal on disposable CI, with synthetic authority.

This exercises real peer credentials and broker framing, not viewer HTTP sessions
or production native-policy/worker integrations. Never run it on an operational host.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("PHANTOM_POLICY_SYSTEMD_TRIAL") != "1"
    or not os.environ.get("PHANTOM_POLICY_TRIAL_PYTHON")
    or os.environ.get("GITHUB_ACTIONS") != "true",
    reason="explicit disposable GitHub Actions root/systemd trial required",
)

SHIM = """
import fcntl
from contextlib import contextmanager
from pathlib import Path
from phantomdocs import view_matrix_broker as broker

def serve(connection, config):
    root = Path(config['workspace'])
    (root / 'entered').touch()
    if (root / 'mode').read_text() == 'block':
        with (root / 'first').open('r+') as first, (root / 'second').open('r+') as second:
            fcntl.flock(first, fcntl.LOCK_EX)
            (root / 'held').touch()
            fcntl.flock(second, fcntl.LOCK_EX)
    @contextmanager
    def authority(actor):
        with (root / 'first').open('r+') as first:
            fcntl.flock(first, fcntl.LOCK_EX)
            yield {}, {}, lambda ref, limit: b'synthetic'
    def read_matrix(**kwargs):
        if kwargs['version'] != 'v1':
            raise ValueError('unknown synthetic version')
        return 'synthetic matrix'
    broker.read_matrix = read_matrix
    broker.serve(connection, client_uid=config['client_uid'], actor=config['actor'],
                 binding={}, authority=authority)
"""

CLIENT = """
import socket,sys
with socket.socket(socket.AF_UNIX) as connection:
    connection.settimeout(70)
    connection.connect(sys.argv[1])
    connection.sendall(b'{"version":"v1"}\\n')
    response=bytearray()
    try:
        while not response.endswith(b'\\n'):
            chunk=connection.recv(1)
            if not chunk: break
            response.extend(chunk)
        if b'"matrix"' in response: connection.sendall(b'delivered\\n')
    except ConnectionResetError: pass
    print(response.decode().strip())
"""


def test_full_bootstrap_socket_deadline_drift_and_rollback(capsys):
    import fcntl

    assert os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    python = "/usr/bin/python3.12"
    source = Path(__file__).resolve().parents[1] / "contrib/matrix-overlay"
    installed = Path(os.environ["PHANTOM_POLICY_TRIAL_PYTHON"]).parent.parent
    (installed_site,) = (installed / "lib").glob("python*/site-packages")
    prefix = "pd-integrated-" + uuid.uuid4().hex
    unit_root = Path("/run/systemd/system")
    service = unit_root / (prefix + "@.service")
    socket_unit = unit_root / (prefix + ".socket")
    dropins = unit_root / (service.name + ".d")

    def command(*args, timeout=80):
        return subprocess.run(
            list(args), capture_output=True, text=True, timeout=timeout, check=False
        )

    def ctl(*args):
        result = command("/usr/bin/systemctl", "--no-pager", *args)
        assert result.returncode == 0, result.stderr
        return result.stdout

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def wait_idle():
        for _ in range(200):
            units = ctl(
                "list-units",
                "--state=activating,active,deactivating",
                "--no-legend",
                "--plain",
                prefix + "@*.service",
            )
            if not units.strip():
                return
            time.sleep(0.05)
        pytest.fail("request process did not exit")

    with tempfile.TemporaryDirectory(prefix=prefix, dir="/var/lib") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        base = root / "runtime"
        site = base / "lib/python3.12/site-packages"
        shutil.copytree(installed_site, site)
        (base / "bin").mkdir()
        package = site / "phantomdocs"
        overlay = root / "overlay"
        overlay.mkdir()
        state = root / "state"
        state.mkdir()
        for name in ("first", "second"):
            (state / name).touch(mode=0o600)
        (state / "mode").write_text("normal")
        (site / "trial_shim.py").write_text(SHIM)
        (site / "never-run.pth").write_text("import sys; sys.exit(99)\n")
        dependency = site / "trial-data"
        dependency.write_text("approved\n")
        (site / "trial-link").symlink_to("trial-data")
        config = root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "actor": "synthetic-agent",
                    "client_uid": 65534,
                    "agent_uid": 65534,
                    "agent_gid": 65534,
                    "agent_home": str(state),
                    "workspace": str(state),
                    "python": python,
                    "pythonpath": str(site),
                    "policy_lock": str(state / "first"),
                    "org_path": str(state / "org"),
                    "native_manifest": str(state / "catalog"),
                    "binding": {
                        "versions": {},
                        "root_ref": "gdrive://rootfolder1",
                        "domain": "synthetic",
                        "project_type": "project",
                    },
                }
            )
        )
        config.chmod(0o600)
        payload = overlay / "view_matrix_host.py"
        shutil.copyfile(source / payload.name, payload)
        launcher = (source / "launcher.py").read_text()
        substitutions = {
            'Path("/opt/phantomdocs/matrix-releases/release-3ee74fe")': f"Path({str(base)!r})",
            'Path("/usr/local/lib/phantomdocs-matrix-pr72/view_matrix_host.py")': f"Path({str(payload)!r})",
            '"/etc/phantomdocs/matrix-release-3ee74fe.json"': repr(str(config)),
            "72a525d657f1b1abb09a5ca8cc5f5d8156d74bbca09f5fdab111c35f755072ec": digest(
                package / "view_matrix_host.py"
            ),
            "b47d905e48080ac000d2d16bb45e3f0d9780c9777f1402a506bf3e56ecacb0db": digest(
                package / "workflow_policy_guard.py"
            ),
        }
        for old, new in substitutions.items():
            assert launcher.count(old) == 1
            launcher = launcher.replace(old, new)
        (overlay / "launcher.py").write_text(launcher)
        bootstrap = overlay / "bootstrap.py"
        shutil.copyfile(source / bootstrap.name, bootstrap)
        entry = site / "trial_entry.py"
        entry.write_text(
            "import runpy,sys\nfrom pathlib import Path\n"
            f"payload={str(payload)!r}\n"
            "def trace(frame,event,arg):\n"
            "    if event=='call' and frame.f_code.co_name=='main' and frame.f_globals.get('__file__')==payload:\n"
            "        from trial_shim import serve\n"
            "        frame.f_globals['serve_configured']=serve\n"
            "        sys.settrace(None)\n"
            "    return trace\n"
            "sys.settrace(trace)\n"
            f"cli=runpy.run_path({str(bootstrap)!r})['cli']\n"
            f"cli.__globals__['SITES']=(Path({str(site)!r}),)\n"
            "cli()\n"
        )
        invocation = [python, "-I", "-S", "-B", str(entry)]
        captured = command(*invocation, "capture")
        assert captured.returncode == 0, captured.stderr
        manifest = overlay / "runtime-manifest.json"
        manifest.write_text(captured.stdout)
        manifest.chmod(0o600)
        approved = manifest.read_bytes()
        baseline = root / "baseline.py"
        baseline.write_text(
            "import os,socket\n"
            "with socket.socket(fileno=os.dup(0)) as s:\n"
            " s.recv(256); s.sendall(b'baseline\\n')\n"
        )
        service_bytes = (
            f"[Service]\nType=oneshot\nExecStart={python} -I -S -B {baseline}\n"
            "StandardInput=socket\nStandardOutput=journal\nTimeoutStartSec=65\n"
        ).encode()
        address = root / "matrix.sock"
        socket_bytes = (
            f"[Socket]\nListenStream={address}\nAccept=yes\nSocketMode=0666\n"
        ).encode()

        def request(uid=65534):
            started = time.monotonic()
            result = subprocess.run(
                [python, "-I", "-S", "-B", "-c", CLIENT, str(address)],
                user=uid,
                group=uid,
                extra_groups=[],
                capture_output=True,
                text=True,
                timeout=75,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            wait_idle()
            return result.stdout.strip(), time.monotonic() - started

        try:
            assert (
                not service.exists()
                and not socket_unit.exists()
                and not dropins.exists()
            )
            service.write_bytes(service_bytes)
            socket_unit.write_bytes(socket_bytes)
            dropins.mkdir()
            retained = dropins / "90-synthetic-alert.conf"
            retained.write_text("[Unit]\nDescription=Synthetic retained drop-in\n")
            retained_bytes = retained.read_bytes()
            baseline_metadata = {
                path: (
                    path.stat().st_uid,
                    path.stat().st_gid,
                    path.stat().st_mode,
                    {k: os.getxattr(path, k) for k in os.listxattr(path)},
                )
                for path in (service, socket_unit, retained)
            }
            unrelated = root / "unrelated-state"
            unrelated.write_text("concurrent synthetic state\n")
            ctl("daemon-reload")
            ctl("start", socket_unit.name)
            assert request()[0] == "baseline"
            override = dropins / "zz-pr72.conf"
            example = (source / "zz-pr72.conf.example").read_text()
            override.write_text(
                example.replace(
                    "/usr/local/lib/phantomdocs-matrix-pr72/bootstrap.py", str(entry)
                )
            )
            ctl("daemon-reload")
            effective = ctl(
                "show", prefix + "@inspect.service", "-p", "ExecStart", "--value"
            )
            assert f"-I -S -B {entry}" in effective
            assert request()[0] == '{"matrix": "synthetic matrix"}'
            assert request(uid=0)[0] == '{"error":"matrix unavailable"}'
            assert (state / "entered").exists()

            def refused():
                (state / "entered").unlink(missing_ok=True)
                response, _ = request()
                assert "synthetic matrix" not in response
                assert not (state / "entered").exists()

            original = dependency.read_bytes()
            dependency.write_text("tampered\n")
            refused()
            dependency.write_bytes(original)
            dependency.chmod(0o666)
            refused()
            dependency.chmod(0o644)
            subprocess.run(["setfacl", "-m", "u:65534:rw", str(dependency)], check=True)
            refused()
            subprocess.run(["setfacl", "-b", str(dependency)], check=True)
            added = site / "unapproved.py"
            added.touch()
            refused()
            added.unlink()
            link = site / "trial-link"
            link.unlink()
            link.symlink_to("trial_shim.py")
            refused()
            link.unlink()
            link.symlink_to("trial-data")
            manifest.write_text('{"version":1}')
            refused()
            manifest.write_bytes(approved)
            assert request()[0] == '{"matrix": "synthetic matrix"}'

            stale = json.loads(approved)
            for stamp in stale["stamps"].values():
                stamp[1] += 1
            manifest.write_text(json.dumps(stale))
            verified = command(*invocation, "verify")
            assert verified.returncode == 0, verified.stderr
            report = json.loads(verified.stdout)
            assert report["hashed"] == len(stale["stamps"])
            assert report["reused"] == 0
            (state / "mode").write_text("block")
            with (state / "second").open("r+") as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                response, elapsed = request()
                assert response == ""
                assert (state / "held").exists()
                # The unit timeout is 65s; systemd signals at that point but a
                # loaded runner can take seconds to reap it, so the ceiling is
                # loose on purpose. The bound that matters is the floor: the
                # request must not return before the timeout fires.
                assert 55 <= elapsed < 80
                failed = ctl(
                    "list-units",
                    "--failed",
                    "--no-legend",
                    "--plain",
                    prefix + "@*.service",
                )
                assert failed.strip()
                for line in failed.splitlines():
                    name = line.split()[0]
                    assert (
                        ctl("show", name, "-p", "Result", "--value").strip()
                        == "exit-code"
                    )
                with (state / "first").open("r+") as released:
                    fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with capsys.disabled():
                print(
                    f"Full bootstrap forced rehash + 55s contention: {elapsed:.3f}s; kill-lag={max(0.0, elapsed - 65):.3f}s; files={report['hashed']}"
                )
            (state / "mode").write_text("normal")
            manifest.write_bytes(approved)
            assert request()[0] == '{"matrix": "synthetic matrix"}'
            ctl("stop", socket_unit.name)
            address.unlink(missing_ok=True)
            ctl("start", socket_unit.name)
            assert request()[0] == '{"matrix": "synthetic matrix"}'
            assert request(uid=0)[0] == '{"error":"matrix unavailable"}'

            override.unlink()
            ctl("daemon-reload")
            assert service.read_bytes() == service_bytes
            assert socket_unit.read_bytes() == socket_bytes
            assert retained.read_bytes() == retained_bytes
            for path, metadata in baseline_metadata.items():
                assert (
                    path.stat().st_uid,
                    path.stat().st_gid,
                    path.stat().st_mode,
                    {k: os.getxattr(path, k) for k in os.listxattr(path)},
                ) == metadata
            assert unrelated.read_text() == "concurrent synthetic state\n"
            assert str(baseline) in ctl(
                "show", prefix + "@inspect.service", "-p", "ExecStart", "--value"
            )
            assert request()[0] == "baseline"
        finally:
            command(
                "/usr/bin/systemctl", "stop", socket_unit.name, prefix + "@*.service"
            )
            command("/usr/bin/systemctl", "reset-failed", prefix + "@*.service")
            for path in dropins.glob("*"):
                path.unlink()
            if dropins.exists():
                dropins.rmdir()
            service.unlink(missing_ok=True)
            socket_unit.unlink(missing_ok=True)
            command("/usr/bin/systemctl", "daemon-reload")
