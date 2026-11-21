"""Disposable systemd test for the matrix host deadline and real flock waits."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("PHANTOM_POLICY_SYSTEMD_TRIAL") != "1",
    reason="explicit disposable root/systemd rehearsal required",
)


@pytest.mark.skipif(getattr(os, "geteuid", lambda: -1)() != 0, reason="root required")
def test_manifest_checks_transitive_imports_before_running_launcher():
    repo = Path(__file__).resolve().parents[1]
    venv = Path(os.environ["PHANTOM_POLICY_TRIAL_PYTHON"]).parent.parent
    (installed_site,) = (venv / "lib").glob("python*/site-packages")
    with tempfile.TemporaryDirectory(
        prefix="pd-overlay-manifest-", dir="/var/lib"
    ) as tmp:
        root = Path(tmp)
        bootstrap = root / "bootstrap.py"
        shutil.copyfile(repo / "contrib/matrix-overlay/bootstrap.py", bootstrap)
        site = root / "site"
        site.mkdir()
        dependency = site / "dependency.py"
        dependency.write_text("VALUE = 1\n")
        (site / "direct.py").write_text("from dependency import VALUE\n")
        (site / "startup.pth").write_text("import sys; sys.exit(99)\n")
        subprocess_path = root / "entry.py"
        subprocess_path.write_text(
            "import runpy, sys\n"
            "from pathlib import Path\n"
            f"main = runpy.run_path({str(bootstrap)!r})['main']\n"
            f"main.__globals__.update(SITES=(Path({str(site)!r}), Path({str(installed_site)!r})))\n"
            "main()\n"
        )
        (root / "launcher.py").write_text(
            "from phantomdocs import view_matrix_host\n"
            "from direct import VALUE\n"
            "assert callable(view_matrix_host.main)\n"
            "print(VALUE)\n"
        )
        (root / "view_matrix_host.py").write_text("# fixture payload\n")
        command = ["/usr/bin/python3.12", "-I", "-S", "-B", str(subprocess_path)]

        def run(*args):
            return subprocess.run(
                [*command, *args],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        captured = run("capture")
        assert captured.returncode == 0, captured.stderr
        (root / "runtime-manifest.json").write_text(captured.stdout)
        valid = run()
        assert valid.returncode == 0, valid.stderr
        assert valid.stdout.strip() == "1"

        dependency.write_text("VALUE = 2\n")
        changed = run()
        assert changed.returncode != 0
        assert "differs from approved inventory" in changed.stderr
        assert not changed.stdout
        dependency.write_text("VALUE = 1\n")
        added = site / "unreviewed.py"
        added.touch()
        assert run().returncode != 0
        added.unlink()
        dependency.chmod(0o666)
        assert "unprotected runtime entry" in run().stderr
        dependency.chmod(0o644)
        dependency.rename(site / "target.py")
        dependency.symlink_to("target.py")
        assert "differs from approved inventory" in run().stderr


@pytest.mark.skipif(getattr(os, "geteuid", lambda: -1)() != 0, reason="root required")
@pytest.mark.parametrize(
    "early_override", [False, True], ids=["example-name", "early-name"]
)
def test_overlay_dropin_verifies_with_systemd(early_override):
    repo = Path(__file__).resolve().parents[1]
    (example,) = (repo / "contrib/matrix-overlay").glob("*.conf.example")
    installed_name = example.stem
    overlay_name = f"10-{installed_name}" if early_override else installed_name
    dropin = example.read_text()
    expected = (
        "ExecStart=/usr/bin/python3.12 "
        "-I -S -B /usr/local/lib/phantomdocs-matrix-pr72/bootstrap.py"
    )
    assert dropin.count("ExecStart=\n") == 1
    assert expected in dropin
    assert "Environment=PYTHONPATH=\n" in dropin
    name = "pd-overlay-verify-" + uuid.uuid4().hex + ".service"
    unit = Path("/run/systemd/system") / name
    directory = unit.parent / (name + ".d")

    def command(*args):
        return subprocess.run(
            list(args), capture_output=True, text=True, timeout=30, check=False
        )

    with tempfile.TemporaryDirectory(
        prefix="pd-overlay-verify-", dir="/var/lib"
    ) as tmp:
        launcher = Path(tmp) / "launcher.py"
        launcher.write_text("pass\n")
        assert launcher.is_file()
        actual = f"ExecStart=/usr/bin/python3 -I -S -B {launcher}"
        assert not unit.exists() and not directory.exists()
        try:
            unit.write_text("[Service]\nType=oneshot\nExecStart=/usr/bin/true\n")
            directory.mkdir(mode=0o755)
            (directory / "release-3ee74fe.conf").write_text(
                "[Service]\nExecStart=\nExecStart=/usr/bin/false\n"
            )
            (directory / overlay_name).write_text(dropin.replace(expected, actual))
            result = command("/usr/bin/systemd-analyze", "verify", str(unit))
            assert result.returncode == 0, result.stderr
            assert command("/usr/bin/systemctl", "daemon-reload").returncode == 0
            result = command(
                "/usr/bin/systemctl", "show", name, "--property=ExecStart", "--value"
            )
            assert result.returncode == 0, result.stderr
            effective = result.stdout
            assert "/usr/bin/true" not in effective
            if early_override:
                assert "argv[]=/usr/bin/false ;" in effective
                assert str(launcher) not in effective
            else:
                assert f"argv[]=/usr/bin/python3 -I -S -B {launcher} ;" in effective
                assert "/usr/bin/false" not in effective
        finally:
            for item in ("release-3ee74fe.conf", overlay_name):
                (directory / item).unlink(missing_ok=True)
            if directory.exists():
                directory.rmdir()
            unit.unlink(missing_ok=True)
            command("/usr/bin/systemctl", "daemon-reload")


@pytest.mark.parametrize("deadline,unit_timeout", [(1, 5), (55, 65)])
def test_overlay_loader_with_real_systemd_and_contended_lock(deadline, unit_timeout):
    import fcntl

    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    python = Path(os.environ["PHANTOM_POLICY_TRIAL_PYTHON"])
    base = python.parent.parent
    package = base / "lib/python3.12/site-packages/phantomdocs"
    if not package.exists():
        package = next((base / "lib").glob("python*/site-packages/phantomdocs"))
    repo = Path(__file__).resolve().parents[1]
    name = "pd-matrix-overlay-" + uuid.uuid4().hex + ".service"
    unit = Path("/run/systemd/system") / name

    def ctl(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            text=True,
            timeout=75,
            check=False,
        )

    with tempfile.TemporaryDirectory(prefix="pd-overlay-", dir="/var/lib") as tmp:
        root = Path(tmp)
        loader = root / "launcher.py"
        payload = root / "view_matrix_host.py"
        shutil.copyfile(repo / "contrib/matrix-overlay/launcher.py", loader)
        shutil.copyfile(repo / "contrib/matrix-overlay/view_matrix_host.py", payload)
        for file in (loader, payload):
            file.chmod(0o600)
        config, first, second, marker = (
            root / x for x in ("config", "first", "second", "held")
        )
        for file in (config, first, second):
            file.touch(mode=0o600)

        def sha(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()

        script = root / "trial.py"
        script.write_text(
            "import fcntl, importlib.util, os, sys\n"
            "from pathlib import Path\n"
            f'spec=importlib.util.spec_from_file_location("candidate", {str(loader)!r})\n'
            "candidate=importlib.util.module_from_spec(spec); spec.loader.exec_module(candidate)\n"
            "def blocked(conn, config):\n"
            f'    with open({str(first)!r}, "r+") as a, open({str(second)!r}, "r+") as b:\n'
            "        fcntl.flock(a, fcntl.LOCK_EX)\n"
            f"        Path({str(marker)!r}).touch()\n"
            "        fcntl.flock(b, fcntl.LOCK_EX)\n"
            "def trace(frame, event, arg):\n"
            f'    if event == "call" and frame.f_code.co_name == "main" and frame.f_globals.get("__file__") == {str(payload)!r}:\n'
            f'        g=frame.f_globals; g["REQUEST_DEADLINE_SECONDS"]={deadline}\n'
            '        g["load_config"]=lambda path: {}\n'
            '        g["socket"].socket=lambda fileno: (os.close(fileno) or object())\n'
            '        g["serve_configured"]=blocked; sys.settrace(None)\n'
            "    return trace\n"
            "sys.settrace(trace)\n"
            f"candidate.run(Path({str(base)!r}), Path({str(package)!r}), Path({str(payload)!r}), {str(config)!r}, "
            f"{sha(package / 'view_matrix_host.py')!r}, {sha(package / 'workflow_policy_guard.py')!r}, {sha(payload)!r})\n"
        )
        script.chmod(0o600)
        assert not unit.exists()
        try:
            unit.write_text(
                f"[Service]\nType=oneshot\nExecStart={python} -I -B {script}\nTimeoutStartSec={unit_timeout}\n"
            )
            assert ctl("daemon-reload").returncode == 0
            with second.open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                started = ctl("start", name)
                assert started.returncode != 0
                assert marker.exists(), started.stderr
                assert (
                    ctl("show", name, "--property=Result", "--value").stdout.strip()
                    == "exit-code"
                )
                with first.open("r+") as released:
                    fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            ctl("stop", name)
            ctl("reset-failed", name)
            unit.unlink(missing_ok=True)
            ctl("daemon-reload")


def test_overlay_rejects_writable_or_symlinked_paths():
    import importlib.util

    assert sys.platform == "linux" and os.geteuid() == 0
    repo = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "overlay_trial", repo / "contrib/matrix-overlay/launcher.py"
    )
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    with tempfile.TemporaryDirectory(prefix="pd-overlay-mode-", dir="/var/lib") as tmp:
        root = Path(tmp)
        item = root / "payload"
        item.write_bytes(b"fixture")
        item.chmod(0o600)
        loader.protected(item)
        subprocess.run(["/usr/bin/setfacl", "-m", "u:65534:rw", str(item)], check=True)
        with pytest.raises(ValueError):
            loader.protected(item)
        subprocess.run(["/usr/bin/setfacl", "-b", str(item)], check=True)
        item.chmod(0o620)
        with pytest.raises(ValueError):
            loader.protected(item)
        item.chmod(0o600)
        link = root / "link"
        link.symlink_to(item)
        with pytest.raises(ValueError):
            loader.protected(link)
        root.chmod(0o770)
        with pytest.raises(ValueError):
            loader.protected(item)
        root.chmod(0o700)


def test_systemd_deadline_releases_lock_and_runs_synthetic_failure_handler():
    import fcntl

    assert sys.platform == "linux" and os.geteuid() == 0
    assert Path("/proc/1/comm").read_text().strip() == "systemd"
    python = Path(os.environ["PHANTOM_POLICY_TRIAL_PYTHON"])
    assert python.is_absolute() and python.name == "python"
    prefix = "pd-matrix-deadline-" + uuid.uuid4().hex
    unit = Path("/run/systemd/system") / (prefix + ".service")
    failure = Path("/run/systemd/system") / (prefix + "-failure.service")

    def ctl(*args):
        return subprocess.run(
            ["/usr/bin/systemctl", "--no-pager", *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    with tempfile.TemporaryDirectory(prefix=prefix, dir="/var/lib") as temp:
        root = Path(temp)
        first, second = root / "policy.lock", root / "manifest.lock"
        first.touch()
        second.touch()
        held_marker = root / "held"
        failure_marker = root / "failure"
        script = root / "host.py"
        script.write_text(
            "import fcntl, os, sys\n"
            "from pathlib import Path\n"
            "from phantomdocs import view_matrix_host as host\n"
            "host.REQUEST_DEADLINE_SECONDS = 1\n"
            "host.load_config = lambda path: {}\n"
            "host.socket.socket = lambda fileno: (os.close(fileno) or object())\n"
            "def blocked(connection, config):\n"
            f"    with open({str(first)!r}, 'r+') as a, open({str(second)!r}, 'r+') as b:\n"
            "        fcntl.flock(a, fcntl.LOCK_EX)\n"
            f"        Path({str(held_marker)!r}).touch()\n"
            "        fcntl.flock(b, fcntl.LOCK_EX)\n"
            "host.serve_configured = blocked\n"
            "sys.argv = ['matrix-host', '--config', '/unused']\n"
            "host.main()\n"
        )
        sink = root / "failure.py"
        sink.write_text(
            f"from pathlib import Path\nPath({str(failure_marker)!r}).touch()\n"
        )
        assert not unit.exists() and not failure.exists()
        try:
            unit.write_text(
                f"[Unit]\nOnFailure={failure.name}\n"
                f"[Service]\nType=oneshot\nExecStart={python} -B {script}\n"
                "TimeoutStartSec=5\n"
            )
            failure.write_text(
                f"[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B {sink}\n"
            )
            assert ctl("daemon-reload").returncode == 0
            with second.open("r+") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                started = ctl("start", unit.name)
                assert started.returncode != 0
                assert held_marker.exists()
                result = ctl("show", unit.name, "--property=Result", "--value")
                assert result.stdout.strip() == "exit-code"
                with first.open("r+") as released:
                    fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for _ in range(50):
                    if failure_marker.exists():
                        break
                    time.sleep(0.1)
                assert failure_marker.exists(), "synthetic OnFailure did not run"
        finally:
            ctl("stop", unit.name, failure.name)
            ctl("reset-failed", unit.name, failure.name)
            for item in (unit, failure):
                assert item.parent == Path("/run/systemd/system")
                assert item.name.startswith("pd-matrix-deadline-")
                item.unlink(missing_ok=True)
            ctl("daemon-reload")
