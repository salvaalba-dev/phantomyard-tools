"""Disposable systemd test for the matrix host deadline and real flock waits."""

import os
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
