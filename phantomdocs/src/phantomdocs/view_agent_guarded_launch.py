"""Root-managed launcher which holds policy authority through reader readiness.

Run only from a root-controlled service with KillMode=control-group. The reader
itself runs under its configured unprivileged Unix account. Runtime policy
authorization remains the reader's responsibility after the startup lock ends.
"""

import argparse
import ctypes
import http.client
import json
import os
import signal
import stat
import subprocess  # nosec B404
import time
from pathlib import PurePosixPath

from phantomdocs.view_agent_startup import launch_protected
from phantomdocs.workflow_admission_config import _read_protected, _unique
from phantomdocs.workflow_protected_paths import protected_parent


def no_new_privileges():
    """Seal the root monitor after its sole unprivileged child is created.

    Some deployed systemd/seccomp combinations refuse UID transitions when
    no_new_privs was set before installing the address-family filter. The child
    independently seals itself with setpriv before executing any reader code.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(39, 0, 0, 0, 0) != 1:
        raise OSError(ctypes.get_errno(), "Cannot seal launcher privileges")


def http_ready(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        return response.status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def wait_ready(child, ready, *, seconds=20):
    """Reap a failed or unready child before releasing startup authority."""
    if type(seconds) is not int or not 1 <= seconds <= 60:
        raise ValueError("Bounded readiness interval required")
    deadline = time.monotonic() + seconds
    try:
        while child.poll() is None:
            if ready() and child.poll() is None:
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        raise RuntimeError("Reader did not become ready")
    except BaseException:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        raise


def prepare_runtime(config, directories, supplementary_groups):
    """Restore only explicitly owned /run socket directories after systemd setup.

    systemd creates RuntimeDirectory paths for the root launcher on every exec.
    The unprivileged reader needs ownership before binding. Persistent records
    must remain outside these disposable directories.
    """
    routes = [config, *config.get("additional_issuers", [])]
    expected = {str(PurePosixPath(route["socket_path"]).parent) for route in routes}
    if (
        not expected <= set(directories)
        or len(directories) != len(set(directories))
        or any(
            not path.startswith("/run/")
            or ".." in PurePosixPath(path).parts
            or str(PurePosixPath(path)) != path
            for path in directories
        )
    ):
        raise ValueError("Explicit owned runtime directories must cover every issuer")
    for route in routes:
        directory = str(PurePosixPath(route["socket_path"]).parent)
        if (
            not directory.startswith("/run/")
            or ".." in PurePosixPath(directory).parts
            or route["socket_group"] not in supplementary_groups
        ):
            raise ValueError("Owned runtime path and explicit reader group required")
        with protected_parent(directory) as (parent, name):
            fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            try:
                info = os.fstat(fd)
                if (
                    info.st_uid not in {0, config["reader_uid"]}
                    or stat.S_IMODE(info.st_mode) & 0o022
                ):
                    raise ValueError("Unsafe runtime directory ownership")
                os.fchown(fd, config["reader_uid"], route["socket_group"])
                # Reader-owned socket directory; group may traverse, never write.
                os.fchmod(fd, 0o750)  # nosec B103
                # systemd may recreate the runtime directory between pre-start
                # and main execution. Restore ACLs on the pinned inodes here.
                for target, acl in (
                    (parent, f"u:{route['issuer_uid']}:--x"),
                    (fd, f"u:{route['issuer_uid']}:--x,d:u:{route['issuer_uid']}:rw-"),
                ):
                    # Fixed executable, numeric ACLs and pinned directory inodes.
                    subprocess.run(  # nosec B603
                        [
                            "/usr/bin/setfacl",
                            "--modify",
                            acl,
                            f"/proc/self/fd/{target}",
                        ],
                        pass_fds=(target,),
                        check=True,
                        timeout=5,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
            finally:
                os.close(fd)


def main():
    import pwd

    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "org",
        "config",
        "journal",
        "committed",
        "policy-lock",
        "python",
        "reader",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--supplementary-group", action="append", type=int, default=[])
    parser.add_argument("--runtime-directory", action="append", default=[])
    args = parser.parse_args()
    if any(group <= 0 for group in args.supplementary_group):
        parser.error("Only explicit nonroot supplementary groups are allowed")
    if os.geteuid() != 0:
        parser.exit(1, "A root-managed launcher is required\n")
    children = []
    previous = {}

    def interrupted(signum, _frame):
        for child in children:
            if child.poll() is None:
                child.send_signal(signum)
        raise InterruptedError("Reader launcher stopped")

    def start_and_wait():
        # Read inside the lock, after checking the exact authority binding.
        config = json.loads(_read_protected(args.config), object_pairs_hook=_unique)
        uid = config.get("reader_uid")
        port = config.get("port")
        if (
            type(uid) is not int
            or uid <= 0
            or type(port) is not int
            or not 1024 <= port <= 65535
        ):
            raise ValueError("Unprivileged reader and bounded port required")
        account = pwd.getpwuid(uid)
        for directory in args.runtime_directory:
            if any(
                path.startswith(directory.rstrip("/") + "/")
                for path in (
                    args.config,
                    args.org,
                    args.journal,
                    args.committed,
                    args.policy_lock,
                )
            ):
                raise ValueError(
                    "Persistent authority must be outside disposable runtime paths"
                )
        prepare_runtime(config, args.runtime_directory, args.supplementary_group)
        environment = {
            "HOME": account.pw_dir,
            "PATH": "/usr/bin:/bin",
            "PYTHONNOUSERSITE": "1",
        }
        for name in (
            "PHANTOMVIEW_BOT_VERSION_CONFIG",
            "PHANTOMVIEW_ASSISTANT_CONFIG",
            "PHANTOMVIEW_MATRIX_ROUTES",
        ):
            if name in os.environ:
                environment[name] = os.environ[name]
        # Root-controlled reader paths; fixed setpriv wrapper and no shell.
        child = subprocess.Popen(  # nosec B603
            [
                "/usr/bin/setpriv",
                "--no-new-privs",
                args.python,
                "-B",
                args.reader,
                "--config",
                args.config,
            ],
            user=uid,
            group=account.pw_gid,
            extra_groups=sorted(
                set(os.getgrouplist(account.pw_name, account.pw_gid))
                | set(args.supplementary_group)
            ),
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
        )
        children.append(child)
        no_new_privileges()
        wait_ready(child, lambda: http_ready(port))
        return child

    try:
        for kind in (signal.SIGTERM, signal.SIGINT):
            previous[kind] = signal.signal(kind, interrupted)
        child = launch_protected(
            org_path=args.org,
            config_path=args.config,
            journal_path=args.journal,
            committed_path=args.committed,
            policy_lock=args.policy_lock,
            start_and_wait=start_and_wait,
        )
        return child.wait()
    except InterruptedError:
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError):
        return 1
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        for kind, handler in previous.items():
            signal.signal(kind, handler)


if __name__ == "__main__":
    raise SystemExit(main())
