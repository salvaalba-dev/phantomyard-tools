"""Load only the reviewed matrix host from an isolated overlay.

This is a deployment candidate, not an installer. The release, config, payload
and all their parent directories must be root-controlled before it is used.
"""

import hashlib
import importlib.util
import os
import stat
import sys
from pathlib import Path

BASE = Path("/opt/phantomdocs/matrix-releases/release-3ee74fe")
PACKAGE = BASE / "lib/python3.12/site-packages/phantomdocs"
PAYLOAD = Path("/usr/local/lib/phantomdocs-matrix-pr72/view_matrix_host.py")
CONFIG = "/etc/phantomdocs/matrix-release-3ee74fe.json"
BASE_HOST_SHA256 = "72a525d657f1b1abb09a5ca8cc5f5d8156d74bbca09f5fdab111c35f755072ec"
BASE_GUARD_SHA256 = "b47d905e48080ac000d2d16bb45e3f0d9780c9777f1402a506bf3e56ecacb0db"
PAYLOAD_SHA256 = "6f4033e18173bf63c28b87a397b6cd74c63c0ce415a3de52f82c74a46de8b870"


def protected(path, directory=False):
    """Reject links and untrusted owners or writable filesystem ancestors."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("unprotected matrix path")
    for part in (path, *path.parents):
        meta = part.lstat()
        is_directory = part != path or directory
        if (
            meta.st_uid != 0
            or meta.st_mode & 0o022
            or (
                not stat.S_ISDIR(meta.st_mode)
                if is_directory
                else not stat.S_ISREG(meta.st_mode)
            )
        ):
            raise ValueError("unprotected matrix path")


def protected_file(meta):
    return meta.st_uid == 0 and not meta.st_mode & 0o022 and stat.S_ISREG(meta.st_mode)


def protected_package(package):
    for parent, dirs, files in os.walk(package, followlinks=False):
        for name in dirs:
            protected(Path(parent) / name, directory=True)
        for name in files:
            protected(Path(parent) / name)


def protected_config(config):
    protected(config)
    if stat.S_IMODE(config.lstat().st_mode) != 0o600:
        raise ValueError("unprotected matrix configuration")


def checked_bytes(path, expected):
    protected(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not protected_file(meta):
            raise ValueError("unprotected matrix file")
        data = stream.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("matrix runtime integrity check failed")
    return data


def run(base, package, payload, config, host_hash, guard_hash, payload_hash):
    protected(base, directory=True)
    protected(package, directory=True)
    protected_config(Path(config))
    protected(Path(__file__))
    protected(base / "bin", directory=True)
    protected(Path(sys.executable).resolve())
    protected_package(package)
    if Path(sys.prefix).resolve() != base.resolve():
        raise ValueError("unexpected matrix interpreter")
    checked_bytes(package / "view_matrix_host.py", host_hash)
    checked_bytes(package / "workflow_policy_guard.py", guard_hash)
    source = checked_bytes(payload, payload_hash)
    protected(package / "__init__.py")
    if not isolated_python():
        raise ValueError("isolated Python required")
    import phantomdocs

    if Path(phantomdocs.__file__).resolve() != (package / "__init__.py").resolve():
        raise ValueError("unexpected matrix package")
    # Compile the verified bytes, not a second read of the path.
    spec = importlib.util.spec_from_loader("phantomdocs.view_matrix_host", loader=None)
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(payload)
    sys.modules[spec.name] = module
    exec(compile(source, str(payload), "exec"), module.__dict__)  # noqa: S102
    sys.argv = [str(payload), "--config", config]
    module.main()


def isolated_python():
    return sys.flags.isolated


def main():
    if os.name != "posix" or os.geteuid() != 0 or len(sys.argv) != 1:
        raise SystemExit("matrix overlay unavailable")
    try:
        run(
            BASE,
            PACKAGE,
            PAYLOAD,
            CONFIG,
            BASE_HOST_SHA256,
            BASE_GUARD_SHA256,
            PAYLOAD_SHA256,
        )
    except (OSError, ValueError, ImportError):
        raise SystemExit("matrix overlay unavailable") from None


if __name__ == "__main__":
    main()
