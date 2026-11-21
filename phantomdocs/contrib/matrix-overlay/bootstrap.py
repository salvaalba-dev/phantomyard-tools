"""Verify the Python runtime inventory before enabling third-party imports."""

import hashlib
import json
import os
import runpy
import stat
import sys
from itertools import dropwhile
from pathlib import Path

HERE = Path(__file__).parent
INTERPRETER = Path("/usr/bin/python3.12")
STDLIB = Path("/usr/lib/python3.12")
ZIP_SLOT = Path("/usr/lib/python312.zip")
SITES = (
    Path(
        "/opt/phantomdocs/matrix-releases/release-3ee74fe/lib/python3.12/site-packages"
    ),
    Path("/usr/local/lib/python3.12/dist-packages"),
    Path("/usr/lib/python3/dist-packages"),
)


def require_protected(path, metadata):
    if metadata.st_uid != 0 or (
        not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022
    ):
        raise ValueError(f"unprotected runtime entry: {path}")


def inventory(roots, files, absent):
    """Record every entry, including bytecode, package data and native extensions."""
    entries = {}

    def record(path, recurse=False, following=frozenset()):
        if path in following or not path.is_absolute() or ".." in path.parts:
            raise ValueError(f"invalid runtime path: {path}")
        for parent in reversed(path.parents):
            if parent not in entries:
                record(parent, following=following)
            if entries[parent]["type"] != "directory":
                raise ValueError(f"non-directory runtime ancestor: {parent}")
        meta = path.lstat()
        require_protected(path, meta)
        entry = {
            "uid": meta.st_uid,
            "gid": meta.st_gid,
            "mode": stat.S_IMODE(meta.st_mode),
        }
        if stat.S_ISLNK(meta.st_mode):
            target = os.readlink(path)
            parts = Path(target).parts
            if ".." in dropwhile(lambda part: part == "..", parts):
                raise ValueError(f"ambiguous runtime link: {path}")
            resolved = Path(os.path.abspath(path.parent / target))
            record(resolved, following=following | {path})
            if entries[resolved]["type"] not in {"file", "link"}:
                raise ValueError(f"runtime link is not a file: {path}")
            entry.update(type="link", target=target)
        elif stat.S_ISDIR(meta.st_mode):
            entry["type"] = "directory"
        elif stat.S_ISREG(meta.st_mode):
            with os.fdopen(
                os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
            ) as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or stamp(meta) != stamp(before):
                    raise ValueError(f"runtime entry changed: {path}")
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if stamp(before) != stamp(os.fstat(stream.fileno())):
                    raise ValueError(f"runtime entry changed: {path}")
            entry.update(type="file", sha256=digest)
        else:
            raise ValueError(f"unsupported runtime entry: {path}")
        entries[path] = entry
        if recurse:
            if entry["type"] != "directory":
                raise ValueError(f"invalid import root: {path}")
            for child in sorted(path.iterdir()):
                record(child, recurse=child.is_dir() and not child.is_symlink())

    for path in (*roots, *files, *absent):
        for parent in reversed(path.parents):
            if parent not in entries:
                record(parent)
            if entries[parent]["type"] != "directory":
                raise ValueError(f"non-directory runtime ancestor: {parent}")
    for path in absent:
        if os.path.lexists(path):
            raise ValueError(f"unexpected runtime path: {path}")
    for path in roots:
        record(path, recurse=True)
    for path in files:
        record(path)
    return {
        "version": 1,
        "entries": {str(path): value for path, value in entries.items()},
    }


def stamp(meta):
    return (
        meta.st_dev,
        meta.st_ino,
        meta.st_uid,
        meta.st_gid,
        meta.st_mode,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    )


def verify_manifest(path, roots, files, absent):
    # The reviewed manifest is a separate trust input, never regenerated at service start.
    inventory((), (path,), ())
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("runtime manifest must be a regular file")
    expected = json.loads(path.read_bytes())
    if expected != inventory(roots, files, absent):
        raise ValueError("runtime manifest differs from approved inventory")


def main():
    if (
        os.geteuid() != 0
        or not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.dont_write_bytecode
        or Path(sys.executable) != INTERPRETER
    ):
        raise ValueError("isolated system Python required")
    if sys.path != [str(ZIP_SLOT), str(STDLIB), str(STDLIB / "lib-dynload")]:
        raise ValueError("unexpected Python startup paths")
    roots = (STDLIB, *SITES)
    files = (
        INTERPRETER,
        HERE / "bootstrap.py",
        HERE / "launcher.py",
        HERE / "view_matrix_host.py",
    )
    if sys.argv[1:] == ["capture"]:
        print(json.dumps(inventory(roots, files, (ZIP_SLOT,)), sort_keys=True))
    elif not sys.argv[1:]:
        verify_manifest(HERE / "runtime-manifest.json", roots, files, (ZIP_SLOT,))
        sys.path.extend(map(str, SITES))
        runpy.run_path(str(HERE / "launcher.py"), run_name="__main__")
    else:
        raise ValueError("invalid runtime manifest command")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"matrix runtime preflight failed: {error}") from None
