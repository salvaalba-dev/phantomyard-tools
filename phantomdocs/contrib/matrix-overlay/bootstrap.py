"""Verify the Python runtime inventory before enabling third-party imports."""

import errno
import hashlib
import json
import os
import runpy
import stat
import sys
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


def acl_metadata(path):
    result = {}
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            result[name] = os.getxattr(path, name, follow_symlinks=False).hex()
        except OSError as error:
            if error.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise
    return result


def inventory(roots, files, absent, approved=None):
    """Record every entry, including bytecode, package data and native extensions."""
    entries = {}
    stamps = {}
    scanned = set()
    active = set()
    rehashed = []
    reused = hashed = 0

    def check_parent(path):
        parent = os.path.dirname(path)
        if parent == path:
            return
        if parent not in entries:
            record(parent)
        if entries[parent]["type"] != "directory":
            raise ValueError(f"non-directory runtime ancestor: {parent}")

    def scan(path):
        if path in scanned:
            return
        active.add(path)
        try:
            with os.scandir(path) as children:
                for child in children:
                    record(child.path, recurse=True, metadata=child)
            scanned.add(path)
        finally:
            active.remove(path)

    def record(path, recurse=False, metadata=None):
        nonlocal reused, hashed
        if path in active:
            raise ValueError(f"invalid runtime path: {path}")
        if path in entries:
            if recurse and entries[path]["type"] == "directory":
                scan(path)
            return
        check_parent(path)
        meta = metadata.stat(follow_symlinks=False) if metadata else os.lstat(path)
        require_protected(path, meta)
        entry = {
            "uid": meta.st_uid,
            "gid": meta.st_gid,
            "mode": stat.S_IMODE(meta.st_mode),
        }
        if stat.S_ISLNK(meta.st_mode):
            target = os.readlink(path)
            parts = [part for part in target.split("/") if part not in {"", "."}]
            if target.startswith("/") and ".." in parts:
                raise ValueError(f"ambiguous runtime link: {path}")
            while parts and parts[0] == "..":
                parts.pop(0)
            if not parts or ".." in parts:
                raise ValueError(f"ambiguous runtime link: {path}")
            resolved = os.path.abspath(os.path.join(os.path.dirname(path), target))
            active.add(path)
            try:
                record(resolved, recurse=True)
            finally:
                active.remove(path)
            entry.update(type="link", target=target)
        elif stat.S_ISDIR(meta.st_mode):
            entry["type"] = "directory"
        elif stat.S_ISREG(meta.st_mode):
            current = stamps[path] = stamp(meta)
            previous = approved["entries"].get(path, {}) if approved else {}
            if not isinstance(previous, dict):
                raise ValueError(f"invalid runtime manifest entry: {path}")
            if (
                previous.get("type") == "file"
                and approved["stamps"].get(path) == current
            ):
                digest = previous.get("sha256")
                acl = previous.get("acl")
                if not isinstance(digest, str) or not isinstance(acl, dict):
                    raise ValueError(f"invalid runtime manifest entry: {path}")
                entry["acl"] = acl
                reused += 1
            else:
                digest = file_hash(path, current)
                hashed += 1
                if approved is not None:
                    rehashed.append(path)
            entry.update(type="file", sha256=digest)
        else:
            raise ValueError(f"unsupported runtime entry: {path}")
        if "acl" not in entry:
            entry["acl"] = acl_metadata(path)
        entries[path] = entry
        if recurse and entry["type"] == "directory":
            scan(path)

    roots, files, absent = (
        tuple(map(os.fspath, paths)) for paths in (roots, files, absent)
    )
    for path in (*roots, *files, *absent):
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise ValueError(f"invalid runtime path: {path}")
        check_parent(path)
    for path in absent:
        if os.path.lexists(path):
            raise ValueError(f"unexpected runtime path: {path}")
    for path in roots:
        record(path, recurse=True)
        if entries[path]["type"] != "directory":
            raise ValueError(f"invalid import root: {path}")
    for path in files:
        record(path)
    return {
        "version": 2,
        "entries": entries,
        "stamps": stamps,
    }, {"hashed": hashed, "reused": reused, "rehashed_paths": sorted(rehashed)}


def file_hash(path, expected_stamp):
    with os.fdopen(
        os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
    ) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or expected_stamp != stamp(before):
            raise ValueError(f"runtime entry changed: {path}")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if expected_stamp != stamp(os.fstat(stream.fileno())):
            raise ValueError(f"runtime entry changed: {path}")
    return digest


def stamp(meta):
    return [
        meta.st_dev,
        meta.st_ino,
        meta.st_uid,
        meta.st_gid,
        meta.st_mode,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    ]


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_manifest(path, roots, files, absent, report=False):
    # The reviewed manifest is a separate trust input, never regenerated at service start.
    inventory((), (path,), ())
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("runtime manifest must be a regular file")
    expected = json.loads(path.read_bytes())
    if (
        not isinstance(expected, dict)
        or expected.get("version") != 2
        or not isinstance(expected.get("entries"), dict)
        or not isinstance(expected.get("stamps"), dict)
    ):
        raise ValueError("invalid runtime manifest format")
    actual, counts = inventory(roots, files, absent, approved=expected)
    before, after = expected["entries"], actual["entries"]
    if not report and before != after:
        raise ValueError("runtime manifest differs from approved inventory")
    if not report:
        return None
    return {
        **counts,
        "added_paths": sorted(after.keys() - before.keys()),
        "removed_paths": sorted(before.keys() - after.keys()),
        "changed_paths": sorted(
            path for path in before.keys() & after.keys() if before[path] != after[path]
        ),
        "inventory_sha256": hashlib.sha256(encode(after)).hexdigest(),
        "manifest_sha256": hashlib.sha256(encode(expected)).hexdigest(),
    }


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
        manifest, _ = inventory(roots, files, (ZIP_SLOT,))
        print(encode(manifest).decode())
    elif sys.argv[1:] == ["verify"]:
        report = verify_manifest(
            HERE / "runtime-manifest.json", roots, files, (ZIP_SLOT,), report=True
        )
        print(encode(report).decode())
        if any(
            report[key] for key in ("added_paths", "removed_paths", "changed_paths")
        ):
            raise ValueError("runtime manifest differs from approved inventory")
    elif not sys.argv[1:]:
        verify_manifest(HERE / "runtime-manifest.json", roots, files, (ZIP_SLOT,))
        sys.path.extend(map(str, SITES))
        runpy.run_path(str(HERE / "launcher.py"), run_name="__main__")
    else:
        raise ValueError("invalid runtime manifest command")


def cli():
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"matrix runtime preflight failed: {error}") from None


if __name__ == "__main__":
    cli()
