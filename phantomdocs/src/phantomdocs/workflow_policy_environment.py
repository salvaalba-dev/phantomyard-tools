"""Seal and verify a separately built, non-editable publisher environment."""

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path


def snapshot():
    prefix = Path(sys.prefix).resolve()
    if sys.prefix == sys.base_prefix:
        raise ValueError("a dedicated virtual environment is required")
    packages = {}
    for name in ("phantomdocs", "phantomorg"):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            raise ValueError("matching publisher packages are required")
        root = Path(spec.origin).resolve().parent
        if not root.is_relative_to(prefix):
            raise ValueError("editable or external publisher package refused")
        files = {}
        for path in sorted(root.rglob("*")):
            if "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                raise ValueError("symlinked publisher package refused")
            if path.is_file():
                files[str(path.relative_to(prefix))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
        if not files:
            raise ValueError("empty publisher package")
        packages[name] = files
    return {
        "schema_version": 1,
        "prefix": str(prefix),
        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "packages": packages,
    }


def _protected_runtime():
    from .workflow_protected_paths import protected_parent

    # The interpreter symlink may target the trusted system interpreter. Pin
    # every containing directory, and inspect the resolved executable itself.
    paths = [Path(sys.prefix) / "bin" / ".inspection", Path(sys.executable).resolve()]
    for name in ("phantomdocs", "phantomorg"):
        spec = importlib.util.find_spec(name)
        paths.append(Path(spec.origin))
    for path in paths:
        with protected_parent(str(path), search_only=True):
            if path.name != ".inspection":
                info = os.stat(path, follow_symlinks=False)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError("publisher runtime is writable outside root")


def verify(value, python):
    _protected_runtime()
    if str(Path(sys.executable).absolute()) != python or value != snapshot():
        raise ValueError("publisher environment differs from its reviewed seal")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    # Exclusive creation preserves prior artifacts. The caller reviews and pins
    # the seal digest in protected configuration; this is not self-attestation.
    with open(args.output, "x", encoding="utf-8") as stream:
        json.dump(snapshot(), stream, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
