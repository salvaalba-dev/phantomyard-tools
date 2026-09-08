"""Storage adapters (spec §8).

Every node is a blob (bytes) + its content hash; adapters only move bytes.
The OS is irrelevant because everything flows through this layer.

Backends are addressed by URI:

    local://<root>                  content-addressed filesystem store
    ssh://[user@]host[:port]/<base> remote content-addressed store over SSH
    gdrive://                       delegates to the persona's workspace.py
"""

from __future__ import annotations

import os
import shutil
import stat

# subprocess is required to shell out to ssh / the persona's workspace.py.
# Commands are built as argument lists (no shell=True) and inputs validated.
import subprocess  # nosec B404
import sys
import tempfile
from functools import wraps
from urllib.parse import urlparse

from .content import FileContent, write_content
from .fsutil import fsync_dir
from .identity import content_hash as _content_hash
from .identity import is_valid_hex64


class StorageError(Exception):
    """Raised when a backend cannot read/write a blob."""


def _storage_errors(operation):
    @wraps(operation)
    def wrapped(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except OSError as exc:
            raise StorageError(f"{operation.__name__} failed: {exc}") from exc

    return wrapped


def _validate_content(data, expected):
    try:
        if _content_hash(data) != expected:
            raise StorageError(f"content hash mismatch for {expected}")
        return data
    except BaseException:
        if isinstance(data, FileContent):
            data.close()
        raise


def _require_hash(content_hash: str) -> None:
    if not is_valid_hex64(content_hash):
        raise StorageError(f"invalid content hash: {content_hash!r}")


@_storage_errors
def _run_checked(args: list[str], *, stdin=None, text: bool = False, output=None):
    """Run a subprocess without a shell.

    Args are an explicit list (no shell=True) and any remote command is built
    from validated 64-hex hashes, so there is no injection surface. The
    returncode is checked by the caller.
    """
    if isinstance(stdin, FileContent) or output is not None:
        # File descriptors keep document bytes out of subprocess PIPE buffers.
        # Diagnostics also go to disk; retain only a bounded error excerpt.
        with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as discard:
            if isinstance(stdin, FileContent):
                stdin.file.seek(0)
            proc = subprocess.run(  # nosec B603
                args,
                stdin=stdin.file if isinstance(stdin, FileContent) else None,
                stdout=output.file if output is not None else discard,
                stderr=errors,
                check=False,
            )
            errors.seek(0)
            proc.stderr = errors.read(65536)
            proc.stdout = b""
            if output is not None:
                output.file.seek(0)
            return proc
    return subprocess.run(  # nosec B603
        args, input=stdin, capture_output=True, text=text, check=False
    )


def _shell_quote(value: str) -> str:
    """Quote ``value`` for a POSIX shell as a single-quoted literal.

    A remote ``cat``/``test`` command is executed by the remote shell, so a
    path taken from an operator-supplied reference must be quoted — otherwise
    shell metacharacters in the path execute additional commands. Embedded
    single quotes are escaped with the standard ``'\\''`` sequence so the
    whole value is transmitted as one literal argument.
    """
    return "'" + value.replace("'", "'\\''") + "'"


class LocalBackend:
    """Content-addressed store: <root>/blobs/<aa>/<full-sha256-hex>.

    Confined (issue #75): the shard directory and blob are validated against
    the *real* storage root, symlinked shards are refused, and reads open the
    blob with O_NOFOLLOW so a symlink cannot redirect them outside the root.
    """

    def __init__(self, root: str):
        self.root = os.path.abspath(root or ".")
        self._root_real = os.path.realpath(self.root)

    def _shard_dir(self, content_hash: str, *, create: bool) -> str:
        """The confined shard directory, or StorageError on an escape.

        Rejects a symlinked shard (``blobs/<aa> -> elsewhere``), a shard that
        resolves outside the real storage root, and — best effort — a shard on
        a different device than the root (mount/bind swap).
        """
        _require_hash(content_hash)
        shard = os.path.join(self._root_real, "blobs", content_hash[:2])
        if os.path.lexists(shard):
            if os.path.islink(shard):
                raise StorageError(f"refusing symlinked shard directory: {shard}")
            real = os.path.realpath(shard)
            if real != shard:
                raise StorageError(
                    f"shard directory escapes storage root: {real!r} != {shard!r}"
                )
            st = os.stat(shard)
            if not stat.S_ISDIR(st.st_mode):
                raise StorageError(f"shard path is not a directory: {shard}")
            root_st = os.stat(self._root_real)
            if st.st_dev != root_st.st_dev:
                raise StorageError(f"shard directory is on a different device: {shard}")
        elif create:
            os.makedirs(shard, exist_ok=True)
            # Re-verify after creation (the path could have been swapped
            # between the check above and the makedirs call).
            if os.path.islink(shard) or os.path.realpath(shard) != shard:
                raise StorageError(f"refusing symlinked shard directory: {shard}")
        return shard

    def blob_path(self, content_hash: str) -> str:
        _require_hash(content_hash)
        return os.path.join(self.root, "blobs", content_hash[:2], content_hash)

    def put(self, content_hash: str, data: bytes | FileContent) -> str:
        shard = self._shard_dir(content_hash, create=True)
        path = os.path.join(shard, content_hash)
        if os.path.lexists(path):
            # Reject a symlink at the blob address itself (TOCTOU guard).
            if os.path.islink(path):
                raise StorageError(f"refusing symlinked blob path: {path}")
            return path
        # Atomic write (issue #74): a unique temp file, fsync'd and renamed
        # into place, so a crash never leaves a partial blob visible under
        # its content address. os.replace replaces a symlink at the
        # destination rather than writing through it.
        fd, tmp = tempfile.mkstemp(dir=shard, prefix=".blob-", suffix=".tmp")
        fd_unclaimed = True
        try:
            with os.fdopen(fd, "wb") as f:
                # fdopen has taken ownership. The context manager closes it
                # before an exception reaches the cleanup handler.
                fd_unclaimed = False
                write_content(f, data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            fsync_dir(shard)
        except BaseException:
            if fd_unclaimed:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path

    def get(self, content_hash: str, *, streaming=False):
        shard = self._shard_dir(content_hash, create=False)
        path = os.path.join(shard, content_hash)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError:
            raise StorageError(f"blob not found: {content_hash}")
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise StorageError(f"blob is not a regular file: {content_hash}")
            if st.st_nlink > 1:
                raise StorageError(f"refusing hardlinked blob: {content_hash}")
            data = FileContent.from_stream(f) if streaming else f.read()
        # Content-addressed store: verify the bytes against the requested
        # hash on read, so a mutated blob is refused (integrity on the read
        # path, not only under `pd verify`).
        return _validate_content(data, content_hash)

    def has(self, content_hash: str) -> bool:
        try:
            shard = self._shard_dir(content_hash, create=False)
        except StorageError:
            return False
        path = os.path.join(shard, content_hash)
        try:
            st = os.lstat(path)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode)


class SshBackend:
    """Remote content-addressed store over SSH (spec §8).

    Same layout as LocalBackend, on the remote host: ``<base>/blobs/<aa>/<hash>``.
    Content hashes are validated as 64-hex before being embedded in a remote
    command, so there is no injection surface from the hash. ``base`` is
    trusted operator configuration.
    """

    def __init__(
        self,
        host: str,
        user: str | None = None,
        port: int = 22,
        base: str = "/var/phantomdocs",
        key: str | None = None,
    ):
        self.host = host
        self.user = user
        self.port = int(port)
        self.base = base.rstrip("/") or "/"
        self.key = key

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def _ssh_args(self) -> list[str]:
        args = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
        ]
        if self.key:
            args += ["-i", self.key]
        args.append(self.target)
        return args

    def remote_path(self, content_hash: str) -> str:
        _require_hash(content_hash)
        return f"{self.base}/blobs/{content_hash[:2]}/{content_hash}"

    def put(self, content_hash: str, data: bytes | FileContent) -> str:
        remote = self.remote_path(content_hash)
        parent = os.path.dirname(remote)
        tmp = f"{remote}.tmp"
        # Write to a temp file then rename atomically, and shell-quote the
        # paths: a mid-transfer disconnect leaves no partial blob visible, and
        # a `base` with spaces/special chars cannot break the write.
        cmd = (
            f"mkdir -p {_shell_quote(parent)} && "
            f"cat > {_shell_quote(tmp)} && "
            f"mv {_shell_quote(tmp)} {_shell_quote(remote)}"
        )
        proc = _run_checked(self._ssh_args() + [cmd], stdin=data)
        if proc.returncode != 0:
            raise StorageError(self._err(proc, "ssh put failed"))
        host = f"[{self.host}]" if ":" in self.host else self.host
        authority = f"{self.user}@{host}" if self.user else host
        return f"ssh://{authority}:{self.port}{remote}"

    def get(self, content_hash: str, *, streaming=False):
        remote = self.remote_path(content_hash)
        if streaming:
            # Preserve adapter-specific SSH options (including identity key).
            data = FileContent()
            try:
                proc = _run_checked(
                    self._ssh_args() + [f"cat {_shell_quote(remote)}"], output=data
                )
                if proc.returncode != 0:
                    raise StorageError(self._err(proc, "ssh get failed"))
                if _content_hash(data) != content_hash:
                    raise StorageError(f"content hash mismatch for {content_hash}")
                return data
            except BaseException:
                data.close()
                raise
        proc = _run_checked(self._ssh_args() + [f"cat {_shell_quote(remote)}"])
        if proc.returncode != 0:
            raise StorageError(self._err(proc, "ssh get failed (blob not found?)"))
        data = proc.stdout
        # Integrity on the read path: verify the bytes against the hash.
        if _content_hash(data) != content_hash:
            raise StorageError(f"content hash mismatch for {content_hash}")
        return data

    def has(self, content_hash: str) -> bool:
        remote = self.remote_path(content_hash)
        proc = _run_checked(self._ssh_args() + [f"test -f {_shell_quote(remote)}"])
        return proc.returncode == 0

    @staticmethod
    def _err(proc: subprocess.CompletedProcess, prefix: str) -> str:
        detail = proc.stderr.decode(errors="replace").strip()
        return f"{prefix}: {detail}" if detail else prefix


class GdriveBackend:
    """Google Drive adapter (spec §8) — delegates to the persona's workspace
    tooling; PhantomDocs never manages Google credentials itself (same pattern
    as PhantomMeet SPEC §6.1).

    Drive is a *reference* backend, not a content-addressed store: ``put``
    uploads the blob and returns the Drive file id, which the caller stores
    as a ``ref`` location so ``get``/``verify`` re-download it through
    ``read_reference`` (the only Drive read path PhantomDocs implements).
    ``get``/``has`` by content hash therefore remain unimplemented.

    Idempotency contract (issue #79): the persona tooling must treat the
    ``--content-hash`` flag as the upload's idempotency key — identical bytes
    MUST resolve to the same Drive file id (content-addressed dedup) rather
    than duplicating the object. This is what makes a retry after a lost
    upload response safe.

    Ambiguous-success semantics: a failed ``put`` does NOT necessarily mean
    no remote object was created — the upload may have succeeded on Drive
    while the response (and thus the file id) was lost. Callers must treat
    ``put`` failures as retryable, not as proof of absence; the idempotency
    contract above is what keeps those retries duplicate-free.
    """

    def __init__(self, workspace_py: str | None = None):
        self.workspace_py = workspace_py or os.environ.get(
            "PHANTOMDOCS_WORKSPACE_PY", "workspace.py"
        )

    def _require_tool(self) -> None:
        if shutil.which(self.workspace_py) is None:
            raise StorageError(
                f"gdrive:// requires {self.workspace_py!r} on PATH "
                "(the persona's Google Drive tooling)"
            )

    def put(self, content_hash: str, data: bytes | FileContent) -> str:
        _require_hash(content_hash)
        self._require_tool()
        with tempfile.TemporaryDirectory(prefix="pd-upload-") as directory:
            tmp = os.path.join(directory, "content")
            with open(tmp, "wb") as f:
                write_content(f, data)
            proc = _run_checked(
                _workspace_command(self.workspace_py)
                + [
                    "drive-upload",
                    tmp,
                    "--folder",
                    "phantomdocs",
                    "--content-hash",
                    content_hash,
                ],
                text=True,
            )
        if proc.returncode != 0:
            detail = proc.stderr.strip()
            raise StorageError(
                f"drive upload failed: {detail}" if detail else "drive upload failed"
            )
        # The upload must yield a re-downloadable file id; without one the
        # document can never be read back (fail-closed). Note (issue #79):
        # reaching this line does not prove the upload FAILED remotely — the
        # response (and file id) may simply have been lost after Drive accepted
        # the object. Retrying is safe *because* the tooling is content-addressed
        # (see the class idempotency contract).
        file_id = proc.stdout.strip()
        file_id = file_id.removeprefix("gdrive://")
        if not file_id:
            raise StorageError(
                "drive upload returned no file id; cannot round-trip the document"
            )
        # Independent read-back verification (audit #8): the returned external
        # reference must be re-read and hash-checked before it becomes
        # authenticated document state. A buggy or malicious workspace.py
        # (wrong id, wrong bytes, a stale id, or a lie about success) fails here
        # instead of being committed as a document location.
        with _gdrive_download(self.workspace_py, file_id, streaming=True) as downloaded:
            if _content_hash(downloaded) != content_hash:
                raise StorageError(
                    f"drive read-back mismatch for {content_hash}: the returned "
                    "reference does not resolve to the uploaded content"
                )
        return file_id

    def get(self, content_hash: str) -> bytes:
        _require_hash(content_hash)
        raise StorageError(
            "gdrive:// get is delegated to the persona's `workspace.py drive`"
        )

    def has(self, content_hash: str) -> bool:
        _require_hash(content_hash)
        raise StorageError(
            "gdrive:// has is delegated to the persona's `workspace.py drive`"
        )


def _parse_storage_uri(uri: str):
    """Validate connection fields before they can raise in a read loop."""
    try:
        parsed = urlparse(uri)
        if parsed.scheme == "ssh":
            if not parsed.hostname:
                raise ValueError("SSH host is required")
            if parsed.port is not None and parsed.port == 0:
                raise ValueError("SSH port must be between 1 and 65535")
        return parsed
    except ValueError as exc:
        raise StorageError(f"invalid storage URI {uri!r}: {exc}") from exc


def resolve_backend(uri: str):
    """Build a backend from a URI (``local://``, ``ssh://``, ``gdrive://``).

    A path without a scheme is treated as a local root.
    """
    if not isinstance(uri, str) or not uri or "\x00" in uri:
        raise StorageError("backend URI must be a non-empty string without NUL")
    if "://" not in uri:
        return LocalBackend(uri)
    parsed = _parse_storage_uri(uri)
    scheme = parsed.scheme
    if scheme == "local":
        # ``local://<root>`` puts the root in netloc; ``local:///abs`` puts it
        # in path. Recombine so the documented two-slash form never silently
        # resolves to the current directory.
        root = (parsed.netloc or "") + (parsed.path or "")
        return LocalBackend(root or ".")
    if scheme == "ssh":
        return SshBackend(
            host=parsed.hostname or "",
            user=parsed.username or None,
            port=parsed.port or 22,
            base=parsed.path or "/var/phantomdocs",
        )
    if scheme == "gdrive":
        return GdriveBackend()
    raise StorageError(f"unknown backend scheme: {scheme!r}")


def _workspace_command(workspace_py: str) -> list[str]:
    """Return an executable command for the configured workspace tool.

    A Python script is directly executable on POSIX. On Windows it needs the
    current Python interpreter, otherwise subprocess raises WinError 193.
    """
    resolved = shutil.which(workspace_py) or workspace_py
    if os.name == "nt" and resolved.lower().endswith(".py"):
        return [sys.executable, resolved]
    return [resolved]


def _gdrive_download(workspace_py: str, file_id: str, *, streaming=False):
    """Download a Drive file's raw bytes via the persona's workspace tooling."""
    with tempfile.NamedTemporaryFile(prefix="pd-gdrive-", delete=False) as f:
        tmp = f.name
    try:
        proc = _run_checked(
            _workspace_command(workspace_py) + ["drive", "download", file_id, tmp],
            text=True,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip()
            raise StorageError(
                f"gdrive download failed: {detail}"
                if detail
                else "gdrive download failed"
            )
        with open(tmp, "rb") as f:
            return FileContent.from_stream(f) if streaming else f.read()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _ssh_canonical(parsed) -> str:
    """The canonical ``ssh://[user@]host[:port]/path`` URI for a parsed URL.

    Preserves host, user, and a non-default port so a reference round-trips
    through ``read_reference`` without losing its connection target.
    """
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{parsed.username}@{host}" if parsed.username else host
    port = parsed.port or 22
    if port != 22:
        netloc = f"{netloc}:{port}"
    return f"ssh://{netloc}{parsed.path or ''}"


def location_uri(location: dict) -> str:
    """Reconstruct the addressable URI for a stored ``location``.

    ``ssh`` references are stored as a full canonical URI (host/user/port
    preserved) so ``get``/``verify`` can re-read them; ``file``/``gdrive``
    store a bare path/id and the backend scheme is re-attached.
    """
    ref = location.get("ref", "")
    if ref.startswith(("ssh://", "file://", "gdrive://", "local://")):
        return ref
    backend = location.get("backend", "")
    return f"{backend}://{ref}" if backend else ref


def _validate_location(location):
    if not isinstance(location, dict):
        raise StorageError("location must be a mapping")
    backend = location.get("backend", "")
    if not isinstance(backend, str) or backend not in (
        "",
        "local",
        "file",
        "ssh",
        "gdrive",
    ):
        raise StorageError("location backend must be local, file, ssh, or gdrive")
    if backend in ("file", "gdrive") and "ref" not in location:
        raise StorageError(f"{backend} location requires a ref")
    field = "ref" if "ref" in location else "path"
    value = location.get(field)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StorageError(f"location {field} must be a non-empty string without NUL")


def _get_blob(store, content_hash, streaming):
    if isinstance(store, GdriveBackend):
        raise StorageError("GDrive blobs require a file-id reference location")
    # Content-addressed adapters validate the bytes before returning them.
    return (
        store.get(content_hash, streaming=True)
        if streaming
        else store.get(content_hash)
    )


@_storage_errors
def read_location(
    location: dict,
    content_hash: str,
    *,
    root: str,
    backend: str | None = None,
    streaming: bool = False,
):
    """Read one declared document location and verify its content hash.

    Blob reads honor an explicit backend override. Otherwise they use the
    recorded store; missing local paths can be restored from the current root.
    External reference locations remain exact pointers and are never redirected.
    """
    _require_hash(content_hash)
    _validate_location(location)
    if "ref" in location:
        data = read_reference(location_uri(location), streaming=streaming)[0]
    else:
        if backend is not None:
            return _get_blob(resolve_backend(backend), content_hash, streaming)
        path = location.get("path")
        stored_backend = location.get("backend")
        if stored_backend == "ssh" and not path.startswith("ssh://"):
            raise StorageError("stored SSH blob path must be an ssh:// URI")
        if (
            stored_backend == "ssh"
            and isinstance(path, str)
            and path.startswith("ssh://")
        ):
            # put() records the complete blob URI, not a backend root.
            # Resolving it as a root would append the shard/hash twice.
            data = read_reference(path, streaming=streaming)[0]
        else:
            if stored_backend == "local" and path:
                # Local put records the full absolute content-addressed path.
                # Recover the root, then retain all LocalBackend validations.
                if not isinstance(path, str) or not os.path.isabs(path):
                    raise StorageError("stored local blob path must be absolute")
                stored_root = os.path.dirname(os.path.dirname(os.path.dirname(path)))
                store = LocalBackend(stored_root)
                if os.path.normpath(path) != os.path.normpath(
                    store.blob_path(content_hash)
                ):
                    raise StorageError(
                        "stored local blob path does not match content hash"
                    )
                try:
                    os.lstat(path)
                except FileNotFoundError:
                    # A relocated backup retains authenticated location metadata.
                    # Only absent paths fall back: corruption/permission failures
                    # at a present location must remain visible to verify.
                    store = LocalBackend(root)
            else:
                store = LocalBackend(root)
            return _get_blob(store, content_hash, streaming)
    return _validate_content(data, content_hash)


def read_document(node, *, root, backend=None):
    """Open the first healthy declared replica; caller owns its snapshot."""
    locations = node.get("locations") or []
    if not locations:
        raise StorageError(f"document has no locations: {node['urn']}")
    failures = []
    for index, location in enumerate(locations, 1):
        try:
            return read_location(
                location,
                node["contentHash"],
                root=root,
                backend=backend,
                streaming=True,
            ), location
        except StorageError as exc:
            failures.append(f"location {index}: {exc}")
    raise StorageError(
        f"unable to read {node['urn']} from any declared location: "
        + "; ".join(failures)
    )


@_storage_errors
def read_reference(uri: str, workspace_py: str | None = None, *, streaming=False):
    """Read the bytes of an external object and return ``(bytes, location)``.

    "Add by reference": index an object that already lives somewhere else,
    without copying it into a content-addressed store. Backends:

      - ``gdrive://<file_id>``              -> the persona's Google Drive
        (via ``workspace.py drive download``; the path is taken from
        ``$PHANTOMDOCS_WORKSPACE_PY``, falling back to ``workspace.py``)
      - ``file:///abs/path`` or a bare path -> local filesystem
      - ``ssh://[user@]host[:port]/<path>`` -> a remote file over SSH

    The returned location carries a ``ref`` key (an external object pointer),
    never a content-addressed store path.
    """
    if not isinstance(uri, str) or not uri or "\x00" in uri:
        raise StorageError("reference URI must be a non-empty string without NUL")
    if workspace_py is None:
        workspace_py = os.environ.get("PHANTOMDOCS_WORKSPACE_PY", "workspace.py")
    if uri.startswith("gdrive://"):
        file_id = uri[len("gdrive://") :]
        if not file_id:
            raise StorageError("GDrive reference requires a file id")
        data = _gdrive_download(workspace_py, file_id, streaming=streaming)
        return data, {"backend": "gdrive", "ref": file_id}
    if uri.startswith("file://"):
        path = uri[len("file://") :]
        try:
            with open(path, "rb") as f:
                data = FileContent.from_stream(f) if streaming else f.read()
        except OSError as exc:
            raise StorageError(f"cannot read reference {path!r}: {exc}") from exc
        return data, {"backend": "file", "ref": path}
    if uri.startswith("ssh://"):
        parsed = _parse_storage_uri(uri)
        target = (
            f"{parsed.username}@{parsed.hostname}"
            if parsed.username
            else (parsed.hostname or "")
        )
        remote = parsed.path or ""
        if streaming:
            data = FileContent()
            try:
                store = SshBackend(
                    parsed.hostname or "", parsed.username, parsed.port or 22
                )
                proc = _run_checked(
                    store._ssh_args() + [f"cat {_shell_quote(remote)}"], output=data
                )
                if proc.returncode != 0:
                    raise StorageError(store._err(proc, "ssh read failed"))
                return data, {"backend": "ssh", "ref": _ssh_canonical(parsed)}
            except BaseException:
                data.close()
                raise
        proc = _run_checked(
            [
                "ssh",
                "-p",
                str(parsed.port or 22),
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                target,
                f"cat {_shell_quote(remote)}",
            ]
        )
        if proc.returncode != 0:
            # proc.stderr follows the caller's text semantics (see _run_checked):
            # bytes on the non-streaming path, str when text=True is requested.
            detail = (
                proc.stderr.strip()
                if isinstance(proc.stderr, str)
                else proc.stderr.decode(errors="replace").strip()
            )
            raise StorageError(
                f"ssh read failed: {detail}" if detail else "ssh read failed"
            )
        # Preserve the full canonical reference (host/user/port + path) so
        # `get`/`verify` can re-read the object later; a bare path would lose
        # the connection target and reconstruct an empty host.
        return proc.stdout, {"backend": "ssh", "ref": _ssh_canonical(parsed)}
    # bare local path
    try:
        with open(uri, "rb") as f:
            data = FileContent.from_stream(f) if streaming else f.read()
    except OSError as exc:
        raise StorageError(f"cannot read reference {uri!r}: {exc}") from exc
    return data, {"backend": "file", "ref": uri}
