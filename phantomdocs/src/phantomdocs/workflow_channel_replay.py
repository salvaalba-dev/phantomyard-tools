"""Experimental durable one-use ledger for verified channel proofs.

This does not authenticate a principal, authorize a resource, or create a
viewer session. A trusted service must verify the channel proof first, derive
the expiry from its authenticated timestamp, and use a trustworthy clock.
"""

import os
import re
import sqlite3
import stat
from pathlib import Path


class ProofLedger:
    """A proof can be admitted once across agents, even after a restart."""

    def __init__(self, path):
        path = Path(path).absolute()
        if path.is_symlink() or path.parent.resolve() != path.parent:
            raise ValueError("ledger paths must not be symlinked")
        parent = path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode):
            raise ValueError("ledger parent must be a directory")
        if os.name == "posix" and (
            parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise ValueError("ledger directory must be private and caller-owned")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("ledger must be a regular file with one link")
        if os.name == "posix" and (
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("ledger must be private and caller-owned")
        self.db = sqlite3.connect(
            path.as_uri() + "?mode=rw", uri=True, timeout=10, isolation_level=None
        )
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("BEGIN IMMEDIATE")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            tables = self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if version == 0 and not tables:
                self.db.execute(
                    "CREATE TABLE proofs (channel TEXT NOT NULL, digest TEXT NOT NULL, "
                    "expires INTEGER NOT NULL, PRIMARY KEY (channel, digest))"
                )
                self.db.execute("PRAGMA user_version=1")
            elif version != 1:
                raise ValueError("unsupported proof ledger")
            self.db.execute("COMMIT")
        except Exception:
            self.db.close()
            raise

    def consume(self, channel, digest, *, now, expires):
        """Consume a verified proof atomically; reject expired or repeated IDs."""
        if channel not in {"telegram", "nostr"} or not isinstance(digest, str):
            raise ValueError("invalid proof identity")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid proof digest")
        if (
            type(now) is not int
            or type(expires) is not int
            or now < 0
            or expires <= now
            or expires > now + 600
        ):
            raise ValueError("invalid proof lifetime")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("DELETE FROM proofs WHERE expires <= ?", (now,))
            result = self.db.execute(
                "INSERT OR IGNORE INTO proofs (channel, digest, expires) VALUES (?, ?, ?)",
                (channel, digest, expires),
            )
            self.db.execute("COMMIT")
            return result.rowcount == 1
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def close(self):
        self.db.close()
