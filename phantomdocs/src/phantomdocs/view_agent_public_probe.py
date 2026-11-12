"""Parse the runtime's read-only public identity listing, without private keys.

The host must run `phantombot phantomchat --list --json` as the bound Unix
account with its trusted HOME and a pinned executable, using a bounded process.
This module never opens a persona's identity or vault files.
"""

import json
import os
import selectors
import subprocess  # nosec B404
import time

from phantomdocs.signing import bech32_decode
from phantomdocs.workflow_admission_config import _unique
from phantomdocs.workflow_protected_paths import open_protected_file, protected_parent


def public_identity(payload, persona):
    """Return exactly one validated public identity from a runtime response."""
    if not isinstance(payload, bytes) or len(payload) > 65536:
        raise ValueError("Bounded public identity response required")
    if not isinstance(persona, str) or not persona:
        raise ValueError("Explicit persona required")
    rows = json.loads(payload, object_pairs_hook=_unique)
    if not isinstance(rows, list):
        raise TypeError("Invalid runtime identity listing")
    names = set()
    selected = None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("persona"), str):
            raise TypeError("Invalid runtime persona")
        name = row["persona"]
        if name in names:
            raise ValueError("Ambiguous runtime persona")
        names.add(name)
        if name == persona:
            value = row.get("npub")
            if not isinstance(value, str):
                raise ValueError("Runtime has no public identity")
            hrp, key = bech32_decode(value)
            if hrp != "npub" or len(key) != 32:
                raise ValueError("Invalid public identity")
            selected = value
    if selected is None:
        raise ValueError("Persona is absent from runtime")
    return selected


def query_public_identity(account, persona, executable):
    """Run only the public listing under an explicit existing Unix identity."""
    import pwd

    if os.geteuid() != 0:
        raise PermissionError("Root-controlled account verification required")
    user = pwd.getpwnam(account)
    if user.pw_uid <= 0:
        raise ValueError("An unprivileged agent account is required")
    with protected_parent(executable) as (parent, name):
        fd = open_protected_file(parent, name)
        os.close(fd)
    # Protected executable, literal read-only arguments and explicit Unix identity.
    child = subprocess.Popen(  # nosec B603
        [executable, "phantomchat", "--list", "--json"],
        user=user.pw_uid,
        group=user.pw_gid,
        extra_groups=os.getgrouplist(user.pw_name, user.pw_gid),
        env={"HOME": user.pw_dir, "PATH": "/usr/bin:/bin"},
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    payload = bytearray()
    deadline = time.monotonic() + 25
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("Public identity query exceeded deadline")
                chunk = os.read(child.stdout.fileno(), 65537 - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > 65536:
                    raise ValueError("Public identity response exceeded bounds")
        if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError("Runtime refused the public identity query")
        return user.pw_uid, public_identity(bytes(payload), persona)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()
