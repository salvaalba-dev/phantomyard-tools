# Matrix host overlay: review candidate

This is a draft, not an installer and not approved for production. The unit
drop-in is an example: remove the prior release-selection drop-in or replace its
contents atomically during a separately authorized change; two competing
drop-ins can override one another according to their sorted filenames. Preserve
the existing alert drop-in, socket, config and 65-second service timeout. Record
and restore ownership, mode, ACL, exact bytes and effective command on rollback.
If retaining `release-3ee74fe.conf`, use the example's filename without the
`.example` suffix (`zz-pr72.conf`). Any name that sorts after all other
ExecStart overrides works. Verify the effective command after reload. Installation would
create `/usr/local/lib/phantomdocs-matrix-pr72` as root:root 0755 with the
launcher and pinned payload root:root 0644, preserving restrictive existing
ACLs. Check all ancestors, existing ACLs and metadata before making any change;
stop if that arrangement would broaden access. These are proposed settings,
not a claim that installation or the dependency review has occurred.

The launcher checks the PR #72 payload bytes and compiles those same bytes. The
installed old host and guard hashes are snapshots; the old guard is subsequently
imported by path and relies on protected ownership and permissions. The launcher
recursively checks only the installed `phantomdocs` package. Python startup and
other transitive imports, including system site-packages and binary extensions,
are outside that verification. Python can process site files before the launcher
starts, including when invoked with `-I`. A secure installation requires an
independently verified startup and dependency manifest, including owner, mode,
ACL, resolved path and SHA-256 for each relevant file, and a plan to detect
drift. Checking `sys.path` inside the launcher alone cannot protect startup code
that has already run. Determine why the actual dependency graph imports any
secp256k1 library before accepting it; no such justification is established here.

Before deployment independently verify the complete current runtime, effective
imports and exact pinned baseline against the live host, including the impact of
`-I`, and validate root-owned protected directories and metadata on every parent
and file before invoking Python. The tests use synthetic fixtures and do not
prove compatibility with the production dependency graph. If checks fail, stop.
Retain the old `candidate-20261110` release pending a separate inventory and
authorized removal decision; its apparent age is not proof it is unused.
