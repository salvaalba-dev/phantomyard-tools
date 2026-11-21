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

The service starts the Ubuntu Python 3.12 interpreter with `-I -S -B`.
Python ignores environment import paths and skips site initialization, including
`.pth` files and site customization. The bootstrap checks the exact initial
search path and refuses an unexpected standard library ZIP. It verifies the
approved inventory before adding the existing venv and distro package roots in
order and invoking the launcher. The inventory includes directories, file link
targets, SHA-256 for all regular files (including bytecode, package data and
native Python extensions), owner, group, mode and POSIX ACLs. Effective ACL write
grants are reflected in the group permission bits and cause rejection. Directory
links are followed into their protected targets, including Babel's distro data.
Adding, removing, replacing or changing a recorded entry
requires review of a new inventory. The capture command writes JSON to stdout:

```sh
/usr/bin/python3.12 -I -S -B /path/to/reviewed/bootstrap.py capture
```

Run capture with the exact reviewed bootstrap, launcher and payload at their
intended paths in a disposable copy of the target filesystem. Compare the
inventory with trusted package and release records and independently review ACLs
and link targets before approving it as `runtime-manifest.json` beside the
bootstrap. Keep it root owned and free of group or other write access. Capture
does not establish provenance by itself. The installed host and guard pins are
snapshots. The guard still imports by path under protected ownership, while the
payload executes from the exact verified buffer. The distro interpreter, ELF
loader, OS libraries and stdlib needed by the bootstrap itself are part of the
trusted OS base. The inventory detects later byte drift in the interpreter and
stdlib, but cannot attest to the code already needed to run the check. Keep the
runtime quiescent during root maintenance. The separate unprivileged worker
continues to use its existing command and environment.

The dependency on secp256k1 comes from `phantomdocs.signing`. Access validation
imports its Nostr key conversion and the manifest imports its crypto version.
Both paths load coincurve even for a read-only matrix request.

Before deployment independently verify the complete current runtime, effective
imports and exact pinned baseline against the live host, including the impact of
`-I -S`, and validate root-owned protected directories and metadata on every parent
and file before invoking Python. The tests use synthetic fixtures and do not
prove compatibility with the production dependency graph. If checks fail, stop.
Retain the old `candidate-20261110` release pending a separate inventory and
authorized removal decision; its apparent age is not proof it is unused.
