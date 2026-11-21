# Disposable integrated rehearsal and source provenance

The GitHub Actions `Disposable policy systemd rehearsal` workflow runs the
integrated overlay test on an ephemeral Ubuntu 24.04 runner with real systemd.
No VPS connection, production credentials, private inventory, live configuration
or existing rollback is used. Fixture paths and service names are unique; cleanup
is limited to those owned fixture paths and units. Do not run this suite on an
operational host. The integrated test requires both explicit trial settings and
the GitHub Actions environment, in addition to root and a systemd PID 1.

## Reviewed source chain

The payload in this overlay is byte-for-byte equal to the merged
`phantomdocs/src/phantomdocs/view_matrix_host.py` at main
`aebe482c6ab583d98d976608879871984a4b2b80` (PR #72). The launcher baseline pins
also match identifiable source blobs in this owning repository:

| Pinned file | Commit containing the exact matching bytes |
|---|---|
| Baseline `view_matrix_host.py` | [511b421](https://github.com/salvaalba-dev/phantomyard-tools/blob/511b421c138cbbbf30a6333e87a1b421a85e588f/phantomdocs/src/phantomdocs/view_matrix_host.py) |
| Baseline `workflow_policy_guard.py` | [84c1630](https://github.com/salvaalba-dev/phantomyard-tools/blob/84c163074b033540e56ddadd8fb8dece0f33f0b3/phantomdocs/src/phantomdocs/workflow_policy_guard.py) |

These comparisons hash Git blob bytes, without checkout newline conversion.
They identify the pinned application sources; a release-directory suffix is not
itself a source revision or proof of a trusted build of the entire release.

The workflow emits pip's installation report entries: distribution names,
versions, source URLs and available archive hashes. Local application packages
are built from the checked-out PR revision; third-party artifacts are resolved
by pip for that disposable runner. The log makes those resolutions reviewable.
It is not a lockfile for the selected production installation, a signature or
approval of production dependency provenance. Installed RECORD hashes prove
local consistency, not independent supplier trust. Keep operational package
inventories and approval receipts private.

## Integrated coverage

The test captures a version 2 fixture inventory, then runs the actual bootstrap,
launcher checks and pinned payload with `/usr/bin/python3.12 -I -S -B` through an
Accept=yes socket and systemd service. Fixture copies substitute only protected
paths and the installed fixture's baseline hashes. The payload bytes and its
55-second request deadline are unchanged. The effective unit retains the
65-second timeout and a synthetic retained drop-in. A `.pth` file which would
abort startup if executed remains inert.

A trace hook replaces `serve_configured` at payload entry with a synthetic
authority/reader shim. The real host config parser, inherited socket, Unix peer
credential check, broker framing, delivery acknowledgement and process deadline
are exercised. The shim holds real file locks and returns synthetic matrix text.
It deliberately does not exercise the operational Workspace worker, native
policy/catalog authorization, real viewer HTTP sessions or audit integration.

The rehearsal checks:

- Successful delivery to the selected synthetic UID and denial of a different
  UID before and after socket recreation.
- Refusal before payload entry after byte, mode, effective ACL, added dependency,
  link-target or manifest-format drift, followed by successful recovery after
  restoring the original approved bytes. It does not approve a replacement
  inventory to hide drift.
- Full rehash by using deliberately stale fixture manifest inode stamps while
  retaining the exact approved entry dictionary. A combined full-bootstrap and
  55-second contended-lock request must exit before 65 seconds with systemd result
  `exit-code`, not `timeout`. The first lock must be immediately reacquirable and
  a subsequent request must succeed. The log records elapsed time, margin and
  file count. Stale stamps exercise full rehash; this is not a claim that the
  runner's filesystem cache was cold.
- Restoration of the disposable baseline command, unit/drop-in/socket bytes,
  ownership, modes and extended metadata; unrelated synthetic state survives.
  A request through the restored baseline must succeed. This trial never reads,
  restores or alters the VPS rollback.

## Acceptance limits

The runner's dependency graph and file count differ from the selected target.
Passing results close a repeatable integrated synthetic rehearsal, not a claim
that its timing margin transfers to a larger target inventory. Compare exact
resolved artifact hashes and approved target metadata before calling an
environment target-representative. Record missing equivalence explicitly.

Production acceptance still requires trusted full-runtime artifact approval,
target-equivalent cold/changed-stamp timing, native worker/policy/catalog and
authenticated viewer delivery/denial/audit evidence. A separate authorized
window is required for production service/socket recreation or rollback trials.
No result here authorizes a merge, deployment, permission change or activation.
