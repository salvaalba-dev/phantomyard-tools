# Minimal committed-source receipt for cooperating consumers

Status: local follow-up to PR #67/#68, coordinated with PhantomView. No installed
source, file metadata, service or permissions have been changed.

`workflow_bridge_policy --commit-witness` bootstraps a small JSON receipt in the
existing root-controlled policy lock after verifying source and every copy.
`po publish-policy` accepts the same option. The lock contains only:
```
{"kind":"phantomorg-committed-source-v1","source":"/srv/example/source.yaml","sha256":"<exact source SHA-256>"}
```
This is protocol data, not a new grant or an organization document. Existing
reader access must already suffice. The publisher does not provision or replace
the lock. It verifies the existing inode, ownership, full mode and xattrs survive
the in-place write. Empty locks may be explicitly bootstrapped; foreign nonempty
contents require investigation. The whole receipt is bounded to 8192 bytes.

Bootstrap is journaled even when no source/copy bytes change. Transactions pin
the receipt option in the existing strict durable record. A failed copy/start or
receipt write retains pending; receipt advancement happens before marker removal
and after any required service start. Nested prestart does not commit the outer
publisher's receipt prematurely. Matching recovery can finish a torn receipt.
An already matching source/copy/receipt combination remains a no-op.

The matching guard detects this protocol in an existing lock: subsequent normal
publisher invocations cannot disable it by omitting a flag. Ordinary exclusive
writers, including the old synchronizer/two-file publication path, are refused.
Use the reviewed complete publisher for repairs; do not remove the receipt or
marker to run a break-glass wrapper. Old binaries/manual root editors can still
ignore the protocol, so the installation writer inventory remains mandatory.

`committed_guard(lock_path, source)` is a read-only shared context with bounded
acquisition. It refuses pending and requires one supported receipt bound to the
configured canonical source. It exposes no source contents and performs no
recovery or permission changes. Consumers must compare their private authority's
exact source hash and hold this context through authorization and delivery.
Shared locking alone does not make a stale private copy current after commit.

PhantomView's coordinated schema-2 reader does this through its existing private
publication/index paths. Those strict paths require root-controlled producers and
protected ancestors, preventing a reader-owned copy from inventing a policy and
reusing a public digest. The root collector checks the same receipt before
publishing. No direct source access or new socket/identity is granted.

The reader guard can take a bounded `timeout`; old unbounded callers retain their
existing behavior. Shared guard contexts now report whether committed mode is
active. Guarded startup requires schema 2 and the same configured lock once active;
the supervisor schema validation also rejects different policy locks.

Exact-digest agent/mixed/dynamic reader composers accept both their existing
reviewed sources and the explicitly pinned coordinated candidate. Unknown source
revisions remain rejected. An old overlay can shadow new site-packages: stage a
complete matching reviewed package/overlay, never just a helper file.

Portable tests cover commit ordering, failure/retry, restart intent, option
pinning, invalid receipts and lock deadlines. Root Linux tests add actual inode/
metadata/xattr checks, torn bootstrap recovery, exclusion of ordinary writers and
bounded lock acquisition. Cross-repository tests exercise the exact composed
reader HTTP guard. CI root selection includes the new receipt suite; a separate
manual viewer integration workflow accepts an immutable reviewed tools commit.
No Linux root execution is claimed by merely preparing these tests on Windows.

Installation still requires current reader/writer/alert inventory, matching
reviewed source revisions, existing access verification, private backups and a
real disposable systemd rehearsal. Bootstrap must not leave a lease-only reader
running as if revocation were synchronous. Freeze approved source changes, switch
all consumer/publisher paths together during an authorized window, bootstrap and
republish private authority, then start the strict reader and verify denial.

The receipt is durable current-state evidence, not policy history. Do not restore
an old/empty lock backup, replace its inode, delete pending, or roll back grants
after partial publication. Matching forward recovery must finish first. Old code
that ignores this protocol is not a supported automatic rollback after activation.
