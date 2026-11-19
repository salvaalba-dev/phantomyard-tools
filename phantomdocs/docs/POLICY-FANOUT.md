# One policy publisher, multiple protected destinations

Status: implementation candidate; installation and activation require separate
review. `workflow_bridge_policy` publishes the same validated source snapshot to
every destination while holding the exclusive common policy lock. Use repeated
`--destination` arguments; the first destination is the bridge routing snapshot.
Every trigger must pass the same complete, ordered list. The existing single
destination command remains supported.

The [PhantomOrg source-publication integration](PHANTOMORG-SOURCE-PUBLICATION.md)
adds a reviewed `po publish-policy` entry point that changes the live source and
all destinations inside this same recoverable transaction. It is a local
candidate and does not establish installation or activation.

```sh
python -m phantomdocs.workflow_bridge_policy \
  --source /srv/example-policy/source.yaml \
  --destination /srv/example-policy/bridge.yaml \
  --destination /srv/example-policy/docs.yaml \
  --policy-lock /etc/phantomdocs/policy.lock \
  --resolver /opt/example-bridge/org-routing.js --unit example-bridge.service
```

## Transaction and permissions

Provision the source and every destination as independent, existing protected
files. Source and consumer semantics remain owned by PhantomOrg. This publisher
does not generate or approve source edits; all source writers must also acquire
the common exclusive lock. Missing, unsafe, aliased or unsupported input fails.

Before activation, verify the intended owner, group, mode and named ACL on each
destination with the actual reader account. Publication pins the existing UID,
GID, full mode and all xattr bytes (including POSIX access ACLs) in a root-only
durable pending record. Each replacement restores its own destination's metadata,
never the source's metadata. It checks those attributes before rename and after
publication. Metadata drift during retry fails rather than adopting broader
access. No automatic chmod, chown or ACL grant is performed on existing targets.

For example, a synthetic consumer can require root ownership, a dedicated reader
group, mode `0640` and an additional named-user read ACL. Preserving `0640` alone
does not preserve that named-user access. The privileged tests exercise an actual
unprivileged read before and after replacement, while a separate `0600` destination
remains unreadable to that account.

Each copy uses a temporary file in the destination's parent directory, fsync and
`os.replace`, followed by a directory fsync. Across files this is a recoverable
transaction, not a single filesystem-wide atomic rename. The `.pending` marker
exists before the first destination write. Cooperating readers and ordinary
writers refuse it; the marker is removed only after every destination's content
and permissions have been verified and any required bridge restart has succeeded.

Also pre-provision `LOCK.publisher` as a protected, root-owned `0600` regular
file beside the existing lock. Never delete or replace either lock while in use.
This second lock serializes publisher invocations across systemd restart, while
all destination writes still use the common policy lock. The publisher must
release the common lock for `systemctl start`, because the bridge's `ExecStartPre`
needs that lock. Prestart skips only the outer publisher lock; it never controls
the service. A nested prestart verifies all copies and preserves the outer
transaction's restart intent. An administrator-started initial prestart can
publish and complete a new transaction without service control.

## Retry and interruption

An incomplete copy, failed fsync or failed start leaves the pending record for the
existing reconciliation timer to retry. The record binds source SHA-256, ordered
destinations, each previous digest, permissions, resolver and bridge unit. Retry
accepts only an old or already published destination, so completed copies are not
rewritten. It remembers whether the bridge was running and can restart it after
a failed attempt stopped it. A previously inactive service is not enabled.

Only this publisher's matching record is eligible for automatic retry. A malformed
record, a manual-source-publication marker, a changed destination list, third-state
content, changed permissions or changed source revision remains blocked for
investigation. Freeze the source revision until an interrupted transaction has
been reconciled; the timer must not silently adopt a newer source or restore a
previous grant. Preserve the marker and independent recovery evidence when
investigating; do not delete it merely to make a request pass.

## Triggers and break-glass operation

Keep the current `.path`, reconciliation timer and bridge `ExecStartPre`. Update
all three to select the same source, destinations, resolver, unit and policy
lock. The timer retries after startup and after each inactive interval, including
failed oneshot runs. Synthetic templates are in `contrib/bridge-policy`.

The timer also reconciles the viewer's consumer copy. Retain the viewer's existing
guarded startup and per-request authority checks; a pending marker must deny
startup or new protected requests until reconciliation succeeds. This candidate
uses timer coverage rather than adding a viewer prestart dependency that could
deadlock its existing supervisor-held shared lock. A timer bounds eventual copy
refresh; it does not establish synchronous revocation for consumers that cache
authority or ignore the lock. Verify each actual consumer before activation.

`sync-org.sh` is **break-glass only**. Remove it from normal schedules during a
separately reviewed cutover. It coordinates with the common lock but publishes
one destination, does not restart consumers and cannot recover this journal.
The example script documents those restrictions. Do not run it concurrently
with orchestration or use it to clear an interrupted fanout.

## Independent drift alert

`workflow_policy_watchdog` compares source and all destination MD5 digests under
a shared policy lock and emits a JSON report. Exit status is `0` for matching
copies, `1` for drift and `2` for unavailable/unsafe/interrupted input. MD5 here
is only an operational equality indicator; SHA-256 remains the transaction
binding and MD5 never authorizes access. The watchdog does not publish, repair,
change metadata, clear pending or control services.

Use the separate drift service/timer templates and connect their journal/failure
signal to the installation's existing alerting. A source-change `.path` trigger
alone cannot detect an independent edit to a destination. No alert recipient,
message transmission or monitoring integration is configured by this candidate.

## Validation boundary

Portable tests cover ordering, lock lifetime, retry, restart intent, nested
prestart, configuration/content/permission drift, repeated CLI destinations and
watchdog exit statuses. Privileged Linux tests additionally cover real locks,
atomic writes, persisted process-death recovery, named-user ACL access, ownership,
mode, xattrs, unsafe files and the actual matrix authority consumer while pending.
They use synthetic files and stub service control; they never touch live policy
or restart real services. Running those tests is not installation acceptance.
