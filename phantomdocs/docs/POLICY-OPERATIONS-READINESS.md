# Publisher isolation, writer closure, alerts and disposable systemd rehearsal

This is a preparation contract, not installation approval or a host receipt.
It continues the committed-policy protocol after tools PR #69 and viewer PR #10.
No production unit, runtime, policy, persona or ACL is changed by preparing it.
Keep actual paths, identities, inventories and delivery receipts private.

## One isolated publisher and one configuration

Use a dedicated, root-controlled virtual environment containing matching
non-editable PhantomDocs and PhantomOrg packages from one reviewed tools commit.
The organization validator remains PhantomOrg's implementation; this entry point
does not discover, compile or change any persona. Do not repurpose an existing
persona environment or the reader's environment.

`contrib/bridge-policy/build-publisher-environment.sh.example` prepares a **new**
output from committed source bytes. It refuses a dirty checkout, mismatched
revision, existing output or an output under the checkout. It exports with Git
archive so package builds cannot change the checkout. Dependencies must be
provided in an offline wheelhouse and a reviewed fully hashed lock, including
setuptools and wheel. No dependency lock or wheelhouse for a real installation
is supplied by the examples; preparing and reviewing those artifacts is a build
gate. The script installs dependencies with `--require-hashes --no-index`, then
builds the two reviewed packages without dependency resolution or build isolation.
It leaves failed outputs intact for inspection and never updates services.

The runtime seal records interpreter bytes, prefix and the complete installed
file sets of both owning packages. It detects changed, missing or additional
package files and refuses editable/external packages. The operator must review
and pin the seal SHA-256 in protected configuration. A seal created from an
arbitrary installation is not evidence of a reviewed build. Dependencies remain
bound to the separately reviewed lock/build receipt and root-controlled runtime;
the seal is not a signature or a complete operating-system attestation.

Run all normal operations through:

```sh
/opt/example-policy-publisher/venv/bin/python \
  -m phantomdocs.workflow_policy_operations \
  --config /etc/example-policy/operations.json audit
```

`policy-operations.json.example` fixes the source, complete ordered fanout,
existing common lock, bridge resolver/unit, organization, interpreter and reviewed
artifact digests. Templates intentionally contain invalid placeholders. No path
is discovered from an installed persona, and no grant is added to make a path
readable. Configuration, inventory and seals must already be root-protected;
the application does not create them or alter their permissions.

## Close every writer, rather than relying on the reader's lock

The protected writer inventory requires an accountable owner, explicit review of
external/manual writers, an expiration, the prohibition of manual source edits,
and all four roles: reviewed publication, reconciliation, bridge prestart and
private authority collection. Source-writing roles name the same interpreter,
module, configuration and operation. Review effective unit definitions, including
drop-ins, EnvironmentFile contents/ownership, wrappers and external launchers.
Store the SHA-256 of the UTF-8 `systemctl --no-pager cat UNIT` output after
`.strip()` normalization. Unit hashes bind the whole effective definition; a
command label in the inventory alone does not establish what a unit executes.

Each operation verifies the pinned inventory, its expiration, the effective unit
hashes and that every listed retired service, timer and path is inactive/failed
and disabled/masked/not-found. Uncertain service state blocks the operation.
`audit` only reads systemd and protected artifacts; it never disables a writer.
Retirement is a separately approved maintenance action, not part of preparation.

The inventory cannot discover arbitrary root editors, shell sessions, remote
automation or a copied old binary. Before declaring closure, explicitly review
unit dependencies and overrides, all timer/path triggers, cron and user crontabs,
shell scripts, external publication tools and the responsible humans. Preserve
private dated evidence and exact entry points. `sync-org.sh` and direct copy or
old `po` commands are outside normal operation; do not describe an unrestricted
root editor as technically prevented by an advisory lock.

The new entry point always enables `require_committed_source`. Inside the
publisher's existing exclusive lock, a fresh transaction must match the current
source to its committed receipt **before** any publication. Reconciliation and
prestart refuse an uncommitted manual source edit, leave copies and receipt
unchanged, and normal orchestration stops the bridge on this unsafe state. The
independent check also compares source identity to the receipt even if all copies
were manually made identical. It reports failure without repairing anything.
This detects/contains bypasses; it cannot serialize an old binary that is still
running or prevent root from directly starting an old bridge.

Readers cannot inspect the root-private source directly: an out-of-band edit
does not itself change the committed receipt. Until a valid new transaction is
committed, a reader may retain the last committed authority. On suspected source
tampering, the operator must quiesce affected readers as part of incident handling.
Do not claim immediate revocation from an unauthorized edit or use this detection
as a substitute for closing every writer before activation.

Fresh receipt activation requires the separate `bootstrap` operation and an
explicit reviewed source SHA-256. A mismatched source, nonempty receipt, candidate
or prestart bootstrap is refused. Recovery remains the existing pinned-journal
forward recovery; a reconciliation timer can complete its own pending transaction
without the candidate file. A pending record is never cleared by alerting or audit.

For reviewed updates, `publish` requires a protected independent candidate and
both exact before/candidate SHA-256 values. All destination replacements retain
their own captured owner, mode and xattrs/ACL, using the existing atomic fanout.
Do not unify destination permissions, truncate the lock, delete a pending marker
or refresh an unexpected source just to make the viewer available.

## Alerts with delivery acknowledgement

The new `example-policy-*` unit templates attach OnFailure to reconciliation,
independent drift/writer checks, reviewed publication, the bridge and the existing
collector. They are alternatives to the legacy templates, not additional parallel
writers. Review bridge and collector drop-ins separately: only the bridge gets
the publisher prestart; keep the collector's committed publication command.
The refresh timer and source path use the same configured fanout. The independent
check timer detects stale copies, receipt drift, changed units and expired review.

The alert unit uses the standalone, stdlib-only `workflow_policy_alert.py` under
the system Python, outside the publisher environment. A missing/broken publisher
environment therefore does not automatically disable the alert adapter. Select
an existing operator-controlled delivery route and protect its executable and
parents. The handler receives bounded-format JSON on stdin, no policy bytes,
paths, credentials or inherited process secrets. There is no shell evaluation.

The existing route's adapter must return success **and** this acknowledgement
only after actual delivery acceptance:

```json
{"delivered": true, "receipt": "example-channel:message-42"}
```

A zero exit code, journal line, empty response or negative acknowledgement is a
failed delivery. The adapter has a deadline, returns failure on unavailable
delivery, and does not recursively invoke itself. Its acknowledgement still
depends on the trusted handler's truthfulness. Retain a real channel receipt and
human observation during an approved probe; this candidate supplies no real
credentials, recipient or channel integration and sends no live notification.

OnFailure alone does not detect a stopped timer or a dead alert route. Include
timer/collector heartbeat and alert-delivery health in the existing independent
operator monitoring. Review service start limits and retry policy so a sustained
incident cannot disappear behind rate limiting. A failed probe must block
installation acceptance rather than fall back to local logging.

### Direct Telegram and archival email

`workflow_policy_alert_routes.py` implements direct Telegram as primary and an
email trace for every incident, with the one-line format `unit=... host=...
state=... time=...` in UTC. Empty, malformed or unavailable systemd Result
metadata degrades to `state=unknown`; it never suppresses delivery to either
configured route. The private configuration fixes one positive Telegram
user chat and one mailbox. No group/Teamup route is implicit. Email is attempted
after either Telegram success or failure; if either required route fails, the
adapter stays failed rather than concealing degraded delivery. A partial attempt
can therefore deliver one message while still reporting failure; do not blindly
retry it as an idempotent operation.

The launcher and `policy-alert-routes.json.example` are synthetic examples.
Install the two stdlib files together only during a separately approved change.
Each existing protected transport wrapper receives JSON containing `channel`,
`recipient`, `message` and `schema_version`, and must return
`{"delivered":true,"recipient":"EXACT_CONFIGURED_RECIPIENT","receipt":"provider:42"}`.
Telegram receives at most six seconds and email at most six seconds, within the
outer delivery deadline. Exit success or an aggregate send count is insufficient.

The current [PhantomBot notify source](https://github.com/salvaalba-dev/phantombot/blob/main/src/cli/notify.ts)
broadcasts to all authorized Telegram and PhantomChat recipients, has no chat
selector and reports aggregate counts. It cannot establish exclusive direct
delivery or an exact recipient receipt. Do not invent a `--chat` argument, treat
`--persona` as a recipient selector, alter allowlists, or modify PhantomBot to
make this adapter work. Reuse the existing targeted watchdog transport only after
its installed interface is verified. Likewise, verify the actual `workspace.py
send` interface, execution identity and provider message receipt before writing
its transport wrapper; do not guess options or broaden credential access.

The version-controlled [persona-aware notify adapter](NOTIFY-ADAPTER.md) now
implements direct Telegram and the reviewed workspace-send binding, plus a
private receipt ledger. The concrete workspace interface is bound to `send <to> <subject> --body <msg>`
and a `Message ID:` receipt line. The installed script hash and conformance to
that binding, plus an approved real delivery probe, remain installation gates. Operational chat/mailbox
bindings belong only in private configuration, never this public repository.

## Real systemd rehearsal in disposable paths

The new opt-in `test_policy_operations_systemd.py` requires Linux root, PID 1
systemd, Node, ACL tools and an explicit separately installed candidate Python.
When explicitly enabled, a missing prerequisite fails rather than silently skips.
The prepared `Disposable policy systemd rehearsal` CI workflow builds a separate
root-owned, non-editable environment and enables the test in an ephemeral runner.
It has read-only repository token permissions and no deployment job or credentials.

The trial creates unique `pd-policy-systemd-*` units only under
`/run/systemd/system`, synthetic policies only under a new `/var/lib` directory,
and a local synthetic alert endpoint. It never enables a unit or touches a
production service. Cleanup stops/removes only the names created by that trial.
No mocked systemctl, lock, rename, metadata preservation or Node invocation is
used. The small bridge waits for systemd READY; an injected start failure cannot
be mistaken for successful readiness. The collector checks the committed guard.

The scenario covers reviewed bootstrap, refusal while a real legacy writer unit
is active, OnFailure delivery from publisher and collector failures, a durable
pending record after bridge start failure, timer recovery through nested prestart,
preserved per-file owner/mode/named ACL, refreshed guarded collection, source path
activation refusing a manual edit, independent drift notification and rejection
of an unacknowledged alert delivery.

The bridge, collector and endpoint are synthetic. This is real systemd
orchestration, not acceptance of the installed native bridge, complete viewer
schema-2 flow or existing operator channel. Those still need a separately
approved staged integration and later private host acceptance. Existing reader
revocation/UID/ACL tests remain required alongside this trial.

## Installation remains blocked

Before any future window: review/package the candidate, run portable and
privileged Linux/systemd CI, prepare the reviewed offline environment, close the
writer inventory with live evidence, prove the real alert route and independent
monitoring, and review exact configuration/unit/metadata/recovery diffs. Keep
policy, configuration, inventory, seal and recovery evidence private.

Only after explicit installation approval: quiesce readers and writers, retire
old triggers, introduce all matching runtimes/configurations, bootstrap the exact
reviewed source under the existing lock, fan out while preserving each target's
metadata, publish fresh private authority/index and start the schema-2 reader.
Verify actual positive/negative access and alert delivery. Do not offer a running
schema-1 reader or an old source writer as a successful transitional state.
