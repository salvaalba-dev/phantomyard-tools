# PhantomOrg source publication through the common fanout

The local [committed-source receipt follow-up](POLICY-COMMIT-RECEIPT.md) binds
cooperating reader requests to the completed fanout without granting source access.

Status: local integration candidate, based on the merged PR #67. No installation
or activation is implied. PhantomOrg owns model validation; the existing
PhantomDocs publisher owns the protected transaction and service orchestration.

## Prepare, review, publish

Use PhantomOrg setup and mutation commands against a **working specification**.
Their sibling YAML lock is not the common policy lock: never point them, an
editor, or a copy job at the live authority. `po build` compiles persona artifacts
and is not a source publication step.

Finish the full organization model, validate it, and place a reviewed independent
candidate in an existing protected directory. The candidate, source and every
destination must be existing root-owned regular files with protected ancestors,
without aliases, links or unprivileged writers. Preserve the installation's
current permissions; this command does not provision files or grant access.

Record the exact candidate SHA-256, expected current source SHA-256 and selected
organization ID during review. Retain an independent protected previous-revision
backup before publication, according to the installation's recovery procedure.
The transaction journal is forward-recovery data, not a history or backup store.

The following synthetic command illustrates the future operator entry point;
replace its paths and reviewed digests with private installation configuration:

```sh
po publish-policy \
  --candidate /srv/example-policy/reviewed.yaml \
  --source /srv/example-policy/source.yaml \
  --expected-source-sha256 "$REVIEWED_SOURCE_SHA256" \
  --candidate-sha256 "$REVIEWED_CANDIDATE_SHA256" \
  --organization sample-org \
  --destination /srv/example-policy/bridge.yaml \
  --destination /srv/example-policy/docs.yaml \
  --policy-lock /etc/phantomdocs/policy.lock \
  --resolver /opt/example-bridge/org-routing.js \
  --unit example-bridge.service
```

The first destination is the bridge. All normal triggers must retain the same
complete ordered fanout and configuration. Install matching PhantomOrg and
PhantomDocs builds from the same reviewed repository revision into the publisher
environment; neither an old installed `po` nor an arbitrary package of the same
version proves this API is present. Both packages can be installed from their
repository subdirectories. No new dependency or access to persona directories is
required. A future installation must also give the timer and bridge prestart
that matching environment, because recovery uses the PhantomOrg validator.

`po publish-policy` delegates directly to `workflow_bridge_policy.refresh` with
candidate review options. The equivalent module command accepts `--candidate`,
`--expected-source-sha256`, `--candidate-sha256` and `--organization`; there is no
second publisher or chained two-file transaction. The command does not discover,
compile, mutate or deploy personas. Validation establishes model consistency,
not human approval of new grants: the reviewed bytes and existing administrator
boundary remain responsible for policy decisions.

## Transaction and forward recovery

The outer `.publisher` lock serializes orchestrators. Under the common exclusive
policy lock, the publisher reads the exact candidate bytes once, checks both
reviewed digests and the current/candidate organization identity, and runs the
full PhantomOrg shape, reference and hierarchy validator. Bridge compatibility
is also checked before changing any live file. A stale or invalid fresh proposal
does not stop an otherwise running bridge or change any live policy.

Before the first live write, a durable root-private pending record pins:

- The validated candidate bytes, selected organization and expected old source.
- The source's UID, GID, mode and all xattrs, including POSIX ACL bytes.
- Every destination's old digest and its own independently captured metadata.
- The existing PR #67 consumer configuration and service restart intent.

Candidate size is limited to 2 MiB and the whole pending record retains the
existing 4 MiB bound. The journal contains private policy data; keep its parent
protected and do not collect it into public logs or repository receipts.

The publisher replaces the live source and then every destination while still
holding the common lock. Each replacement uses a same-filesystem temporary file,
restores that file's own captured owner/mode/xattrs, and performs rename and fsync.
This is a recoverable multi-file transaction, not one filesystem-wide atomic
operation. Cooperating readers refuse the pending marker until all copies and
metadata match and the required bridge start succeeds. Nested bridge prestart
preserves the outer restart intent, as in PR #67.

After a failure or process death, the existing reconciliation invocation without
candidate flags can finish the matching source transaction. It validates the
journal's pinned bytes through PhantomOrg and accepts only the recorded old/new
source and destination states with unchanged metadata. Recovery does not need
the original candidate file. Optional `--organization` on normal triggers also
binds recovery to the configured tenant. Missing matching validation support,
foreign records, permission drift, unexpected content or changed configuration
remain blocked for investigation. Never clear the marker or restore old grants
just to make consumers run.

A private disposable staging file beneath the lock directory feeds the existing
permission-preserving replacement routine. It is removed on normal exit; a killed
process can leave a root-private orphan. Recovery ignores that orphan and uses
the durable journal. Cleanup is a separate reviewed maintenance action.

Periodic source-to-copy fanout without candidate flags retains PR #67 behavior.
Do not combine this path with `workflow_policy_publish` or its differently owned
recovery marker. `sync-org.sh` remains break-glass only. The independent watchdog
reports drift and does not authorize or repair publication.

## Verification and remaining installation work

Portable tests cover exact-byte validation, organization/revision binding,
invalid references/cycles/duplicates, rejection without service interruption,
one-lock source and fanout publication, nested prestart, idempotence and recovery
without the candidate. Root Linux tests use synthetic protected paths to exercise
real ACL/xattr preservation, actual consumer revocation and pending refusal,
failure at each file, process death after source rename, and concurrent reviewed
writers. Service control is stubbed; no live service is restarted by these tests.

CI installs both matching packages and includes the new privileged Linux suite.
Passing it is required before installation review; it is not VPS acceptance.
The private cutover must still inventory every source writer, retain old-source
recovery evidence, verify actual reader ACLs and all consumer lock boundaries,
and connect the independent watchdog to the existing alert route. Deploying or
activating the command, services and triggers requires separate authorization.
