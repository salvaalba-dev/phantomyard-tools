# Organization-policy publication and consumption

Status: local design and interruption-safety candidate, 2026-11-18. Source
baseline: `salvaalba-dev/phantomyard-tools` at
`16edf6798a1b7debb77555919c7e41e61c7a3448`. This does not establish an installed
publication path. Organization-policy lifecycle remains the first queue item.

Follow-up candidate: [PhantomOrg source publication](PHANTOMORG-SOURCE-PUBLICATION.md)
integrates reviewed source replacement with the merged PR #67 fanout under the
same lock and durable journal. The older two-file publisher below remains a
separate recovery domain and must not be chained into that normal path.

## Authority and publication boundary

The [fanout publication candidate](POLICY-FANOUT.md) extends the bridge publisher
to multiple destinations, durable matching-record retry, per-destination metadata
preservation and a separate read-only drift watchdog. It does not generate or
approve the source or establish complete installation acceptance.

The intended authority is a complete, validated PhantomOrg `org.yaml` snapshot
for one explicitly selected organization. PhantomOrg owns its meaning; neither
PhantomDocs nor the viewer may invent grants or reconstruct policy from document
categories, actor caches or generated persona files. `po build` currently compiles
actor artifacts from the input specification; it does not establish a separate
authoritative organization-policy publication service.

Keep these roles distinct:

1. **Working specification:** editable PhantomOrg source. Wizard and operator
   edits are proposals until validated and published. An incomplete `new-org`
   seed is not an authorization policy ready for publication.
2. **Candidate:** independent, protected full snapshot, validated with the owning
   PhantomOrg validator and consumer compatibility checks. Review binds the exact
   bytes, organization identity and expected previous revision.
3. **Published authority:** administrator-selected, protected source path. Only
   the publication transaction may replace it. The configured consumer copy must
   represent the same exact bytes. No working specification is a live policy
   merely because its filename is `org.yaml`.
4. **Previous revision:** independent protected backup, checked against the old
   authority before publication. Retention is not permission to reuse revoked
   grants. Restore is another reviewed publication.

Path selection, organization binding, writer identities and consumer mapping
belong in private installation configuration. Do not add operational policy,
identities, host paths or receipts to this public repository. Existing owner,
mode and extended permissions must survive replacement; do not make a consumer
more privileged to obtain access. Consumers needing a privileged reader must use
an existing authenticated, scoped boundary.

## Writers present in source

| Entry point | Current coordination | Required treatment |
|---|---|---|
| PhantomOrg `po publish-policy` (integration candidate) | Delegates source replacement and every destination to the PR #67 common-lock transaction | Reviewed exact-byte candidate only; matching packages and separate installation acceptance required. |
| PhantomOrg `wizard/new_org.py:new_org` | Direct initial YAML write | Working specification only; never target live authority. |
| PhantomOrg `wizard/mutations.py:_save` and mutation commands | Atomic save; most callers use the sibling `org.yaml.lock` mutation lock | Working specification only. This is a different lock domain from the protected policy lock. |
| PhantomOrg `wizard/interactive.py:run_setup_wizard` | Existing-spec edits use the mutation lock; new-spec save does not | Candidate creation must complete before protected publication; atomic save alone does not coordinate consumers. |
| PhantomDocs `workflow_policy_publish.publish` | Exclusive protected policy lock, expected-old digest, independent backup and durable pending marker | Reviewed source and one consumer-copy publication. Does not generate policy or discover writers. |
| PhantomDocs `workflow_policy_publish.recover` | Explicit exclusive recovery; checks marker paths and allowed digest states | Only recovery may enter the lock while a publication is pending. |
| PhantomDocs `workflow_policy_sync.synchronize` | Exclusive protected policy lock and permission-preserving replacement | Normal synchronization must refuse pending publication. It does not verify a publication receipt or establish upstream freshness. |
| PhantomDocs `workflow_bridge_policy.refresh` | Exclusive common policy lock, multiple copies, pinned permissions and matching-record retry; separate publisher lock across restart | Normal distribution entry point; its watcher remains eventual and is not synchronous revocation across consumers. |
| Operator editors, restore commands, copy jobs, timers and external generators | Not established by this repository | Inventory privately; migrate to the publication path or exclude them from the live paths before acceptance. |

The lock does not stop a writer that never acquires it. A protected live source
must not also be the target of wizard mutation, an older synchronizer or a manual
copy. This table inventories repository entry points, not installed writers.

## Freshness, interruption and revocation contract

The acceptance target is revision freshness, not a recent file modification time.
A request must use the latest committed published revision for its configured
organization. A local copy's digest alone proves neither that it matches current
authority nor that a publication job ran successfully. Before enabling this
contract, define a protected binding between source, revision, organization and
consumer, and make every actual consumer verify it at its request boundary.

Readers hold the shared policy lock through authorization and protected delivery.
Publication holds the same exclusive lock from expected-old verification through
source and consumer-copy replacement. Existing bounded requests can finish before
the writer obtains that lock; requests admitted after a completed revocation
must use the new policy. Do not claim cancellation of bytes already delivered.

The existing two-file publisher makes a durable pending marker before replacing
either file. Shared readers and ordinary exclusive writers now refuse while it
exists. Only explicit recovery can bypass that refusal. Recovery accepts the
recorded `(old, old)`, `(new, old)` and `(new, new)` states, synchronizes from the
recorded source and clears the marker durably. An interruption before source
replacement retains the old policy; after source replacement it completes the
new policy. Other states require investigation. Recovery does not guess a new
candidate or roll back a revocation to satisfy a reader.

Unreadable, unsafe, duplicate-field, invalid, mismatched or interrupted input
must deny new protected operations. Do not fall back to cached grants or the
backup. Full PhantomOrg semantic validation and organization binding are still
integration requirements: the current PhantomDocs `parse_policy` check rejects
duplicate fields and unsupported schema versions but is not that full validator.

## Consumer coverage and acceptance still required

Current shared-lock entry points include `workflow_local_peer_service.serve_one`,
audit authority adapters, `view_matrix_authority.guarded_matrix_authority`,
`view_agent_startup` and `view_agent_systemd.SystemdRouteHost.lock`. They coordinate
with the configured lock but do not independently prove upstream freshness.
`access.load_org` is a plain loader, not a transaction guard. Command-line callers
and external viewer consumers must be mapped explicitly before claiming coverage.
Bridge refresh has a separate restart lifecycle. No viewer contract was changed
by this candidate.

Required acceptance on Linux, using synthetic data and the real consumers:

- Concurrent candidate generation and publication preserve both writer ordering
  and expected-old conflict rejection; no uncoordinated writer can touch live paths.
- Stale revision, invalid semantic policy, wrong organization, unreadable input,
  unsafe path and pending publication deny protected reads and writes.
- Interrupt before and after each durable transition; recover only recorded
  states and preserve the independent backup, ownership, mode and ACLs.
- Existing bounded requests serialize before publication; later requests see
  revocation through admission, audit, matrix delivery and viewer request paths.
- Restart and recovery do not restore cached grants; verify every configured
  consumer copy and any bridge transition before acknowledging publication.

`test_policy_lifecycle.py` adds a targeted regression through the real matrix
authority context: interrupt either source or destination replacement, reject
ordinary sync, deny the consumer until recovery, then observe retained or revoked
access as appropriate. Privileged CI now includes it and `test_policy_publish.py`.
This is not complete lifecycle acceptance or a production verification.

## Remaining prerequisite and next action

The repository does not establish the selected installation's generating command,
live source, publication identity, writer inventory or full consumer mapping.
Until those are verified, wiring a working spec into a live consumer would assume
an authority and could miss a revocation. Keep activation blocked.

Next: obtain a private, read-only installation inventory identifying
the generator, authoritative source, every writer, shared lock and consumer path;
use that evidence to implement the source/revision binding and writer migration.
Run privileged Linux acceptance before any separately authorized merge or rollout.
