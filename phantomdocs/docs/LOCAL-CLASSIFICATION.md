# Local classification of unsigned documents

This operation changes the current access category of an existing document,
including every retained version. It is intended for a trusted local operator
who already controls the authoritative store and PhantomOrg policy. It is not a
remote API, a human login, a bearer credential or cryptographic actor proof.
An actor name selects a declared custodian; it does not authenticate that actor.
Do not expose these commands directly to a browser, model or untrusted caller.

No PhantomBot changes, signing key, additional dependency, listener or background
service are required. This operation never calls a persona or loads an nsec.

## Supported stores

- Version-1, unsigned, unsealed namespaces with a consistent audit checkpoint.
- A custodian with current PhantomOrg write access to the document's owners and
  both its existing and proposed category.
- One document identity whose retained versions have consistent categories and
  owners. Ambiguous source references require separate review.
- The existing single-writer-host storage contract and native manifest lock.

Signed nodes, signed tags, signed audit rows, signature-required profiles, seals,
seal history and signed audit baselines are refused. This command never strips
signatures, downgrades a profile or re-signs historical records. A legacy store
without an audit checkpoint must first complete its separate reviewed migration.

## Plan, review, apply

These synthetic examples assume an existing document, custodian and categories
declared in PhantomOrg. Replace the expected MAC with the observed current MAC.

```sh
pd classification-local-plan urn:sample-org:doc:meeting.txt \
  --root /srv/sample-documents --org-yaml /etc/sample-org.yaml \
  --actor custodian --expected-mac <current-64-hex-mac> \
  --expected-category category-2 --category category-4-river \
  --reason 'Restrict the retained meeting history to the reviewed project' \
  > /private/review.json

pd classification-local-apply --trusted-local --review /private/review.json \
  --root /srv/sample-documents --org-yaml /etc/sample-org.yaml --actor custodian
```

The plan is read-only and creates no lock file. It includes the full manifest
digest, current document MAC, retained version/content hashes, owners, current
policy digest, audit prefix digest, checkpoint and persona reader comparison.
Reviewing a plan does not authorize applying it. Human/counterpart access and
viewer publication are separate checks; the persona comparison does not prove
either one.

The apply command requires an explicit `--trusted-local` acknowledgment. Under
the native writer lock it reloads the policy and store, checks both write grants
and all guards, and refuses any stale or changed request. A changed unrelated
record intentionally invalidates a plan because the manifest digest covers the
whole namespace. Regenerate the plan; do not patch its guards manually.

## Category and history semantics

Every retained node of the selected URN receives the target category in one
atomic manifest replacement. All other node fields remain unchanged: identity,
MAC, content hash, bytes, locations, owners, metadata, creation provenance,
predecessor links and version pointers. Unrelated documents are not changed.
No content edition, duplicate document or synthetic version is created.

This is a mutable access-metadata operation on an **unsigned** store. Node MACs
identify content and lineage, not the category. Creation metadata continues to
describe the original version; the new audit receipt records the classification
decision, its custodian, reason, policy and reviewed pre-state separately.

The operation uses no classification overlay or parallel permission map. Native
readers, including older version-1 readers, encounter the target category on
current versions, historical MACs and tags alike. Native `get`, `search` and
`versions` use that category. Subsequent content versions and rollbacks inherit
the effective category through the existing document service. Signed-store
classification remains a separate unsupported operation.

An external viewer may retain a previously published snapshot. This command does
not revoke that snapshot or republish its contents. Coordinate the authoritative
transition with the viewer's existing invalidation/publication mechanism and
verify listing, search, originals, history and assistant context before activating
a new recipient. It does not grant a human counterpart, project scope or write
capability. Existing exclusions still apply.

## Audit-first commit and retry

The original audit bytes are preserved. Exactly one unsigned `classify-local`
receipt is appended before the manifest is replaced. It includes the reviewed
plan and local operator UID, advances the existing mutation/audit anchors and
leaves the structural node head unchanged. A UID is operational traceability,
not a signature or proof against a compromised host administrator.

If the audit append completes but the manifest write fails, retain the original
plan and retry it before running other mutations or recovery commands. A complete,
matching pending receipt is resumed without another append. An immediate retry
after a successful commit is a no-op. Later unrelated mutations make that old
plan stale; they are not silently rolled back. Partial, altered or unknown audit
tails and changed policies are refused and preserved for operator review.

The operation never truncates an audit log. The existing generic recovery or
mutation workflow can discard uncommitted orphan audit entries under its normal
crash-recovery contract; do not run that workflow on a pending classification if
you intend to resume its receipt. Preserve the store and original plan first.
Filesystem durability and metadata preservation follow the existing native
manifest/audit implementation; deployments must retain their shared ownership,
group and platform-specific access controls when selecting the writer account.

The trust boundary remains the local host, its filesystem permissions and the
authoritative PhantomOrg source. This is not a tamper-proof external audit system.

The metadata/audit checks do not certify document contents, external file
availability or cloud sharing permissions. Review those separately and use native
content verification where required. This command does not fetch or upload any
original, change cloud permissions, approve minutes or resolve disputed dates.
