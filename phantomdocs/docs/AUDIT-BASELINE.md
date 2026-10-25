# Adopting a legacy audit checkpoint

A non-empty legacy audit log without `auditSeq` and `auditHead` has an unknown
committed position. Ordinary mutations and recovery refuse it rather than
discarding its history. Checkpoint adoption is an explicit migration for this
case, not document reclassification or ordinary crash recovery.

## Review first

Use the installed native CLI and the authoritative PhantomOrg model:

```bash
umask 077
pd audit-checkpoint-plan --root ./docs --org-yaml ./org.yaml \
  --actor custodian > checkpoint-plan.json
```

The command reads the namespace and prints a private JSON plan. It writes no
namespace files. Keep the plan outside public repositories: it includes actor
and namespace identifiers, policy and manifest digests, audit hashes and counts.
Review the actual source history before approving it; a valid hash chain alone
does not establish the truth of old entries.

Only a native namespace administrator may plan or adopt a checkpoint. The
organization must match the namespace. Adoption supports an unsealed version-1
namespace with a valid non-empty audit chain and no existing checkpoint or
baseline receipt. Partial checkpoints, unknown protocol versions, sealed legacy
stores and malformed history require separate review; do not reset their fields
to bypass these checks.

## Explicit adoption

```bash
pd adopt-audit-checkpoint --root ./docs --org-yaml ./org.yaml \
  --actor custodian --nsec-file /private/existing-signing-key \
  --plan checkpoint-plan.json --reason "Adopt reviewed legacy history"
pd verify --root ./docs --org-yaml ./org.yaml
```

Use the actor's existing supported signing-key file; this command does not create
or export keys. It reloads PhantomOrg and checks current administrative authority
and key binding under the native writer lock. The key must also be valid at the
exact signed issue time. Keep the host clock correct.

The entire manifest, policy and original audit bytes must still match the plan.
Even an unrelated manifest or policy edit makes the plan stale. A plan is a
snapshot guard, never independent authorization.

Adoption preserves the original audit prefix byte for byte, appends exactly one
signed adoption entry, then atomically commits the manifest checkpoint and
`auditBaseline` receipt. Its closed signature payload binds the reviewed plan,
reason, actor, issue time and sequence. Document nodes, references, categories,
owners, content and existing signatures are unchanged. Unsigned historical
documents and entries remain unsigned: the new signature attests only to the
checkpoint adoption, not to historical authorship.

## Detached signing integration

An external runtime can retain its private key while PhantomDocs prepares and
verifies the fixed checkpoint operation. First create the reviewed plan as above,
then prepare a fresh request against the unchanged authoritative inputs:

```bash
pd audit-checkpoint-request --root ./docs --org-yaml ./org.yaml \
  --actor custodian --plan checkpoint-plan.json \
  --reason "Adopt reviewed legacy history" > checkpoint-request.json
```

This command does not load a signing key or write to the namespace. Its output
is the exact closed payload used by the existing signature format. It accepts no
caller-supplied digest. Preparing a request does not authorize a runtime to sign
it: the integration must authenticate its operator, independently bind the
approved organization, actor and complete request, and refuse arbitrary signing.

The runtime returns exactly `payload`, `sigPubkey` and `sig`. The payload must be
unchanged. The signature is the existing Schnorr mutation signature over
`mutation_message(_envelope(payload))`, including both existing domain prefixes.
A Nostr access-link signature is not a substitute. No runtime adapter, signing
socket, HTTP service or PhantomBot change is shipped by this receiver feature.

Once that adapter has been separately reviewed and tested, apply its response:

```bash
pd adopt-audit-checkpoint --root ./docs --org-yaml ./org.yaml \
  --actor custodian --plan checkpoint-plan.json \
  --reason "Adopt reviewed legacy history" --signed-record checkpoint-signed.json
```

External mode never resolves `PHANTOMDOCS_NSEC` and cannot be combined with
`--nsec-file`. Direct library users must instantiate `DocumentService` with
`signing_key_from_environment=False` and no key file, then supply `signed_record`
to `adopt_audit_checkpoint`. Local key-file signing remains supported unchanged.

The record reader rejects duplicate fields and files larger than 64 KiB.
Application rechecks current administrator authority, full source guards, the
signature, the exact plan/reason/actor, and key validity both now and at issue
time under the writer lock. A fresh external signature must be within 60 seconds
of the host clock. This freshness check applies only before the first append;
retrying the identical pending or committed record may complete after that
window. Changed durable evidence is refused, never replaced by a new signature.

Request and response files contain no private key, but expose operational
identifiers and digests: keep them private. This feature does not approve or
activate any deployment or alter the trusted local-writer boundary.

## Interrupted operations and verification

- Before a complete audit append: the manifest stays unchanged. A clean failure
  can be retried; a torn or short append is preserved and requires manual review.
- After the complete signed append but before manifest commit: ordinary writes
  and recovery refuse the pending adoption. Retry the same command with the
  original plan, actor and reason. It verifies the durable signed record and
  source guards, then completes the manifest without appending another entry.
- After manifest commit: retrying the same operation returns `unchanged: true`.
  Unknown extra entries, changed policy, invalid signatures and mismatched
  receipts are refused rather than truncated or silently repaired.

`pd verify --org-yaml` checks the receipt, original audit prefix and historical
key binding. Verification of an adopted namespace requires the organization
model. Normal recovery can still discard a provably uncommitted ordinary tail
after the adopted checkpoint; it cannot discard the adoption itself.

These guarantees use the existing trusted local writer and native lock model.
Every writer must honor that lock. The signature is not an independent proof of
historical administrator permissions: administrative authorization is checked
against PhantomOrg when adopting, and the policy digest records that snapshot.
It does not provide external rollback detection for replacement of the entire
store; existing external seals/checkpoints remain separate controls.

No daemon, timer, new dependency or automatic deployment is introduced. Linux
tests exercise native durable writes and interrupted retries; Windows control-
flow rehearsals do not establish POSIX mode or durability guarantees.
