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
