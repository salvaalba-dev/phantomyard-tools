# One-time local checkpoint migration

`legacy_checkpoint.py` is an explicit operator utility for an unsigned, unsealed
legacy document store with a non-empty audit log and no committed checkpoint.
It does not require a persona signing key or a PhantomBot change. It is not a
daemon, scheduler, PhantomView runtime dependency or automatic setup operation.
New installations with valid initialized checkpoints do not need this migration.

## Trust and scope

This mode trusts the local administrator and the authoritative PhantomOrg model.
`--actor` selects a currently declared native namespace administrator; it is not
cryptographic proof of the caller's identity. Restrict execution and write access
to trusted host operators. The receipt records the local UID when available and
explicitly says `unsigned-local-admin`. It never claims a persona signed or
authenticated the migration.

Hashes detect divergence against the reviewed state; they do not authenticate
an attacker-controlled manifest or provide external rollback protection. Existing
signed or sealed stores, signature-required profiles, signed documents and signed
audit entries are refused. This utility is not an unsigned switch on the native
signed-adoption command and does not weaken its verifier.

Only native checkpoint header fields are updated. Original audit bytes remain
an exact prefix, followed by one unsigned `migrate-legacy-checkpoint` entry with
the reviewed plan, reason, timestamp and available operator UID. Document nodes,
versions, references, owners, classifications and content remain unchanged.
No `auditBaseline` signature receipt is invented. Existing unsigned document
operations continue using the ordinary native checkpoint protocol afterward.

## Review and rehearse

Use a reviewed checkout matching the tested PhantomDocs version. This contrib
script is not a new installed `pd` command. Keep all operational artifacts private
and preserve an operator-controlled copy of the source manifest and audit before
any real application. Coordinate writers and use an isolated copy for rehearsal.
Do not copy a persona directory or any signing keys for this operation.

```bash
umask 077
python phantomdocs/contrib/legacy_checkpoint.py plan \
  --root /private/rehearsal-store --org-yaml /private/org.yaml \
  --actor custodian > /private/checkpoint-review.json
python phantomdocs/contrib/legacy_checkpoint.py apply \
  --root /private/rehearsal-store --org-yaml /private/org.yaml \
  --actor custodian --review /private/checkpoint-review.json \
  --reason "Reviewed one-time local checkpoint migration"
pd verify --root /private/rehearsal-store --org-yaml /private/org.yaml
```

These paths and actor are synthetic. Review the actual plan and original history
before applying it. A rehearsal plan cannot authorize a different live store:
generate and review fresh live guards before the separately authorized live step.

Planning reads only. Apply reloads the organization and native manifest under the
existing host-local writer lock, rechecks administrative authority and the exact
manifest, policy and audit snapshots, and refuses stale or ambiguous state. It
never truncates or reinitializes the log. No credential is read or generated.

The tool uses native filesystem locking and atomic manifest writes. Durable-write
tests run on Linux; Windows control-flow rehearsals are not a substitute for
platform-specific durability validation. This historical repair adds no operating
system requirement to PhantomView or to other installations.

## Interrupted execution

- A failure before append leaves source data unchanged.
- A short or torn append stays on disk and requires operator review. Neither
  ordinary recovery nor this utility guesses which bytes to delete.
- After a complete receipt append but before manifest commit, ordinary native
  writes refuse the unknown checkpoint. Retry with the same reviewed plan and
  reason; the utility verifies the original prefix and pending receipt and
  completes the manifest without another append.
- A retry after commit returns `unchanged: true`. Conflicting receipts, extra
  pending entries, changed source guards and inconsistent checkpoints are refused.

After a successful migration, retain the private review and receipt evidence.
There is no recurring migration job to maintain. This utility does not reclassify
documents or change PhantomOrg permissions; those remain separate reviewed work.
