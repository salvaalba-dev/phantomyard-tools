# Copy reconciliation prototype

`review_receipt` accepts a trusted, locally sourced receipt
claim with explicit intake reference, archive reference and SHA-256. The caller
must validate the receipt's provenance; this function cannot authenticate it.

The function resolves the expected inbox from PhantomOrg, checks that the caller
may read the referenced native record, reads the intake copy through a bounded
Drive reader, and compares its SHA-256 to the receipt and native content hash.
It checks provider metadata both before and after reading. A missing, ambiguous,
unauthorized, changed, or inconsistent item requires review. A matching result
is still a review result: it never authorizes registration, publication, moving,
or deletion. Matching bytes alone do not establish semantic identity.

The operation downloads the intake file into a temporary snapshot. It is not a
metadata-only scan. The caller must separately control access, receipt storage,
size limits, consent, snapshot cleanup and any subsequent action. Metadata
checks cannot prevent a change after the final observation. No production
configuration or provider credentials are supplied by this prototype.

The separate experimental local audit-link operation uses the existing manifest
lock, audit chain and checkpoint. It records the document identity, inbox and
archive references, content digest, actor, declared inbox and policy hash. It
accepts only unsigned, unsealed stores, checks current content and policy again,
and attempts to resume an interrupted audit-first commit without truncating the
log. Generic audit recovery refuses to discard a pending intake-link entry;
the dedicated operation must reconcile it. The receipt is still an
operator-supplied claim and is not authenticated.
The operation is explicit and is not connected to the live intake pipeline.
POSIX locking, crash durability, receipt provenance and concurrent writers
must be verified for each deployment.

The proposed audit entry declares `trusted-local-process` and records the local
effective UID and a digest of normalized receipt claims. This deliberately uses
the installation's existing trust boundary: any code controlling that same OS
account can make claims as that account. The UID and digest do not prove the
identity of the original sender, authenticate a receipt, or add a signature.
Legacy receipts require an explicit local review before being promoted into a
private trusted directory. No PhantomBot changes or new signing keys are needed.

## Explicit local workflow

`pd workflow copy-link-review` produces a plan without reading the source file.
The operator supplies the existing document URN, archived and inbox references,
the document SHA-256, and the inbox name declared in PhantomOrg. Save the plan
in a private file and review it. `pd workflow copy-link-apply` reads that plan and
an independently reviewed normalized receipt from a private directory, then
rechecks the inbox file using a bounded Drive reader before appending the audit
entry. Both commands require the local actor and PhantomOrg model. A local actor
name is not remote authentication; the caller must protect the store, token,
receipt creation and local identity mapping.

The normalized receipt is an object with exactly `inbox_ref`, `archive_ref` and
`sha256`. Operator review and current source verification are mandatory; copying
arbitrary legacy receipt contents into this file does not authenticate them. No
operation deletes or moves inbox data or publishes to PhantomView.

`pd workflow scan --use-local-copy-links` opts into reading local audit links.
An authorized matching row is `linked-reference`, never a new job. It reports
`content_reverified: false` and `requires_current_content_check: true`; the
intake object could have changed since it was linked. Conflicts remain held.
Unsigned, unsealed, checkpointed local stores are required for this opt-in.
