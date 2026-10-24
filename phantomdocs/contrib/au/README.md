# Deployment-specific meeting ingestion

This contribution is fork-only deployment glue, not a generic PhantomDocs
command or a product-wide routing policy. It indexes already archived meeting
artifacts using an authoritative PhantomOrg model and existing persona tools.
It does not change ACL, move files, approve minutes, or activate a deployment.

Examples below are synthetic. Keep real account names, email addresses, archive
IDs, unit names, document titles and operational receipts in private deployment
configuration. This document does not identify the current state of any host.
The implementation still has deployment-specific bindings: review those before
reuse. Sanitizing this README does not sanitize other files or erase Git history.

## Grouping and completeness

Recognized legacy filenames lose their final extension, at most one terminal
`_YYYY-MM-DD-HH-MM-SS` timestamp, and at most one recognized artifact-class
suffix, in either order. The key uses Unicode NFC and casefold, preserving other
dots, title words and dates. Classification aliases are defined in the source;
unknown classes/extensions remain pending rather than being guessed.

A group must contain a transcription and summary. Minutes and an original MP4
recording are optional. A recording alone never makes a group eligible. Existing
indexed artifacts still participate in completeness so partial groups can resume.
The grouping context includes the source and project flag; unrelated inboxes
must not merge merely because filenames resemble each other.

Opaque branded names require a reviewed catalog with exact file IDs, current
names, source, meeting key, artifact class and project flag. Branding is preserved.
Use a distinct key for each meeting, shared only by its actual artifacts. Never
infer dates, confidentiality or project authority from a title.

## Classification and authority

Classification comes from the authoritative document-type policy. The existing
ordinary-meeting route requires category 2. The separately supported project
opt-in requires an explicit declared project-scoped category on the document
type, matching the implementation's supported project binding. It cannot be
inherited implicitly from a broad domain or invented in a recovery catalog.

The native PhantomOrg resolver must authorize the custodian to write and the
intended project actor to read. Owners constrain writes, not readers. Category-2
indexing permits every actor granted that category; it is not an invitee-only
permission check. Human/counterpart sessions need their own integration tests.

A changed type policy does not reclassify historical references. Classification
conflicts require an audited native transition preserving identities and history,
not a duplicate registration or a reset seen marker. Supporting materials and
sensitive non-meeting document types follow their separately approved process.

## Sources, archives and idempotency

Resolve actual sources, archive destinations and identifiers from reviewed private
deployment configuration and the authoritative model. Source selectors supported
by this contribution are deployment-specific; inspect `--help` and source bindings
before using them. Do not assume a project inbox is also its final archive.

Metadata enumeration uses Drive's read-only scope, paginates all results and
refuses incomplete searches. Indexing through `pd add --ref gdrive://ID` may read
bytes to compute native hashes, but registers a reference rather than uploading
an archive copy. See the [Drive list API](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list).

Before adding anything, inspect current and historical locations for its Drive
ID. An already indexed reference is skipped without another download or version,
even after a rename or missing seen marker. Conflicting classification/ownership
and orphan seen markers stop for review. Write a success marker only after the
expected native reference is observed. Preserve successful partial commits.

Scheduled scans and recovery share the same ingestion lock and state directory.
Unrelated manual writers may not honor that deduplication lock: coordinate them
before recovery. Edits under an existing Drive ID are not silently rehashed;
explicit document versioning remains a separate operation.

## Operator validation

Use a private configuration inventory rather than copying another installation's
accounts, directories or services. For example, a fictional secretary persona
might run as `pb-secretary` and use `secretary@example.org`; these are examples,
not defaults or deployment instructions.

Before installing a candidate:

1. Record the exact reviewed commit and run its regression tests in isolation.
2. Verify the effective service interpreter can import PhantomDocs and the Drive
   client dependencies. Inspect existing unit overrides and preserve rollback
   evidence; do not overwrite an existing backup or drop-in.
3. Check the authenticated service account, persona wrapper, authoritative store,
   organization file, source selectors and final archive bindings.
4. Plan with read-only metadata. Review complete groups, classifications, owners
   and every pending item before any real registration.
5. Test native search and the actual counterpart/session boundary using each
   actor's own authenticated account. Do not impersonate another actor or assume
   an account exists on a particular host.

The following commands use operator-supplied private variables. They are not a
ready-to-run installation or authorization to process documents:

```bash
"${INGEST_PYTHON}" "${INGEST_SCRIPT}" --help
"${INGEST_PYTHON}" "${INGEST_SCRIPT}" --source "${SOURCE_SELECTOR}" --inventory
"${INGEST_PYTHON}" "${INGEST_SCRIPT}" --source "${SOURCE_SELECTOR}" \
  --prepare-catalog "${NEW_PRIVATE_CATALOG}"
"${INGEST_PYTHON}" "${INGEST_SCRIPT}" --source "${SOURCE_SELECTOR}" \
  --catalog "${NEW_PRIVATE_CATALOG}" --dry-run
```

Use a fresh catalog filename because creation is exclusive. A dry run writes no
markers, lock or store content and does not read document bytes. Native integrity
verification is separate and may deliberately read indexed content. Do not use
`pd verify` as proof that recovery performs no downloads.

## Pending work and recovery boundaries

Structured HOLD records identify incomplete, unknown or unclassified artifacts.
A recognized project artifact outside its configured canonical archive remains
pending until an explicit reviewed catalog establishes its context. Its siblings
remain held too. Independent complete authorized groups can still be indexed.

Exit 0 means no pending artifacts and no indexing errors; exit 2 means a partial
pass requiring review; exit 1 means an integrity, policy or execution failure.
Dry-run uses the same status distinction. Existing scheduler logs retain the
operational evidence; no extra service or parallel registry is introduced.

Unknown catalog IDs, changed names, source collisions, unauthorized policy,
classification conflicts and orphan markers remain fatal. Never broaden access,
move files, delete originals or reset markers merely to silence a HOLD.

Delivery and final archival belong to the deployment-owned processing/archiving
circuit. This utility does not implement them. The document-workflow handover is
a separate opt-in integration, not an automatically active replacement. Cleanup
must remain subject to verified delivery and archival evidence in that circuit.
