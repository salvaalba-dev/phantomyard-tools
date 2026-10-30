# General document inbox scan

`pd workflow scan` is the metadata-only first step toward general document
intake. It reuses the existing workflow planner and PhantomOrg access resolver;
it does not introduce an alternative category model, daemon, or document store.
The existing meeting importer remains unchanged.

## What the command does

For one explicitly configured inbox and document context, the command:

1. Requires a complete, bounded inventory and a structurally valid native store
   belonging to the selected organization.
2. Resolves category, write owners, default processor, tools and destination
   through the existing installation and PhantomOrg planner.
3. Produces one `reference-document` proposal for each eligible binary original.
4. Reports existing references across native history without making another job.
5. Holds foreign-inbox objects, incomplete fingerprints, trashed objects, native
   cloud documents requiring export, and conflicting existing identities/policies.

The native destination folder must already exist. The operator supplies the
domain, document type and requesting domain explicitly; filenames never choose
a security category or department. Unknown inventory fields, including category
or requester overrides, are refused. Read/write authority comes from PhantomOrg.
Category inheritance is handled by that resolver, not duplicated by the scanner.

## Inventory contract

An existing trusted metadata adapter supplies this JSON without document bodies:

```json
{
  "version": 1,
  "complete": true,
  "items": [
    {
      "id": "example-application-id",
      "name": "Application.xlsx",
      "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "parents": ["example-project-inbox-id"],
      "size": "773",
      "version": "29",
      "md5Checksum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

The inventory is UTF-8, at most 4 MiB, 1,000 entries and 64 nesting levels. Duplicate JSON keys,
duplicate file IDs, incomplete pagination and invalid metadata are refused.
The adapter must follow every provider page before setting `complete: true`;
that flag and the parent IDs remain adapter-supplied claims, not independently
verified evidence. The command does not call Drive or refresh credentials.

Size, Drive revision counter and MD5 retain their provider string types. Missing
binary fingerprints are held. The revision counter is never a semantic document
version: proposals explicitly return `document_version: null`. The request ID is
stable for the same organization, reference and fingerprint; metadata ordering
does not create another request. A changed provider revision produces another
proposal, not an automatic document version or authorization to overwrite one.

## Usage

Use the existing installation contract with an explicit `reference-document`
route. Its `intake.inbox` resolves to `documents.inboxes` in PhantomOrg. Run as
the declared local planner account; `--actor` is not remote authentication.

```bash
pd workflow scan \
  --inventory /private/review/inventory.json \
  --installation /private/config/reference-installation.json \
  --org-yaml /private/config/org.yaml \
  --root /private/documents \
  --phantombot-config /private/config/phantombot.toml \
  --domain projects --document-type report --requesting-domain projects
```

Exit 0 means the metadata scan was planned without held or blocked entries.
Exit 2 means review is required, preserving independent proposals in the report.
Exit 1 means an invalid contract, unauthorized policy or other input failure.
An empty inventory still validates the installed policy and destination.

## Deliberate execution boundary

Every report and native plan has `execution_ready: false`. Admission, publication
and cleanup are `not-performed`. The command reads metadata/configuration only:
no source-byte downloads, hashing, transformation, archive operations, native
mutations, journal creation, memory capture, services or notifications occur.
Reported MD5 and parent membership do not replace SHA-256 verification.

An `indexed-reference` result means only that an existing native identity is
known. It has `content_reverified: false` and
`requires_current_content_check: true`: neither a changed Drive object nor its
current version has been verified. Classification/ownership conflicts are held;
the scanner never silently reclassifies a document or creates a second identity.
Native structural validation is not cryptographic or content verification.

The generated job's requester is the authenticated **local planner**. No remote
sender is authenticated, signature produced, ledger entry admitted, or existing
signed execution check bypassed. Inventory files and adjacent intake requests
must not be treated as authorization instructions.

An execution adapter must independently recheck actual inbox/archive membership,
source bytes, current ACL and metadata, bind authorized intent to its operation,
resolve semantic identity/version and format grouping, and reconcile native
commits through `DocumentService.index_reference_once`. It must then confirm
PhantomView publication before closing or removing intake copies. A new proposal
does not prove these steps or authorize cleanup.

The remaining integration is intentionally separate: connect the existing
ingestion timer/archiver to authorized native execution and the viewer's verified
publication handover, with durable receipts and crash reconciliation. This PR
does not activate an automatic general-document pipeline in any installation,
change PhantomBot, or require a new service.
