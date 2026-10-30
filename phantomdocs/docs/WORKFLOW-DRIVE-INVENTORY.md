# Read-only Google Drive inbox inventory

`pd workflow inbox-inventory` builds the bounded metadata input for
[`pd workflow scan`](WORKFLOW-INBOX-SCAN.md) from one explicitly selected Drive
folder. It uses a caller-supplied OAuth access-token file and the existing
standard-library HTTP client; it does not discover or refresh credentials.

```bash
pd workflow inbox-inventory \
  --inbox-ref 'gdrive://DECLARED_INBOX_FOLDER_ID' \
  --drive-token-file /private/drive-access-token \
  --max-items 1000 > /private/inbox-inventory.json

pd workflow scan \
  --inventory /private/inbox-inventory.json \
  --installation /private/config/reference-installation.json \
  --org-yaml /private/config/org.yaml \
  --root /private/documents \
  --phantombot-config /private/config/phantombot.toml \
  --domain projects --document-type report --requesting-domain projects
```

The inventory command verifies the selected folder metadata, then lists only its
direct children. It uses the shared-drive corpus when Drive identifies one and
the signed-in user's corpus otherwise. It follows every page, refuses repeated
page tokens, incomplete searches, wrong-parent results, duplicate file IDs,
oversized responses and more than 1,000 items. Only after the last complete page
does it emit `complete: true`. Size and Drive's revision counter remain provider
metadata strings; the scanner never treats the revision counter as a semantic
document version. The resulting JSON is also capped at 4 MiB so it can be passed
directly to the scanner.

This is a bounded API enumeration, not a transactional snapshot. Files can change
while pages are being read. No file body is downloaded, no digest is computed,
and no Drive object is moved or modified. A later execution must recheck folder
membership and current metadata, then verify bytes before native indexing. An
incomplete response fails the command instead of producing a partial inventory.
Native Google documents and shortcuts remain visible as metadata and are held by
the scanner for separate export review.

The OAuth token file must be a regular, private file; POSIX requires it to be
owned by the caller with mode `0600` or stricter. The command sends only HTTPS
GET requests to Google's fixed Drive API host and refuses redirects, so an
Authorization header is not forwarded to another host. Response and item limits
bound local memory and parsing work.

This command does not admit workflow jobs, change PhantomOrg, access PhantomBot,
publish to PhantomView, create a service or timer, or delete inbox files.
