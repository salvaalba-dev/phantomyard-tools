# Verification record

Verified locally on Windows with Python 3.14, using the supported Python 3.11+
standard-library APIs. CI is configured to run the same tests on Ubuntu; it has
not run on GitHub because this branch has not been pushed.

## Automated checks

```sh
python -m unittest discover -s tests -v
python -m compileall -q phantomblog
node --check phantomblog/resources/dashboard.js
bash -n install.sh
```

The suite contains 54 tests covering catalogue/date/slug/category validation,
language completeness, raster assets and uploads, escaped metadata, authored body
HTML, scoped CSS, shared template validation, output ownership, invalid-input
preservation, deterministic builds and read-only commands. It also checks legacy
byte preservation, archive boundaries 0/1/12/13/25, chronological/slug ordering,
featured styling without duplication, pruning only numbered archives, source CAS,
reviewed agent proposals, MCP initialization/tools, auth/Origin/cookie behaviour,
exact live verification, deployment-before-sharing, response contracts, uncertain
results, duplicate protection, reconciliation and explicit persona targeting.

One symlink fixture test is skipped on this Windows account because it cannot
create symlinks. It runs on hosts with symlink permissions, including the configured
Linux CI runner. The path containment implementation is still exercised by traversal
and unsafe manifest tests locally. Installer shell syntax was checked with Git Bash;
no global installation or persona changes were performed.

## Browser checks

Disposable fixture workspace only, containing 13 clearly identified synthetic
articles and a generated raster image. Nothing was added to a live publication.

- Desktop: 1440 × 900. Mobile: 390 × 844 and 320 × 760.
- Login, content editing/save, English/Spanish selection and saved preview.
- Article layout selection and cover/body/lead section ordering.
- Category creation and English/Spanish label editing.
- Shared template load, validation and save.
- Working local build/freshness controls and configuration forms.
- Cover image loads at its authored 1200-pixel width; scoped preview styles load.
- Reciprocal article language links and English → numbered archive → corresponding
  Spanish archive navigation retain page 2.
- At mobile widths the document has no horizontal overflow. The fixture table
  scrolls inside its own width instead of widening the document.
- Sharing destinations contain the configured public URL and correct language URL;
  no share link was submitted and no real post was sent.

An initial preview sandbox blocked styles/images. It was corrected to retain the
same origin while disabling scripts; the authenticated asset routes then loaded
successfully. The private preview also applies a restrictive CSP and never runs
the website dictionary translator.

## External limits

MCP adapter calls, receipts, failures and memory capture were tested with synthetic
providers, and HTTP verification with a local fixture server. A subsequent real
installation check found native Windows Phantombot v1.1.422, outside the session
PATH. Its executable runs, and its MCP registration/call help matches the adapter
contract. The default persona's registry listed no MCP servers. Explicit runtime
path selection was added and tested; no persona registry was changed in that
check. Real MCP acceptance subsequently passed on an explicitly selected existing
persona: tool discovery, bilingual snapshot (Spanish accents preserved), read-only
dry run, deterministic builds, two-language pagination, proposal creation without
application, and prepare-only publication. The uniquely named temporary registry
entry and synthetic workspace were removed afterwards. This caught and fixed the
runtime's human-readable discovery format and Windows UTF-8 transport issue.
The direct PhantomChat editing workflow subsequently passed with a running
persona: a human-authorized request was sent through the signed-in browser client,
the persona read the registered PhantomBlog snapshot and submitted a proposal.
An independent comparison confirmed only the supplied English/Spanish title edits,
the original source revision, unchanged saved source and draft status. The proposal
loaded in the dashboard for review and remained unapplied until the user's explicit
approval. After approval it was applied through the dashboard, both language
previews showed the exact titles, and build/check passed. Draft article pages were
excluded from public output; nothing was deployed or socially shared. A temporary
directory inaccessible to the live harness initially prevented this flow. Placing
the synthetic draft under the repository's ignored `workspace/` resolved it without
changing permissions, identities or the active persona. This verifies direct chat
delivery, not the dashboard's optional messaging MCP adapter.

No production OAuth, deployment or social post is claimed as verified. Those are
separate setup/acceptance steps on the target installation. The source includes
configuration instructions and exposes unavailable connections accurately.

To repeat the opt-in real installation test (it temporarily registers a local
server for the selected persona; it does not message or publish):

```powershell
python tests/runtime_acceptance.py --executable 'C:\absolute\path\phantombot.exe' --persona YOUR_TEST_PERSONA
```

Use an actual lowercase persona name. The acceptance runner never changes the
active persona or removes an unrelated connection. The regular CI suite uses
synthetic providers and does not require an installed Phantombot runtime.

The existing Aquaponics repository was checked separately: it remains at commit
`5555ac7`, with only its previously unrelated authoring prompt untracked. No new
Aquaponics content, server sync or cron change was made for PhantomBlog.
