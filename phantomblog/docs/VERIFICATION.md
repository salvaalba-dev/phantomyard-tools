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

The suite contains 59 tests covering catalogue/date/slug/category validation,
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

The proposal review and guided connection setup were checked in the browser at
1440 x 900 and 390 x 844 using disposable fixtures. Both language title changes
appeared as named before/after fields; HTML-like metadata remained literal text
with no injected image or script. Unsaved edits disabled proposal application.
Connection mapping checks left saved source untouched, credential arguments were
rejected, valid mappings could be added and saved, and an unavailable synthetic
server showed its actual status without claiming account authorization. Neither
view caused horizontal page overflow at the mobile width. A placeholder rendering
error found during browser verification was corrected and rechecked.

For a disposable review demonstration, run `python tests/preview.py --port 8791
--proposal-demo` on one line from the tool directory. It never adds sample articles
to a real workspace.

## Hardening update: 2026-10-08

- Live verification refuses a hostname that resolves to a nonpublic address and
  dials the exact address it validated, keeping the URL hostname for TLS and
  disabling proxies, so a second DNS answer cannot move the request. Local
  fixture verification is restricted to loopback and HTTP errors are closed
  instead of leaked.
- Releasing the workspace lock tolerates a lock file that already disappeared,
  instead of raising over the original error.
- Suites: 65 tests OK. `compileall` and `node --check` are clean.

## One-time access links: 2026-10-08

Branch: `codex/phantomblog-access-links`, based on main commit `c8889cf`.
No real identities, signing keys, tokens or access links were used in fixtures.
No external messages, publication, deployment or Git push was performed.

Implementation uses an explicit Nostr public-key allow-list and verified NIP-98
requests, with coincurve/libsecp256k1 for BIP-340 verification. Issuance never
returns the master token. Access codes are random, held as in-memory hashes,
expire after 15 minutes, and are atomically consumed only after session creation.
Host, Origin and Sec-Fetch-Site checks precede issuance/redemption. Both login
paths and logout set HttpOnly, SameSite=Strict and Secure cookies.

Checks ran from the component directory on Windows 11 and Python 3.12:

- `python -m pytest tests -q`: **79 passed, one existing Windows symlink test
  skipped**, plus 31 successful unittest subtests. A fresh owned `--basetemp`
  directory was necessary because Windows denied access to pytest's shared temp
  directory. All source/workspace fixtures are temporary.
- New regressions include valid, expired, used and invalid codes; real Schnorr
  signatures; allow-list, freshness, payload and URL binding; request replay;
  foreign Host/Origin; concurrent redemption; failed session creation; query/log
  exclusion; secure cookies; disabled issuance; missing verifier; CLI output.
- Node.js executed the real dashboard script against a minimal browser surface
  for successful and failed redemption. History cleanup occurred before fetch,
  the code appeared only in the POST body, and the valid case opened the app.
  JavaScript syntax validation passed. This is not an actual browser session.
- `python -m ruff check phantomblog tests`: **36 existing findings** remain in
  untouched files. Before this task there were 41 findings; touched modules were
  cleaned up. The changed Python files pass Ruff without exclusions.
- `python -m ruff format --check phantomblog tests`: **11 existing untouched
  files** require formatting. All four changed/new Python files pass the check.
- `python -m bandit -r phantomblog -q`: **five existing low-severity findings**
  (B404/B603) on the pre-existing executable-only subprocess integration in
  server.py/connectors.py. There are no medium/high findings or findings in the
  new access layer. No baseline suppressions or security-check exclusions were
  added to claim a clean full-component result.
- `git diff --check` passed. CI now installs the dev extra and runs pytest so
  the signature and dashboard regressions are collected.

Full-component lint/format/security checks were run but are not claimed clean.
Their existing findings are preserved to keep this authentication change scoped.

Manual browser acceptance remains unverified because Codex's browser helper
fails during Windows sandbox setup (reported upstream as openai/codex#52069).
A browser must accept Secure cookies on the trusted loopback origin. PhantomChat
requires a signer/adapter for NIP-98 requests; its chat UI alone is not sufficient.
The local issuer does not expose the dashboard publicly or send links itself.
Browser fragment/history/clipboard limits and leak recovery are documented in
README; history cannot be guaranteed never to observe a pasted fragment.
