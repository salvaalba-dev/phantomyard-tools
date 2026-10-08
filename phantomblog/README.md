# PhantomBlog

Static bilingual publishing with a private editorial dashboard and agent proposal
workflow. Python 3.11+, standard library for builds and the original dashboard; signed access links
use an optional Schnorr verification dependency. Public websites receive
HTML, CSS and image files; they need no Python service or new build step.

Development home: `salvaalba-dev/phantomyard-tools/phantomblog`. A future upstream
submission to `phantomyard/phantomtools` is a separate human decision. No runtime
behaviour, installer or generated URL depends on the GitHub owner name.

## What works in v0.1

- Articles, bilingual categories, dates, drafts, featured styling and image uploads.
- Supplied English/Spanish HTML bodies, inline or in body source folders. No AI
  writing or translation happens during a build.
- Site → category → article design defaults, three layouts, section ordering,
  scoped article CSS and a shared HTML template editor.
- Deterministic archives of 12 records, localized metadata, raster social previews,
  language links and visitor share destinations.
- Validation before writes, source revision checks, manifest ownership and atomic
  file replacement. Existing legacy pages keep their bytes and URLs.
- Authenticated loopback dashboard; MCP stdio tools read/build/propose. Humans
  review agent proposals and control external publication.
- Configurable MCP deployment, social and PhantomChat messaging adapters. The
  reviewed workflow builds, deploys if selected, verifies exact live HTML and then
  shares, with per-connection receipts and duplicate protection.

Platform names in the dashboard are **configuration choices**, not bundled account
connections. A working MCP server, provider authorization, and its actual tool
schema must be configured on the target Phantombot machine. This checkout contains
no credentials and has not posted to any platform. PhantomChat opens its existing
client and prepares article context; in-dashboard sending requires a verified
messaging MCP adapter. It does not embed or copy the GPL PhantomChat client.

## Start locally

From the `phantomblog/` directory:

```sh
python bin/phantomblog --root /absolute/path/to/my-blog init
python bin/phantomblog --root /absolute/path/to/my-blog --json dry-run
python bin/phantomblog --root /absolute/path/to/my-blog build
python bin/phantomblog --root /absolute/path/to/my-blog check
```

Replace the path with your workspace. The default workspace is beside this tool,
not relative to the caller's current directory. Explicit relative `--root` paths
are resolved from the caller. Every content/asset/output path is resolved from
that workspace. On Windows use `python bin\phantomblog` or `bin\phantomblog.cmd`.
No package installation is required. `pip install .` is optional.

Set an administrator token through your process manager or Phantombot vault.
For a standalone development session, inject a random token into
`PHANTOMBLOG_ADMIN_TOKEN` without saving it in the repo. Then:

```sh
python bin/phantomblog --root /absolute/path/to/my-blog dashboard
# Or resolve it through the existing persona vault:
python bin/phantomblog --root /absolute/path/to/my-blog dashboard \
  --token-ref vault:PHANTOMBLOG_ADMIN_TOKEN --persona editorial
```

The master token stays in the dashboard process; request a one-time access link
as described below. The service binds only
to loopback and checks authentication, Host and Origin. For remote access use an
authenticated tunnel retaining that URL; exposing this HTTP listener is not a
supported production setup. Tokens never go in URLs or browser storage.

## Authoring and integration

Read [the agent workflow](docs/AUTHORING.md), [connector configuration](docs/CONNECTORS.md),
[architecture and ownership](docs/ARCHITECTURE.md), and [verification](docs/VERIFICATION.md).

Sources live in `blog.json`, optional `bodies/`, `assets/` and `templates/`.
Generated files live in `public/`. Commit sources **and** generated files to your
website repo. Your existing GitHub-to-server sync can publish them unchanged.
PhantomBlog itself never silently commits, pushes, merges or changes server cron.

Exit codes: `0` success; `1` stale outputs from `check`; `2` invalid input, unsafe
ownership or unavailable local source; `3` external integration failure or partial
sharing failure; `130` interrupted. `check` and `dry-run` write no files and make
no network calls. Their results do not mean a page is live.

## Install and test

Linux/macOS: `./install.sh` symlinks the reviewed checkout's wrapper into
`~/.local/bin` (or `$PREFIX/bin`). It refuses to overwrite divergent installed
copies. Windows: add this tool's `bin` folder to PATH through system settings.

```sh
python -m unittest discover -s tests -v
node --check phantomblog/resources/dashboard.js
python tests/preview.py --port 8790
```

The preview creates a disposable test workspace with clearly labelled synthetic
articles, images and a synthetic login token declared in `tests/preview.py`.
It performs no deployments or messages. Stop it with Ctrl+C. Fixtures are never
installed into a real publication.

MIT. See [LICENSE](LICENSE).

## One-time dashboard access (PhantomChat identities)

Install the optional signature verifier with `python -m pip install ".[access]"`.
Start the dashboard with an explicit allow-list of lowercase, 64-character hex
Nostr public keys belonging to the humans allowed to request access:

```sh
python bin/phantomblog --root /absolute/path/to/my-blog dashboard \
  --allow-identity <human-public-key-hex> \
  --allow-identity <another-human-public-key-hex>
```

The administrator token is still resolved on the server from the configured
environment or vault reference. It is not returned, used in a link, or required
by the requesting human. No allow-list means issuance is disabled. Display names,
NIP-05 aliases, text claiming to be a person, and relay/bot identities do not grant
access. Each allowed public key must sign its own request.

A configured PhantomChat/Phantombot adapter requests a link on the human's behalf
using that human's signed [NIP-98 HTTP authorization](https://github.com/nostr-protocol/nips/blob/master/98.md).
Use a kind `27235` event with empty content, a current integer `created_at`, and
exactly one of each required tag:

```json
[
  ["u", "http://127.0.0.1:8787/api/access-link"],
  ["method", "POST"],
  ["payload", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"]
]
```

The payload hash is SHA-256 of the exact request bytes `{}`. The event ID is the
NIP-01 canonical hash; the signature is BIP-340 Schnorr. Send the base64-encoded
complete signed event in `Authorization: Nostr <base64-event>` with
`POST /api/access-link`, `Content-Type: application/json`, and body `{}`.
Signatures must be within 60 seconds of server time; a signed request can only be
used once. It is bound to the exact URL, method and body. Never give the adapter
an `nsec`, private key or the master dashboard token.

Alternatively, submit the already-signed event from a file using the CLI:

```sh
python bin/phantomblog access-link --port 8787 --signed-event /private/request.json
```

It prints one line, `http://127.0.0.1:8787/#c=<one-time-code>`. Deliver that link
privately to the requesting human; never broadcast it on a Nostr relay. PhantomChat
uses Nostr identities, but its current chat UI does not itself sign NIP-98 HTTP
requests: an adapter with access to the human's approved signer is required.
This change does not install a relay listener or automatically send a message.

Paste the link into a browser with access to the local dashboard. The browser
immediately removes the fragment with `history.replaceState`, submits the code
in a JSON POST, and enters the existing authenticated dashboard. The cookie is
HttpOnly, SameSite=Strict and Secure, including logout. Use a browser that accepts
Secure cookies on trusted loopback HTTP; do not remove Secure to accommodate a
browser that refuses them. Host and Origin checks and the loopback-only bind are
unchanged. Remote clients need an authenticated tunnel retaining this exact
loopback origin; a remote client cannot reach this machine's loopback by simply
opening the link. Public HTTPS hosting is not added by this feature.

Links expire after 15 minutes and are consumed only by a successful login. They
are bearer credentials: anyone with the link can use it first. Codes are stored
only as in-memory hashes, never in source files, browser storage or server logs.
The fragment is not sent in the page request or HTTP Referer; JavaScript erases
it before API calls. Browsers, clipboard managers, extensions or history sync
can still capture a pasted URL before JavaScript runs, so a blanket guarantee of
no browser-history exposure is impossible. Do not put links in shared history.

If a link leaks, restart the dashboard to invalidate all outstanding links and
sessions, then request a new link. If an identity is compromised, remove its
public key from the allow-list before restarting. Restarting never revives a
consumed code. Keep signed events and access links out of Git and application logs.

Development checks for this component (install `.[dev]` first):

```sh
python -m ruff check phantomblog tests
python -m ruff format --check phantomblog tests
python -m bandit -r phantomblog -q
python -m pytest tests -q
```

The JavaScript bootstrap regression uses Node.js when available; set
`PHANTOMBLOG_TEST_NODE` to its executable path if it is not on PATH. Build and
original dashboard functionality still work without the access extra. Signed
access was verified on Python 3.12; some newer Python versions may lack a
prebuilt coincurve wheel and require its native build prerequisites.
