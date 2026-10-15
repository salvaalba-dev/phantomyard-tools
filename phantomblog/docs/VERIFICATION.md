# Verification: link-only dashboard

This record covers the current authentication change, using disposable workspaces
and newly generated synthetic keys only. No live site, persona store, relay,
provider account or external publication was used. No instance identities or
hosts are included in these instructions.

## Repeat the checks

From `phantomblog/`, with Python 3.11+:

```sh
python -m pip install ".[dev]"
python -m ruff check phantomblog tests
python -m ruff format --check phantomblog tests
python -m bandit -r phantomblog -q
python -m pytest tests -v
node --check phantomblog/resources/dashboard.js
```

Use a fresh owned `--basetemp <disposable-directory>` if the OS restricts pytest's
shared temporary directory. `PHANTOMBLOG_TEST_NODE` may select a Node executable.
Tests generate keys inside temporary fixtures and operate only on fixture servers
bound to ephemeral loopback ports. Persona stores are read-only during requests.
The public-origin regression uses an in-test generated `.invalid` hostname;
requests still go to the fixture's loopback listener, with synthetic Host/Origin
headers. It never resolves or contacts that hostname.

Coverage includes five-minute expiry, real Schnorr verification, wrong identities,
invalid signatures, URL/method/payload binding, stale and replayed events, invalid
and consumed codes, concurrent redemption, session-creation failure, missing
allowlist and dependency, fragment-only delivery, query/log exclusion, foreign
Host/Origin rejection, and Secure cookie authentication/logout. Persona CLI tests
exercise fresh runtime hex/nsec keys, checksum rejection, arbitrary persona ids,
missing stores, private errors, repeated issuance and unchanged identity files.
Static-token routes/options and Bearer authorization cannot authenticate.

The full suite also covers catalogue validation, bilingual output, ownership,
legacy preservation, deterministic builds, pagination, read-only commands,
reviewed proposals and synthetic connector publication/reconciliation workflows.
A source audit refuses embedded full nsec/npub values or literal 64-hex identities.
It does not claim to prove absence of every possible secret encoding.

Node executes the actual dashboard bootstrap against a minimal browser surface,
checking that history cleanup precedes fetch, the code goes only into the
redemption POST body, and success opens the app. This is a script regression,
not a live browser or deployed proxy acceptance test. A real HTTPS proxy, cookie
behaviour in the selected browser and remote delivery still require operator
acceptance. The preview helper creates disposable content and an ephemeral
signing identity, prints a five-minute link, and sends no external messages:

```sh
python tests/preview.py --port 8790
```

## Recorded results

Checked on Windows with Python 3.12.14, pytest 9.1.1, coincurve 21.0.0,
Ruff 0.16.10 and Bandit 1.9.4. Tests used a fresh owned temporary workspace;
Node ran the real dashboard bootstrap regression.

- Full pytest: **94 passed, 1 skipped, 31 subtests passed in 28.97 seconds**.
  The skip is the existing Windows symlink-permission fixture.
- Changed Python files: Ruff check and Ruff format check pass.
- Changed production Python files: Bandit passes with no findings.
- Full-component Ruff check: **31 existing findings in untouched files**.
- Full-component Ruff format check: **9 untouched files require formatting**.
- Full-component Bandit: **3 existing low-severity B404/B603 findings**, all in
  the untouched executable-only subprocess connector. No medium/high findings.
- Dashboard JavaScript syntax and `git diff --check` pass.

Full-component lint/format/security checks were run and their complete failures
are retained in the delivered check output; they are not claimed clean. No
baseline suppression or exclusion was added. Python 3.11 compatibility follows
the supported APIs but was not separately executed in this Windows session.
No browser/proxy deployment, provider call, real identity read, live site edit,
external message or Git push was performed.
