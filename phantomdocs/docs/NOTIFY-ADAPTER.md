# Persona-aware notification adapter

`src/phantomdocs/notify_adapter.py` is the version-controlled stdlib-only
transport behind the policy alert router. It requires Python 3.11+ and Linux
protected paths/locking. Copy/build from a reviewed Git revision during a
separately approved installation; do not depend on an unversioned host script or
an old workspace. Preparing this file does not install it or send notifications.

The alert launcher and route script remain separate from the publisher venv.
Both Telegram and email route entries can use the same `notify-adapter` launcher;
the validated input channel selects the transport. Actual destinations and paths
belong in private protected configuration. Public examples contain synthetic
identities and intentionally incomplete workspace settings.

## Runtime persona resolution

The order is exactly:

1. Explicit `--persona`.
2. `PHANTOMBOT_PERSONA`.
3. `default_persona` in the selected installation's `state.json`.
4. `default_persona` in its global `config.toml`.
5. Its only existing persona directory, if exactly one exists.
6. A clear failure requesting explicit selection.

There is no built-in persona name. Stated invalid or nonexistent selections
never fall through to another persona. The state is below the explicitly selected
`data_dir`; the global configuration path is also explicit. `personas_dir` in
global configuration is respected; otherwise the namespace is `data_dir/personas`.
All selected paths and ownership must pass protected descriptor-based traversal.
The selected persona directory must exist before credentials are read or an
external request is attempted. This adapter does not read signing identities or
perform Nostr signing.

The existing outer scripts forward only a validated `PHANTOMBOT_PERSONA` routing
value along with fixed PATH/LANG. Other environment secrets are not inherited.
When called by systemd, resolution uses that unit's actual execution environment,
not the environment of a failed unit or a previous terminal session. Missing
configuration must be resolved explicitly before activation; do not assume a
systemd instance automatically inherits an interactive persona selection.

## Root-controlled runtime configuration

The runtime JSON is metadata, not a credential store. Its dedicated reader
requires root ownership on the file and every ancestor, with no group/other
directory write bits. A service can read a root-owned **0640** profile only when
the file group is its effective primary group. Supplementary-group access alone
does not qualify. Root operators can also read root-owned **0600** profiles.
Public-readable, group-writable, special-bit, linked, oversized or concurrently
replaced files are refused. The reader never repairs permissions or ownership.

During a separately authorized installation, keep code/wrappers under a protected
root-owned directory such as `/usr/local/lib/example-alerts/` (0755). Runtime
profiles can live under `/etc/example-alerts/` (root:existing-service-group 0750),
with root:existing-service-group 0640 files. Use only the selected service's
existing primary group; do not add memberships or relax access to persona data.
The root-controlled route configuration and executable checks remain separate.

Telegram credentials and ledger files retain their independent exact **0600**
checks. A private ledger directory can be owned by the existing service identity
with mode 0700. Runtime group readability never permits group-readable tokens
or ledger rows. These are preparation rules, not an instruction to modify a host.

## Direct Telegram

The adapter reads only `personas/<resolved>/config.toml`, requires mode **0600**,
and reads `channels.telegram.token` and the existing `allowed_user_ids`. The
explicit positive chat ID must already belong to that authorization list. It
never borrows a host/default token, edits configuration, adds an allowlist entry,
repairs a mode, or sends to a group implicitly.

It calls the fixed HTTPS Telegram `sendMessage` endpoint directly, disables
environment proxies and redirects, checks the exact returned private chat ID,
and requires positive integer `message_id` and `date`. The provider ID and
timestamp are stored in the private ledger. Telegram's [Bot API contract](https://core.telegram.org/bots/api#sendmessage)
defines the returned Message; acceptance is not a claim that the human read it.
The token stays in process memory/request handling, outside subprocess arguments,
ledger rows and diagnostic output. Provider exceptions are not echoed because
their URLs may contain a token.

## Existing workspace mail transport

Only the selected persona's `tools/workspace.py` can be invoked. Its exact
SHA-256 must match the reviewed runtime configuration. The script is invoked
through fixed `/usr/bin/python3`, without a shell or interactive stdin. A root
caller drops to the installation owner's existing UID/primary GID with no
supplementary groups; other callers must already be that UID. HOME and
PHANTOMBOT_PERSONA are set explicitly for that existing execution identity.
No account, grant, scope or credential file is created or changed by this adapter.

The bound interface is `workspace.py send <to> <subject> --body <msg>`.
`workspace_send_args` must therefore be exactly
`["send", "{recipient}", "{subject}", "--body", "{message}"]`. Guessed options,
additional arguments and reordered placeholders are refused. The adapter supplies
one fixed operational subject and preserves the recipient and body as separate
arguments without a shell.

`workspace_receipt` must be `message-id-line`: stdout must contain exactly one
complete `Message ID: <value>` line, which the installed tool writes as
`✅ Sent. Message ID: <value>`; the prefix is accepted, the value is kept. A
placeholder value (`?`, printed when the provider returns no id), two receipt
lines, JSON IDs and exit success alone are refused.
Raw stdout/stderr are neither persisted nor forwarded. The example now contains
these concrete arguments and receipt format, but its source hash remains an
invalid placeholder. Pin the SHA-256 of the actual selected persona's script and
review that its command/output match this contract before activation. No hash of
an uninspected installation is invented, and no real mail delivery was verified
by these local tests.

An optional later SENT lookup can confirm that the provider retained a message,
but only through an already-authorized read interface. Do not request
`gmail.readonly`, change OAuth scopes, or treat SENT presence as a recipient read
receipt. This candidate neither adds that scope nor performs that lookup.

## JSONL ledger and uncertain delivery

Every send has a generated attempt ID. A private 0600 JSONL record with status
`attempting` is appended under flock and fsynced **before** external transmission.
A second record stores `accepted` plus the provider ID/date, or
`failed-or-unknown` without exception details. Fields are UTC date, attempt ID,
resolved persona, channel, recipient, provider message ID/date and status. No
tokens, bodies, body hashes, raw provider responses or credential paths are stored.

The ledger parent must already be protected and accessible to the existing
execution identity. The adapter can create its own new 0600 ledger, but never
changes permissions on an existing file. Symlinks, hardlinks, wrong ownership,
loose file modes and a torn final row are refused. Existing rows are not repaired
or removed. Concurrent cooperating writers serialize complete rows; directory
and file durability use ordinary fsync descriptors, not O_PATH descriptors.

A timeout, invalid provider reply, process death or failure to persist the final
receipt can follow a real delivery. An `attempting` row without a final record is
therefore uncertain. There are no automatic retries or exactly-once claims.
Review the ledger/provider state before retrying. A failed ledger intent prevents
the network request; a failed final ledger write prevents a successful adapter
acknowledgement even if delivery already happened.

The outer router attempts email for every incident even if Telegram fails. It
does not hide partial route failures. The adapter acknowledges the exact recipient
and a ledger attempt reference only after the real provider receipt is persisted.

## Validation still required

Portable tests use synthetic persona selections, tokens, payloads and mocked
network/process transports. Linux tests exercise actual protected credential
reads, persona existence, concurrent JSONL writes, fsync, mode and symlink refusal
in generated `/var/lib/notify-adapter-*` paths, without sending messages. They
also drop to an existing numeric UID/primary GID to verify root-owned 0640
profiles and all refusal boundaries without changing accounts or memberships.
Both privileged workflows include those filesystem tests. The opt-in systemd
job starts a disposable unprivileged service to read the same profile, then
confirms it fails when that synthetic profile becomes publicly readable.

Before installation: review the concrete workspace command/output and execution
context, run Linux/systemd CI, review private destination/runtime configuration
and permissions, then obtain separate approval for any real delivery probe. Do
not modify PhantomBot or expand permissions to satisfy a failed prerequisite.
