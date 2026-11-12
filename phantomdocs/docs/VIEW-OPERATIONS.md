# Viewer onboarding, operation and recovery

PhantomOrg is the authorization source. The protected local inventory binds an
existing actor to a separately prepared Unix account, persona and tool signer;
it does not grant organization membership or document access. Never copy a
persona identity, regenerate its keys, edit its vault or insert a task prompt.
Use the runtime's supported public identity listing for verification.

## What happens automatically

For an inventory entry whose account, UID and public identity match current
PhantomOrg, the supervisor composes the managed route, validates the reader,
and applies a durable transaction. Withdrawal of the actor's last declared
channel, removal from PhantomOrg or an identity mismatch withdraws that route.
The independently protected human routes remain separate. Identity-query errors
fail closed during apply; they are not a reason to retain an unverified route.

The timer retries failures and checks unchanged routes. Existing approved
resources are revalidated against current authority; newly discovered resources
are excluded. Adding an actor does not approve any document. The reader checks
authorization for each request, including existing sessions.

## What an operator must prepare

1. Establish the actor and its document scope in PhantomOrg through the normal
   authority publisher and shared policy lock. Do not invent a local permission
   grant, infer an account from an actor name or union a legacy roster into it.
2. Prepare its Unix account and persona using the existing installation process.
   Verify the public identity as that account using the pinned runtime. Bind the
   numeric UID explicitly. Reused UIDs and shared actor identities require repair.
3. Provision a separate viewer tool signer through its supported credential
   mechanism. Configure the account's viewer client with the matching public
   signer and socket. The persona identity is not the tool signer's key store.
4. Prepare the reader's runtime topology before making the inventory entry live.
   Each socket needs its explicitly owned runtime directory, traversal/default
   ACLs, reader group and guarded-launcher argument. The effective systemd
   `RuntimeDirectory`, `ReadWritePaths`, tmpfiles rules, guarded-launcher
   `--runtime-directory` arguments and explicit child groups must agree.
5. Use `compose_routes` and `render_units` to produce inactive drafts covering
   the protected baseline and all prepared routes, including temporarily
   withdrawn routes. These functions do not authorize or install anything.
   Review paths and ownership; never grant a blanket home-directory or group
   permission to make a startup error disappear.
6. Coordinate installation and inventory publication under the supervisor's
   transaction lock. Prepare topology before exposing the new inventory entry
   to the timer. Install only reviewed tool-owned files atomically, reload
   systemd when unit files change, and preserve the previous files for recovery.
   Keep the reader stopped if an incomplete installation cannot safely start.
7. Run the read-only checks below, then the normal supervisor apply. Verify a
   real account session, exact policy filtering, one-time code refusal, logout
   invalidation, and denied document endpoints. Check an isolated withdrawal
   and restoration before describing the onboarding path as proven.

Unknown or unprepared future accounts receive no automatic route. Initial
account, signer, client and runtime-topology preparation remain installation
responsibilities. Once those are complete, later eligibility changes require
no hand-edited managed reader configuration.

## Read-only readiness checks

Run with the installed, pinned interpreter and module path, as the protected
operator. Example paths below are synthetic:

```sh
python -B -m phantomdocs.view_agent_host --settings /etc/example-view/settings.json
python -B -m phantomdocs.view_agent_host --settings /etc/example-view/settings.json --check-onboarding
```

The first command validates a freshly built candidate. The second additionally
compares declared actors with the prepared inventory, verified candidate and
effective systemd runtime directories and configured reader groups. It returns
nonzero for `not-provisioned`, `identity-unverified` or `runtime-not-prepared`.
Actors without a declared channel are reported as `no-declared-channel` and
receive no managed route. Query or installation errors return a redacted refusal.
Neither mode stops or starts the viewer or commits a route transaction; the
existing schema loader may create and remove its temporary validation file.

The report omits identities, signer keys and installation paths. A successful
report is a limited readiness observation: guarded-launcher arguments, tmpfiles
ACLs, account-side client configuration and an actual authenticated session
still require verification. It does not prove end-to-end onboarding.

## Routine health verification

Check the viewer's active/running state, local HTTP response, matrix socket,
enabled/active supervisor timer, latest supervisor result and pending journal.
An inactive/dead oneshot supervisor with a successful last result is normal
between timer runs. Check timestamps and recurring successful cycles, rather
than interpreting that state as an outage.

Record the selected runtime, deployed module hashes, current policy/configuration
binding and approval-history hashes privately. Confirm that a successful check
has not added approvals. Keep cookies, tokens, one-time links, operational
identities and private document evidence out of logs and public pull requests.

## Recovery decisions

| Observation | Action | Required verification |
| --- | --- | --- |
| Healthy, unchanged, no pending record | Leave running; observe next timer cycle | Fresh identity checks and successful result |
| Missing/unsafe baseline or failed identity query | Apply refuses and attempts to stop the viewer; repair the protected input | Fresh schema check, successful apply, health and sessions |
| Matching pending transaction | Let the supervisor independently rebuild and retry | Candidate bytes and current authority match; readiness passes; committed record persists before journal removal |
| Mismatched/corrupt pending record | Keep stopped and preserve the record for investigation | Explain the mismatch and prepare an operator-reviewed transaction against current authority |
| `viewer-stop-failed` | Confirm and enforce shutdown through the host administrator | Service and child processes actually stopped; do not claim automatic shutdown |
| Invalid settings before a trustworthy unit can be selected | Repair installation settings through the operator | Protected paths, target unit and ownership established before apply |
| Runtime rollback | Restore reviewed code/unit files only with current-authority revalidation | Never start an old configuration merely because its old health check passed |

Do not delete a pending record to force startup. Do not restore stale grants
from a configuration backup. Retain the old record and the reason for any
operator intervention; a fresh configuration needs a current authority binding.
The supervisor's transaction lock precedes the shared policy lock. All policy
publishers must cooperate with that same policy lock.

## Host restart and power interruption

Persistent configuration, inventory, baseline, pending and committed records
must live outside `/run`. systemd recreates only the tool-owned socket runtime
directories; the guard restores the required ACLs on pinned inodes. A reader
whose committed configuration is stale must refuse startup. The enabled timer
can retry reconciliation after boot when the installation and identities are
available. These mechanisms are a design, not evidence of a successful power-loss
test on a particular VPS.

A planned reboot is not a power-loss test. SIGKILL of a disposable reader is
also not a host power-loss test. To test loss of power, use a separately
authorized maintenance window and a disposable equivalent host or provider
hard-power action with a working out-of-band recovery console. Preserve backups
of tool-owned persistent files without copying runtime-owned persona secrets.
Record before/after hashes, boot ID, journal state, enabled timers, guarded
startup, socket ownership/ACLs, current policy and all account session checks.
Exercise both an idle interruption and a pending-transaction interruption on
the disposable environment. Preserve failure evidence and keep access closed
until current-authority reconciliation succeeds. Do not certify this case from
unit tests, a graceful reboot or a process restart.

## Matrix and final-archive discipline

Use the already issued matrix's exact Drive identity and verified issuance
receipt. A partial matrix remains partial until all outstanding provenance and
post-baseline operations have evidence. Preserve historical IDs, earlier matrix
versions, references and operations logs. A differently named or nonidentical
file is not automatically a new registration, original or superseding version.

Refresh a fully paginated tree as the bound agent through its existing Workspace
reader. Check PhantomOrg and native document-version authorization while holding
the policy/catalog locks. Verify matrix version, metadata and content before and
after reads, and compare exact IDs, parents, versions and content hashes. A Drive
tree observation is not a transactional snapshot or proof of a complete audit.

For a manual, distinguish the published derivative, local working copy and
frozen original. A matching local PDF does not establish original custody.
For an email and PDF sharing a historical ID, preserve both and establish their
relationship from source evidence; different bytes cannot satisfy an exact-byte
original rule. Preserve superseded branding packages when their contents differ.

An uncertain archive outcome requires checking the same existing Drive ID,
parents, revisions and receipt before any retry. Do not re-register, regenerate
IDs, overwrite a previous matrix, synthesize an original, or move a live source
merely to close a checklist. Record verified facts and unresolved disposition
separately. Final archival is complete only when original custody, destination,
version history, permissions and the corresponding matrix operation are proven.

## Evidence boundaries

Keep a private dated receipt with distinct sections for newly observed service
health, tests run now, historical deployment tests and untested cases. Include
failed attempts and their corrected reruns where they affect the conclusion.
Do not present synthetic future actors as real provisioned accounts, isolated
policy withdrawal as a live production revocation, or process recovery as host
power-loss recovery. Public documentation uses synthetic examples only.
