# Provisioned agent route supervisor

The supervisor reconciles an explicitly provisioned Unix-account inventory with
the current PhantomOrg document. It adds and withdraws viewer routes for those
accounts, independently queries each account's public runtime identity, and
preserves an independently protected human-route baseline. A new Unix account
requires a protected account/persona binding and a separately provisioned tool
signer before it can enter this inventory. Account discovery, persona installation
and signer provisioning remain separate installation responsibilities.

The runtime query is `phantombot phantomchat --list --json`, executed as the bound
Unix account with its own HOME and a pinned, root-controlled executable. Responses
have a 25-second deadline and a 64 KiB limit. Each selected persona must report a
valid public identity; a changed UID or an identity shared by multiple actors
refuses reconciliation. A missing actor, last-channel withdrawal, or mismatched
identity removes its managed route. Query failures stop the viewer. Private
persona identity and vault files stay inside the runtime's own implementation.

`python -m phantomdocs.view_agent_host --settings /etc/example-view/settings.json`
builds and schema-checks a candidate without restarting the reader. Adding
`--apply` performs reconciliation under the transaction and policy locks. The
settings contain protected paths for `org`, `config`, `journal`, `committed`,
`policy_lock`, `transaction_lock`, `baseline`, and `inventory`; an explicit `unit`,
`runtime`, `python`, and `reader`; and numeric `supplementary_groups`. Inventory
entries contain `actor`, `account`, `persona`, and a provisioned `route` accepted
by `compose_routes`. Operational identity records belong outside this repository.

Install the root-managed guarded launcher together with the supervisor. Its
unprivileged child runs the real reader; the parent holds the policy lock through
bounded readiness. Keep explicit supplementary groups and all owned runtime
directories in the unit. `render_units` returns inactive service, timer, override,
and tmpfiles drafts for review. systemd owns only the innermost reader socket
directories, and removes them after a stop or crash. The guard restores reader
ownership and the issuer's traversal/default socket ACLs on pinned directory
inodes after systemd prepares them. The host requires `/usr/bin/setfacl`; pre-start
tmpfiles rules alone do not guarantee those ACLs survive runtime recreation.
Preserve unrelated native conversation
directories. Persistent configuration, policy, journal and committed records
must stay outside disposable runtime directories.

The root guard requires the distribution's `/usr/bin/setpriv`. With the inherited
address-family filter, some deployed systemd/kernel combinations reject UID
transitions if `no_new_privs` was set before filter installation. The override
therefore leaves that flag unset only during the trusted guard bootstrap. The
child changes UID, then `setpriv --no-new-privs` seals it before executing reader
code. Immediately after creating that child, the root monitor seals itself with
`prctl` and verifies the flag before waiting for readiness. Both running processes
retain the address-family filter and `NoNewPrivs: 1`. An unsuccessful seal stops
and reaps the child. The integration test checks both flags and the child's UID.

Policy publishers must cooperate with the same policy lock. The reader must
recheck authorization on every request. Install the pinned dynamic projection
adapter for policy revision changes: it revalidates resources from the existing
approved generation and excludes newly observed resources. Administrative
approval history and the active approval pointer remain unchanged.

A health failure leaves the viewer stopped with its durable pending transaction.
The next reconciliation independently rebuilds the candidate and recovers only
when its bytes and policy revision match the pending record. A changed pending
transaction, malformed journal, or unavailable stop operation requires operator
recovery. Keep the service stopped while resolving these cases; restarting an
older configuration can restore a revoked grant. The timer retries failed runs
and periodically verifies unchanged bindings.

After validating the protected installation settings and selecting the target
unit, the CLI loads the baseline once inside the locked candidate builder.
Missing, unreadable, unsafe or malformed baseline data and invalid health ports
therefore enter the same fail-closed stop path as an identity-query failure.
The candidate and readiness check use that same baseline snapshot. A schema-only
invocation reports failure without stopping an existing viewer. If the host
cannot stop the viewer, the apply command exits unsuccessfully with the redacted
status `viewer-stop-failed` and `manual_intervention_required: true`; it does not
claim shutdown succeeded. Repairing the baseline allows the next apply to build
and validate a fresh candidate before restarting the viewer. Invalid installation
settings that prevent selection of a trusted target unit require operator repair.

The optional root/systemd integration test creates a disposable unit and a real
reader with isolated sockets, port and audit database. It exercises health
failure, journal recovery, restart, SIGKILL and stale-authority startup refusal.
Additional explicit test inputs exercise link issue/redemption, last-channel
withdrawal, old-session rejection and restoration using an existing real account
against a private organization copy. These tests preserve production services,
live policy, approved documents and persona files. They do not simulate a host
power loss or establish arbitrary new-account provisioning.

## Implementation and artifact language

Use English for supervisor code, identifiers, references, comments, docstrings,
error messages, logs, command descriptions, test descriptions, documentation,
operational summaries, generated reports, reusable scripts, commit messages and
pull request text. Conversation with the operator may use their preferred language.
Keep business documents, organization data, actor names, persona content and
external material in their original language. Preserve established configuration
keys and external interfaces; update callers, tests, documentation and generated
artifacts together if a task-owned reference ever needs renaming.

Language reviews must inspect the actual source and generated text, including
embedded scripts and systemd descriptions. Keep operational identities,
credentials and deployment receipts outside the public repository. Separate
historical deployment evidence from newly observed service health in handoffs.
A documentation or report translation alone does not require reactivation or a
reader restart.
