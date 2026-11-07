# Nostr bridge policy refresh

This is an opt-in, separately deployed bridge routing reconciler. It applies the
existing PhantomOrg `roles`, `actors` and escalation routing through the
installed bridge resolver; it does not enforce PhantomDocs categories or
PhantomView recipient access. It does not modify PhantomBot.

At service startup, the preflight validates the authoritative source and copies
it into the protected bridge snapshot under the existing exclusive policy lock.
A path watcher requests reconciliation when the source changes; a periodic
30-second retry also detects a missed event. If derived agent keys, routing or
role membership change while the bridge is active, the reconciler stops it,
atomically updates the snapshot, releases the lock, then starts the bridge. If
only unrelated policy bytes change, it updates the snapshot without restarting.
An intentionally stopped bridge is not automatically started.

If validation fails, a policy publication marker exists, or a copy changes
during the operation, an active bridge is stopped and not restarted. After
correcting or recovering the policy, an operator must inspect the failure and
start it explicitly. If systemd cannot stop the bridge, the error is reported;
this tool cannot guarantee fail-closed behavior when systemd itself fails.

**This is eventual synchronization, not atomic revocation.** Path notifications,
timer execution, in-flight messages and uncontrolled root edits create a window
where an already-running bridge may use the previous policy. A systemd path unit
may fail or be rate-limited. Direct edits that ignore the shared lock are not
coordinated. Do not rely on this watcher to enforce per-document ACLs or to
make revocations instantaneous. A fully coordinated writer and reader protocol
is required before using it as a security boundary for PhantomView.

The examples target one installation and are inert until installed by root.
Provision a dedicated root-owned virtual environment at the path used in the
examples, with all parent directories and the bridge resolver and dependencies
protected from non-root writes. Verify the bridge currently runs from the
selected snapshot and that its active derived routing matches that snapshot;
otherwise an unchanged snapshot is not proof of running state. Install and
validate the bridge prestart drop-in, path, timer and oneshot together. Plan
rollback and a message-recovery test; a restart interrupts bridge connections.
The unit examples do not synchronize the separate PhantomDocs/PhantomView
projections and do not edit the authoritative organization file.
