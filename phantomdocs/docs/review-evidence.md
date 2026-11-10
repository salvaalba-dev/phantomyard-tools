# Review evidence bridge

This experimental bridge collects a bounded Drive inventory and the selected
matrix using an agent's existing Workspace account. It is read-only and does
not register documents, reconcile the matrix, or establish that an audit is
complete. The review output always reports `complete_audit: false`.

The collector keeps the short-lived Drive token in process memory. A collection
attempt takes an exclusive lock and creates a pending marker before collection.
Once created, the marker survives collection failure or interruption until a
successful retry publishes a new snapshot. Readers reject missing coordination
state, pending attempts and concurrent collections. A supervisor must also
refuse to start the wake if collection exits unsuccessfully, including failures
before the marker is created or while it is cleared and synced. Existing
snapshots without this coordination must be collected again.

The peer requires a protected identity map, an administrator-controlled binding
between the Drive root and PhantomOrg naming domain and project type, the current
PhantomOrg policy and the native document catalog. It resolves the project's
category from the current policy on every request and refuses missing or
ambiguous bindings. It checks all known document versions because the
unfiltered matrix can mention documents without their identifiers. This can
deny a whole review when any catalog document is inaccessible. The policy and
catalog locks protect the check and the socket write. Once bytes have entered
the client or MCP broker, a later revocation cannot retract them; every new
request must be checked again. A supervised process must also bound time spent
waiting for policy and catalog locks.

For a first isolated wake, `create_initial_grant` can create an enabled policy
with one exact MCP operation and an expiry of at most 30 minutes. It runs as
the persona owner and atomically creates the policy only when none exists; it
will not replace or renew any existing policy, including one created by another
process during the attempt. An expired grant is not removed automatically. This
helper is not a recurring grant-renewal mechanism.

The example systemd socket and service describe one agent instance. Provision
distinct unit names, socket paths, Unix account and root-owned configuration for
each agent. The socket uses `Accept=yes` and an instantiated service so that
the peer receives the connected socket on stdin. Its runtime limit bounds lock
waits. The example is inert until adapted, installed and explicitly enabled.

Do not activate this candidate until its source and bindings have been reviewed,
the peer has been supervised, a narrowly scoped broker grant and its lifecycle
have been configured, and a scheduled wake has been tested. Failed collection
must be reported as incomplete; an inventory alone is not a reconciliation.
