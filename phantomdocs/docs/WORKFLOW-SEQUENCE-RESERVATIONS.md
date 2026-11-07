# Trusted local sequence reservations

`SequenceReservations` is an additive ledger primitive for the format
`ENTITY-YYYYMMDD-NNN`. It reserves consecutive numbers per entity and day in an
existing private `WorkflowLedger`, using an immediate SQLite transaction. The
same request ID and request digest always return the existing reservation;
reusing that request ID for different data or scope fails. Reservations remain
durable after failures and are never released or automatically reused.

An authorized operator must explicitly initialize each entity/day with a
verified baseline and SHA-256 evidence digest. The digest records the evidence
used; it does not prove that the evidence is complete. An absent scope refuses
all reservations. Initialization cannot be changed after it is recorded. A
baseline of zero is a claim that no earlier ID was assigned in that scope, not
an inference from an empty inbox or an old matrix. A scope with 999 used numbers
fails rather than wrapping.

This API assumes one trusted allocation authority and a single durable ledger
shared by all of that authority's allocation processes. It does not authenticate
the caller, prevent external or manual assignment, discover existing IDs,
lock Drive, process an inbox, register documents, or update the matrix. The
caller must not reserve an ID while the item remains in the inbox; this API does
not verify that precondition. Before integration,
establish the numbering scope, verify all previous and in-flight assignments,
secure and back up the ledger, bind requests to authorized processing, and
verify crash recovery with every writer. Do not enable it against live files
until those requirements and the archive/matrix workflow are satisfied.
