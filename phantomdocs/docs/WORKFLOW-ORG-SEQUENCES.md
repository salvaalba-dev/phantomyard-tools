# Organization-linked document sequences

`OrganizationSequences` extends the trusted local sequence reservation API with
explicit, durable bindings to the active PhantomOrg version-1 organization.
The caller supplies an entity code and selects either an existing department ID
or a declared security category with `scope: project`, together with an explicit
uppercase scope code. The latter is an explicit installation mapping: project
categories are access classifications, not a general project catalog, and the
caller must verify that the chosen category identifies the intended project.
No project is inferred from a folder, category name, actor, or title.

The format is `ENTITY-SCOPE-YYYYMMDD-NNN`. Departments and project mappings use
the same namespace: one scope code cannot be assigned to different references,
and one reference cannot silently change its code. Entity-to-organization
bindings are also unique and durable within a ledger. Changing a display name
does not change the identifier. A removed scope cannot allocate new numbers;
existing reservations and historical identifiers remain intact. A general
scope must be explicitly represented as an eligible department or project
category; no fallback is invented.

Initialization records the mapping permanently before initializing the daily
watermark. It must be performed only by a trusted operator after selecting the
correct stable codes and verifying a complete baseline. A failed later daily
initialization may leave that binding in place. No automatic rename, release or
reassignment is provided. One durable ledger must be shared by every allocator;
raw `SequenceReservations` calls, external processes or manual IDs can bypass
these bindings and must be excluded by deployment policy. Database access and
operator authorization are outside this module.

This adapter does not authorize actors or classify documents. Callers must hold
the policy lock over validation and reservation, apply PhantomOrg inherited ACLs,
verify that the item has left the inbox, and enforce archive and matrix recovery
before production use. The adapter does not perform those checks, and it does not
write to Drive, PhantomOrg, PhantomView or the document matrix. It is not wired
to a live workflow. Existing IDs must never be renumbered.
