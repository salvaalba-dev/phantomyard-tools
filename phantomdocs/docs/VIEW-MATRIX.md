# Protected project matrix reader

This opt-in integration reads existing, explicitly pinned Drive files without
registering or moving them. A version selector maps to a root-reviewed Drive
reference and SHA-256; `current` may name the same object as a numbered version.
Each request requires both the live PhantomOrg project classification and
read access to every native document version, because free-text matrices can
describe documents without identifying them. A changed source hash fails closed.

The hosting viewer must authenticate the session and bind its actor and project
scope before it contacts an actor-specific Unix broker. The broker verifies the
viewer's kernel UID, holds the shared policy and native manifest locks, starts
the Workspace reader under the configured agent UID with no supplementary groups,
and retains the locks until the bounded delivery acknowledgement. The viewer
checks the broker UID and rechecks the session and project scope before delivery.
Protect each broker configuration, socket parent, Python interpreter and all code
on the module search path from modification by the viewer and agent accounts.
The Workspace adapter runs as the agent and uses its existing credentials.

`view_matrix_http_patch` and `view_matrix_ui_patch` produce inactive candidates
only for their exact pinned viewer revisions. The HTTP route expects a protected
root-owned configuration named by `PHANTOMVIEW_MATRIX_ROUTES`. The UI adds a
project matrix control and renders returned content as text. Provision a
supervised per-connection Unix listener and verify its kernel peer credentials,
service ownership and effective actor binding before activation. Configure a
bounded socket and HTTP timeout, and preserve the prior service for rollback.

Tests with synthetic sessions are not a substitute for an end-to-end test with
the real agent account, a valid identified viewer session, a denied peer and a
denied session. Review the full matrix's inherited scope, all existing versions,
and the effect of policy revocations. A previously delivered response cannot be
recalled. The viewer's separately approved projection may require a new reviewed
publication whenever the organization revision changes.
