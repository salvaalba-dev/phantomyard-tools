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

## Reproducible staging on Linux

Use a reviewed, immutable commit and a new root-owned release directory for
each deployment. Never build over the running release. Install the complete
PhantomDocs package and its reviewed dependencies into an isolated virtual
environment; record the commit and the hashes of the package and dependency
artifacts in the local deployment receipt. Do not publish configuration,
Drive references, credentials, receipts or production policy in the repository.
Use the same Python environment for the broker and viewer, or ensure that both
environments contain the identical reviewed PhantomDocs package. Verify imports
as the actual viewer account and as the agent account before activation.

Compose a copy of the currently supported viewer release, not the live tree.
From the installed package, call `view_matrix_http_patch.patch_http` on the
copy's `scoped_http.py` and `view_matrix_ui_patch.patch_scoped_ui` on its
`scoped-ui.js` when using the identified scoped viewer. The separate `patch_ui`
targets the older `app.js` frontend and does not modify the scoped frontend.
Write each result only into the copy. Both functions reject an unexpected
source digest: a newer viewer must be reviewed and supported explicitly, not
patched by bypassing the digest. Record the input and output hashes. Verify the
copy and every interpreter, package, configuration file and parent directory
are protected against modification by the viewer and agent users. Retain the
previous release and configuration for rollback.

Create one root-owned broker configuration per actor, with the approved actor,
viewer UID, agent UID/GID, Workspace executable, organization, lock and native
manifest paths, and reviewed version-to-Drive-reference/hash bindings. The
viewer route must bind that same actor and project scope to that broker and
expected server UID. Do not derive any of these values from HTTP requests.
`current` is an explicit alias, not a Drive search; update it under review when
the current version changes, while retaining previous bindings.

An example socket-activated service, with installation-specific paths and a
dedicated IPC group substituted by the operator, is:

```ini
# phantomdocs-matrix-example.socket
[Socket]
ListenStream=/run/phantomview/matrix-example.sock
SocketUser=root
SocketGroup=phantomview-ipc
SocketMode=0660
Accept=yes
RemoveOnStop=yes
[Install]
WantedBy=sockets.target
```

```ini
# phantomdocs-matrix-example@.service
[Service]
Type=oneshot
User=root
ExecStart=/opt/phantomdocs/releases/RELEASE/bin/python -m phantomdocs.view_matrix_host --config /etc/phantomdocs/matrix-example.json
StandardInput=socket
StandardOutput=null
StandardError=journal
NoNewPrivileges=yes
TimeoutStartSec=65
```

Provision the socket parent with a reviewed tmpfiles rule and protect it from
replacement. Check the units with `systemd-analyze verify`, then test a separate
socket using the real service UIDs before enabling it. Verify the viewer's
existing preflight and projection revision before any restart. After activation,
verify the identified agent session against known version hashes, denial of an
unauthenticated session and an unrelated local UID, and service health after a
restart. Exercise a revocation against isolated copies of the organization and
manifest before deployment; all production policy writers must use the same
lock. If a check fails, restore the saved viewer configuration and release,
restart it, and disable the new socket. Do not delete document versions or
register an existing matrix as part of deployment or rollback.
