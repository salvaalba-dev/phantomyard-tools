# Local workflow peers and policy coordination

These building blocks let a supervised local service associate a Unix socket
peer with an actor declared by the administrator and pass the actor to the
existing PhantomOrg authorization checks. They do not authenticate a remote
human. Every process running as a mapped local account has that account's
authority.

`resolve_peer_actor` obtains the local UID from Linux `SO_PEERCRED` and resolves
it through a protected administrator-owned identity map. Root, unmapped UIDs,
unprotected paths and malformed maps are rejected. The host must create and
protect the listener, its parent directory, the identity map, the ledger and
all backend configuration. The peer cannot provide a trusted actor, policy,
receipt path, category or destination.

`serve_one` takes its lock path, organization loader and request context from
the trusted host. It loads a fresh organization under a shared policy lock and
keeps that lock through request handling and context cleanup. Archive indexing
requires an existing service-owned receipt and delegates destination, content,
policy and owner validation to the native handover and document service.

`python -m phantomdocs.workflow_policy_sync --source SOURCE --destination
DESTINATION --policy-lock LOCK` is an explicit administrator operation. It
validates and atomically replaces a root-controlled policy file, preserving its
owner, mode and extended attributes, under the exclusive policy lock. The lock
file and all parents must already exist and be protected. Synchronization fails
on unsafe paths, changed input, unsupported schema or inability to preserve
attributes.

**All policy writers must cooperate with the same lock**, including writers of
the source policy. This is an operational prerequisite: root can bypass the
lock, and an old or manual writer that does not use it can race the service.
Do not enable a production service until every writer has been inventoried and
the synchronization path has been reviewed. The local peer and synchronization
modules do not install a daemon or timer, poll an inbox, move Drive files, or
make an existing integration use the lock. Those require separate integration,
tests and deployment.

The Linux test suite uses only synthetic policy and requests. It checks peer
handling, ACL inheritance, failed authorization, concurrent policy changes,
policy-file metadata and symlink rejection. Network credentials, real documents
and Drive behavior are outside those tests.
