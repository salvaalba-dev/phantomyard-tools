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

## Supervised admission host

`python -m phantomdocs.workflow_admission_activation --config CONFIG` provides
an admission-only host for one systemd-activated Unix stream listener. It
requires Linux, a root-owned socket under root-controlled directories, a private
ledger for its service UID, and root-controlled configuration files. The host
verifies its configured server UID and obtains each caller's UID from the kernel;
it never trusts an actor selected by the caller. It does not poll inboxes, execute
accepted jobs, issue archive requests, move files or register documents.

The root-controlled JSON configuration has this shape (all values are
synthetic examples and paths must be adapted by the operator):

```json
{
  "identity_map": "/etc/example/identities.json",
  "ledger_path": "/var/lib/example/jobs.sqlite",
  "policy_lock": "/etc/example/policy.lock",
  "org_path": "/etc/example/org.yaml",
  "installation_path": "/etc/example/installation.json",
  "processor_config_path": "/etc/example/persona.toml",
  "processor_state_path": null,
  "socket_path": "/run/example/admission.sock",
  "store_path": "/var/lib/example/store",
  "server_uid": 1234
}
```

Processor config and optional state must be current and protected; the host uses
the same state-over-config precedence and source labels as the workflow executor.
Do not use an untrusted or stale copy to bypass the processor pin. The socket
must be created and its parent protected by the supervisor; it may grant the
intended local group permission to connect. Only configured local UIDs receive
an actor, and PhantomOrg still determines access.

`pd submit-workflow --job JOB --actor ACTOR --org-yaml ORG --root STORE`
submits one complete job through this service. Its default configuration is
`/etc/phantomdocs/admission.json`; `--service-config` can select another
root-controlled configuration. It verifies the target store, organization and
server UID before sending. A received response acknowledges a request only:
it does not confirm semantic identity, execution, archiving or registration.
After a lost response, reconcile the request before attempting it again.

The existing policy synchronization and other deployment writers must use the
same lock before this host is enabled. An inbox processor, workflow execution,
verified Drive archiving and explicit publication remain separate work.

The Linux test suite uses only synthetic policy and requests. It checks peer
handling, ACL inheritance, failed authorization, concurrent policy changes,
policy-file metadata and symlink rejection. Network credentials, real documents
and Drive behavior are outside those tests.
