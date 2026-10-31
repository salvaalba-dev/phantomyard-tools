# Local workflow admission draft

This draft adds a separate local admission path. It does not replace signed
requests or authenticate a remote sender. All code running as a mapped local
account is trusted as the mapped actor, including code compromised through that
account. PhantomOrg still decides whether that actor may write the planned
category and owners; execution rechecks current policy and plan pins.

`pd workflow accept-local` resolves the caller from an explicit Linux effective
UID mapping. Root is refused. The administrator-provided JSON file and every
directory above it must be root-owned and not writable by group or others;
symlinks are refused. Example data (not an installation recommendation):

```json
{"version": 1, "actors": {"12345": "example-service"}}
```

The submitted job's requester must equal the mapped actor. It cannot claim to be
a different persona or human. The mapping is not a replacement for channel
authentication and never proves who originally supplied a Drive object. Signed
and local jobs with the same request ID cannot replace each other. Repeating the
same local intent reuses the original plan and events; changing intent under the
same ID is rejected. The ledger labels local events `accepted-local` or
`replanned-local`, so they are not presented as signed remote requests.

For local jobs, the CLI also requires `--identity-map` at `prepare` and
`index-archive`; the mapped effective UID must match the actor performing that
step. Signed jobs continue to use the existing path. These CLI checks do not
isolate other code running under a mapped account.

The ledger API is a trusted in-process interface and its `caller` parameter is
not itself an authentication mechanism. Code integrating it must derive the
actor from an equivalent protected binding on every admission. The initial CLI
implementation fails closed on non-Linux platforms; a future Windows integration
requires an independently reviewed account and ACL binding.

This draft does not provide an inbox runner, archive writer, PhantomView
publisher, user-session handoff, or a production service. Do not activate it
until those components, current ACL revalidation, receipt custody, crash recovery,
and multi-format/version reconciliation have independent end-to-end tests. Do
not move or delete an inbox copy merely because a proposal was admitted.
