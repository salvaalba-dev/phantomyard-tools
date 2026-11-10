# Shared human and agent viewer routes

An existing actor may have a human-authenticated issuer and also need an
agent-scoped issuer. Configure `mixed_agent_signers` only in the protected
operator configuration. Each actor maps to public signer keys that are a
nonempty proper subset of that actor's existing route `identities`. The actor
must also appear in `agent_actors`. A signer in the subset requests an
agent-scoped session; the remaining route signers retain the existing human
resolution. This selection reads an untrusted claimed key solely to select a
verification path. The existing issuer still verifies the full signed event,
and the local handoff still verifies the connected process UID. A forged claim
does not authenticate either route.

Do not reuse a bot identity, alter its keys, or place a secret in the reader
configuration. Provision a separate agent-owned signing key and root-owned
link configuration for each agent. Resolve the actor from the trusted route,
never a browser-supplied actor. Re-evaluate PhantomOrg for each request and
deny access after a policy or actor change. An agent link is read-only and does
not grant the agent access to human-only actions.

The provided composer accepts only the pinned identified-reader and launcher
revisions; construct and test a new release rather than editing a running one.
Retain the previous release and configuration. Verify both the original human
signer and the new agent signer, including forged signatures, before activation.
Test that other agents cannot read another agent's key or connect to its handoff.

On Linux, a separate socket directory and a named user ACL can permit the
designated agent to connect without adding the viewer to the agent's private
Unix group. The directory must remain protected against replacement, and a
default ACL must grant access only to the designated agent's socket. Provision
the directories and ACLs at boot and test actual kernel peer credentials. An
ACL does not replace the existing signer, session, or PhantomOrg checks.
