# PhantomView Nostr identity primitive

This experimental module verifies a direct NIP-17 gift wrap and resolves the
verified human Nostr key to a human in an organization document and checks an
explicit agent allowlist. Several humans may be listed for one agent. It fails
closed on ambiguous identities and missing allowlists. Examples and tests use
synthetic keys only.

This is **not a running integration or an authorization decision**. It does
not read or validate the trusted PhantomOrg source, enforce document ACLs,
maintain durable replay protection, subscribe to a relay, issue viewer sessions,
or send replies. In particular, the message identifier is not a consumed
nonce; repeated calls return the same result. Never expose this helper to an
untrusted caller or use its result to grant access on its own.

An integration must validate the live organization and its inherited grants,
perform replay-safe handoff, bind the authenticated human to the viewer's
recipient session, recheck revocations, and preserve the existing bridge's
message-delivery behavior. The selected agent and its allowlist must come from
trusted configuration, not the caller. Each human's public Nostr key must be
declared. An agent key does not authenticate its human. Allowlist membership
alone does not grant access to documents; current PhantomOrg ACLs still apply.

The companion `phantomview-telegram-identity.js` verifies the legacy Telegram
Login Widget signature and timestamp without consuming bot updates. This is
also a primitive, not a live login. An integration must bind the login to the
initiating browser, prevent replay, protect the bot token, authorize the human
against the current organization and issue a restricted viewer session. The
website origin must be registered with Telegram. Enabling this route must not
replace or interfere with the bot's existing update consumer.
