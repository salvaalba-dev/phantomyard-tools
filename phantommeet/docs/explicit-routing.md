# Explicit meeting routing

Configure the optional deployment-owned order writer in the manifest so that
`pm apply` and re-apply regenerate the invitation tool with the same routing
contract. Existing installations without a writer retain their behavior.

```yaml
invite:
  order_writer: [python3, /opt/example/meeting-order.py]
  org_file: /opt/example/org.yaml  # optional live PhantomOrg source for defaults
```

This is an argv list, never a shell command. The adapter is an operator-trusted
executable running with the inviting persona's existing permissions. Installing
PhantomMeet does not install that adapter, grant Drive access, or provision
destinations. Keep credentials in the existing runtime vault and use synthetic
values in manifests published in this repository.

With a writer configured, `meeting-invite.sh` must resolve a concrete department
and requester. Without `org_file`, supply `--department ID --requester TEXT`.
With `org_file`, the installed PhantomMeet Python package supplies defaults:

1. Explicit requester and department arguments take precedence.
2. Otherwise the requester is the unique PhantomOrg human/actor matching the
   verified runtime envelope (`--sender-channel telegram|nostr|email --sender-id
   ID`). Telegram uses the human's numeric `telegram_user_id`, Nostr uses `npub`,
   and email uses the verified address. Display names and bot handles are not
   authenticated sender identities. The invoker must pass metadata supplied by
   its authenticated channel runtime, never values extracted from message text.
   This tool has no direct access to the incoming channel session.
3. The department defaults to a whole id/name mentioned in the title (case and
   accents normalized) or the requester's own `role -> department` in the live
   org file. This is deterministic catalog matching, not semantic guessing.
   Substring matches, room names, persona defaults, and memory visibility scopes
   are not used. Multiple title matches or disagreement with the requester's
   department require a question; a subsequently explicit department resolves it.
4. A different explicit requester uses their own context. If they are not in
   PhantomOrg, supply an explicit department or a unique department in the title;
   never reuse the original sender's department for someone else.

An authenticated sender not yet in PhantomOrg is retained as a channel-qualified
identity (for example `telegram:303`); no role or department is invented for them.
If identity or destination remains unresolved, ask a short question before
inviting. Invalid identities or duplicate sender bindings fail closed. The org file is read
at each invocation, so role updates apply without a stale department cache.
Install the updated PhantomMeet package in the same Python environment available
as `python3` to the generated tool. The runtime must bind sender identities before
these defaults can operate; configuring `org_file` alone does not authenticate a
channel. A selected department never grants permission to that destination.

After recorder preflight succeeds (or is overridden with `--force`) and before
broadcasting, the tool invokes:

```text
<order_writer argv...> --room ROOM --title TITLE --requester REQUESTER
                      --department DEPARTMENT --ordered-by PERSONA
```

The adapter must return zero only after it has:

1. Validated the department against both authoritative destination maps and
   verified the actual inbox and order folder using its existing access.
2. Written exactly `<room>.json` in the configured order folder, containing
   `room`, `title`, `requester`, `department`, `ordered_by`, and a timezone-aware
   `created` timestamp. `ordered_by` identifies the executing persona; it is
   provenance, not proof of authorization derived from incoming text.
3. Verified the stored contents. Reuse an identical existing order on retries;
   reject conflicts, duplicate filenames, malformed data, and ambiguous listings.
   Serialize concurrent writes for a room. Do not overwrite another order.

Adapter failure or absence withholds the invitation. `--force` bypasses only
recorder readiness. A notification failure can leave a valid order behind: retry
with the same context. `--dry-run` calls neither adapter nor bridge nor notifier;
its order preview does **not** certify destination validity. Routing flags without
a configured adapter fail rather than silently discard the requested destination.

## Recording-side integration

The post-meeting pipeline and Jibri finalizer are deployment services, outside
PhantomMeet's persona-file ownership. This change does not replace them or change
STT/TTS. Configure them separately with the following contract:

- Preserve the original Jibri `metadata.json` bytes as `<mp4>.jibri.json` before
  publishing the MP4. Keep the source metadata. Reject symlinks, missing or invalid
  metadata, paths outside the recording root, and conflicting target files;
  retain the source on failure. Publish without overwriting existing recordings.
- Resolve explicit `<mp4>.dept` first, then `<mp4>.meta.json` with `department`.
  A present but malformed explicit sidecar blocks processing.
- Otherwise read the exact room from the Jibri sidecar's `meeting_url`, validate
  its HTTPS host against the configured meeting service, and retrieve the unique
  exact `<room>.json`. Jibri metadata is room evidence, never a department source.
- Validate the order's room and department against both live maps on every pass.
  Missing, invalid, conflicting, or ambiguous context remains in HOLD. Do not
  cache missing orders: an order created afterwards must resolve on the next pass.
- Keep existing recordings in HOLD until their actual departments are confirmed.
  Verify artifacts and Drive delivery before moving or deleting source MP4s.

Before deployment, back up the manifest, generated tool, shared KB file, pipeline
configuration, resolver, and finalizer with a dated receipt. Review `pm apply
--dry-run`, then apply only to the intended personas. Run the adapter's own
integration tests for Drive readback, retries, conflicts, and late-created orders,
and test finalization on a disposable recording before claiming end-to-end success.

The repository tests exercise the actual rendered invitation tool with a fake
recorder, adapter, and notifier. They do not certify a live Drive adapter or VPS.
