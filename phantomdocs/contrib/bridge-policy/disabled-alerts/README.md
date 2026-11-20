# Disabled alert chain rehearsal templates

These are review templates, not an installer. Replace synthetic account/path
values only in a separately reviewed private profile. No activation marker,
installation commands, dependency drop-ins or `[Install]` section are supplied.

The unit explicitly binds the existing user and primary group. The runtime
profile and route file are root-owned 0640 under root-owned protected ancestors;
the existing execution group reads them without gaining write access. Tokens and
ledger files retain exact 0600 checks. Code/wrappers stay root-owned; no service
account, group membership, ACL or OAuth permission is created or broadened.

`ConditionPathExists` prevents the disabled unit from running without the
reviewed `delivery-enabled` marker. Both wrappers separately exit 78 without it,
so direct invocation cannot bypass the disabled unit condition. The marker is
not included. A skipped condition is not a delivered alert or an operational
health check. Real `OnFailure` wiring and any marker creation need separate
installation/activation approval.

Wrappers replace the process environment with fixed PATH/HOME/LANG and invoke
distribution Python using `-E -s -B`. They preserve protocol stdin/stdout and do
not import a vault, forward arbitrary environment variables or fix a persona in
code. The selected installation resolves persona at runtime. Any Google identity
must be available through the already-reviewed native workspace defaults; the
current adapter does not forward GOOGLE overrides to its mail child.

The opt-in `test_disabled_alert_systemd.py` rehearsal renders these exact
templates into unique `/var/lib` fixtures and `/run/systemd/system` units. It
uses an existing numeric UID/primary GID, without account or membership changes.
`systemd-analyze verify` and actual service starts validate the rendered unit.
The real root path guards, configuration reader, routing, wrapper exec and 0600
ledger remain in use. Only the provider-facing entry point is replaced with a
synthetic transport; a rehearsal-only private network namespace also prevents
external traffic. No Telegram or email provider is contacted.

The rehearsal proves disabled starts and direct-wrapper refusal, synthetic dual
route acknowledgements, minimal environment and UID/GID, rejection of a public
runtime file, user-owned routing parent and non-root transport wrapper, then
marker removal and unit cleanup. This is CI acceptance of a parametrized
template, not verification of a particular host's accounts, paths, credentials,+provider delivery or installed unit. Private operational configuration stays
outside this repository.
