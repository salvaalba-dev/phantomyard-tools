# PR #73 production preparation gates

This checklist defines evidence required for the protected matrix host overlay.
It grants no permission to stage files on a host, merge, deploy, reload units,
recreate sockets or activate the candidate. Keep host inventories, manifests,
configuration, identities, request details and deployment/rollback receipts in
an approved private evidence location. Use synthetic data in this repository.

## Source validation and current limits

Source and GitHub CI status rechecked on 2026-11-26 at reviewed code revision
`51b124b3874ed8eae47a42513902a04b545a85d8`, with main at
`aebe482c6ab583d98d976608879871984a4b2b80`. PR #73 was open and unmerged, and
at that revision it was still a draft; its current review readiness belongs in
the pull request interface, not here. This document adds preparation criteria;
it does not record a host run.

That revision is the last one to touch the payload, the launcher or the
bootstrap. Commits stacked on top of it change only this checklist and the
timing assertion exercised by the systemd trial, so they carry no payload,
launcher or bootstrap bytes. A document inside the change never cites the runs
of the commit that contains it — those do not exist until it is pushed — so the
checks of the current PR head belong in the pull request interface, not here.

Seven job checks across four workflows passed at `51b124b`: `pipeline`,
`phantommeet`, `phantomorg`, `disposable-systemd`, `regression` (AU ingest),
and `regression (3.10)` / `regression (3.12)` (document workflow contracts).
The verified runs are [CI](https://github.com/salvaalba-dev/phantomyard-tools/actions/runs/45845505479),
[disposable systemd](https://github.com/salvaalba-dev/phantomyard-tools/actions/runs/45845505760),
[AU ingest](https://github.com/salvaalba-dev/phantomyard-tools/actions/runs/45845505225)
and [workflow contracts](https://github.com/salvaalba-dev/phantomyard-tools/actions/runs/45845505836).
All four are `pull_request` runs recorded against that revision. Any later change
to the payload, launcher or bootstrap invalidates them until it is pushed and
re-run. A later change to the trial's timing assertion invalidates the
contention result specifically, and must be re-run on the disposable systemd
job before it is cited again.

An earlier revision of this section was verified at head
`bf2baa031b56b38654df8927557283b34cea264f` (runs 44959237869, 44959237921,
44959237863 and 44959237855); it is superseded by the head above and is kept
only as history.

Historical fixture results below belong to the 2026-11-21 review at
`7637c0c3e623ef4b1bc702804d6ca934e3dcc297`; they are not timings for the current
head or the target host. That earlier
[disposable systemd rehearsal](https://github.com/salvaalba-dev/phantomyard-tools/actions/runs/44893762104)
completed 30 tests in 68.75 seconds. Its manifest fixture reported capture
1.530 seconds, verification 0.079 seconds and 3,962 reused files. Those numbers
describe the CI fixture, not the intended target or its dependency provenance.
The tests exercise isolated bootstrap imports/drift separately from the real
systemd launcher/deadline trial; they do not establish the combined production
bootstrap-to-request duration, a target rollback or authenticated acceptance.

The consolidated project status reports generation 26 publication and the
viewer PR #12 reader cutover as complete. Neither is a pending step here.
This checklist excludes PhantomBot changes, document processing and matrix
generation/publication automation.

## Private evidence record

For every gate record UTC start/end times, operator, exact candidate revision,
target/environment reference, commands or harness revision, exit status,
observations, evidence artifact hashes and reviewer decision. Link records
privately; do not put private evidence URLs in this public repository. Distinguish
not run, failed and passed. Retain unsuccessful results and their disposition.
A later code, dependency or metadata change invalidates affected results.

| Gate | Required private evidence | Status at source review |
|---|---|---|
| Target inventory | Final-path version 2 manifest, provenance and metadata review | Not supplied |
| Verification timing | Target warm/cold and combined request timings | Not supplied |
| Rehearsal | Target-representative full bootstrap, drift and contention results | CI fixtures passed; target evidence not supplied |
| Rollback | Preserved baseline and successful disposable restoration | Not supplied |
| Acceptance | Authorized deployed revision and post-recreation access tests | Deferred until separately authorized deployment |

## 1. Target inventory

Before any authorized staging, capture the current effective service/socket
configuration, ordered drop-ins, environment, timeout, release selection and
existing rollback reference. Inspect ancestors, ownership, modes and access and
default ACLs. Stop on any proposed access broadening; do not fix permissions as
an implicit part of capture. Retain existing releases and the existing VPS
rollback, including `candidate-20261110` pending separate review.

After staging is explicitly authorized, place only the reviewed candidate files
at their intended protected paths without changing intake or the active command.
Use the [README capture procedure](README.md) with the exact interpreter and
flags. Review all inventory roots, linked package data, native extensions and
ancestors against trusted OS packages and approved release/wheel artifacts.
Account for uncovered files and differences. Capture alone is not provenance.
Also review configuration protection and launcher baseline/payload pins.

Retain the complete version 2 manifest and its raw-file SHA-256. Record the
verifier's canonical `manifest_sha256` and stamp-free `inventory_sha256`
separately; canonical JSON and raw file bytes need not have the same digest.
Review the inventory and provenance before approving the manifest. Require
successful `verify` with empty added/removed/changed lists. Capture on the final
filesystem; a disposable copy's device/inode stamps cannot substitute for it.

## 2. Verification timing and timeout accounting

Measure elapsed time and exit status for capture and repeated `verify` calls on
the target with `/usr/bin/python3.12 -I -S -B`. Timings from revisions before
`51b124b` are not comparable: the inventory reader now hashes on demand, reads
with `POSIX_FADV_WILLNEED` and takes the access metadata from the same verified
descriptor, so capture and reuse costs changed shape. Retain every sample, hashed/reused
counts and rehashed paths. Identify warm versus cold conditions and how they
were obtained; do not drop production caches or restart services for measurement
without authorization. In a disposable environment also measure valid unchanged
content with changed inode/stamps, which forces rehashing without changing the
approved inventory. Do not regenerate the approved manifest to hide drift.

The 55-second deadline begins in payload `main()`, after inventory verification,
launcher checks and imports. Verification is therefore not covered by that
deadline. Check the actual effective service timeout is still 65 seconds, and
measure the entire service process from startup through exit under the complete
bootstrap command. For a full 55-second contention case, preflight, imports and
cleanup together must fit strictly within the remaining 10 seconds. Record the
observed margin and approve sufficient headroom for target variability; a
standalone fast `verify` result cannot close this gate. Do not increase either
budget to make the trial pass. Stop if the effective unit uses different timing
semantics or the combined trial reaches the service timeout.

## 3. Disposable rehearsal

Use a disposable target-representative environment with synthetic requests,
matching dependency bytes, interpreter, metadata and ordered drop-ins. Do not
run the root/systemd fixture suite against the production host. Keep real
notification destinations disconnected; use a synthetic failure sink.

Exercise the full bootstrap-to-payload path with `-I -S -B`, including actual
dependency/native-extension imports and skipped `.pth` execution. Check the
effective command after composing all drop-ins, preserving the alert drop-in,
socket, config and budgets. Include an incorrectly ordered override as a negative
case. Refuse byte, dependency addition/removal, owner/mode/ACL and link-target
drift before executing the launcher; test malformed/unsafe manifests too.

Hold a synthetic second lock while the request owns a first lock. Verify deadline
exit before systemd termination, no remaining process, immediate reacquisition
of the first lock and a successful subsequent request. Run the full 55/65-second
case through the bootstrap, not only the launcher. Preserve raw timing/results.
Recreate the disposable service/socket and repeat authorized and denied requests.

## 4. Rollback rehearsal and preservation

Keep a private baseline of exact unit/drop-in/config bytes and hashes, effective
command, service/socket state, release paths, ownership, modes, ACLs and relevant
extended metadata. Preserve the existing VPS rollback unchanged. Identify each
candidate-owned file and whether it was absent before staging; never restore a
whole directory or overwrite unrelated files from a partial snapshot.

In the disposable environment, apply the proposed overlay selection, then
restore only changed owned files and their original metadata. For newly added
files, rehearse withdrawing only those exact files. Preserve concurrent unrelated
state. Reconcile drop-in precedence, reload there, restore prior intake state
and verify the original effective command, budgets, metadata and access behavior.
Record baseline/restored comparisons and a successful authorized request through
the restored runtime. A backup existing on disk is not a tested rollback.

## 5. Authorized deployment acceptance

Only after target preparation, review, rehearsal and rollback pass, request
explicit merge authorization and a separate install/activation window. Recheck
source and target drift before that window. Record the eventual merged revision
(rebase merge changes SHAs), installed file hashes and approved manifest digests.

During that authorized window, verify effective command/drop-ins, isolated
startup, successful real authenticated matrix delivery and existing denial of
the former reader and unrelated identities. An unauthenticated HTTP failure is
not a substitute for authenticated delivery. Verify lock-contention cleanup
without sending provider notifications. After authorized service/socket
recreation, repeat delivery and denial tests, inspect socket ownership/mode/ACLs,
confirm audit writes and check unexpected failed instances/processes. Use the
tested rollback on acceptance failure under the agreed window procedure.

## Remaining blocker and next action

The required privileged target evidence has not been supplied or independently
verified in this review. Limited read-only inspection does not close the gates
above. The next action is to obtain the private operator evidence record or an
approved privileged read-only session for manifest/provenance review and target
timing. Reconcile the actual effective configuration before proposing any change;
never infer installation state solely from the PR state or repeat a completed
step. Any further staging and later merge/deployment/activation require explicit
authorization. Keep the production gates open until their dated evidence exists.
