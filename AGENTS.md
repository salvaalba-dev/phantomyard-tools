# Repository instructions

Read CONTRIBUTING.md before changing any tool.

## Repository and branch policy

- Work only in salvaalba-dev/phantomyard-tools for this repository.
- Never push to, merge into, or otherwise modify phantomyard/phantomtools.
- Use the existing branch explicitly assigned to the task.
- If no task branch has been assigned, use main. Do not assume that the
  currently checked-out branch is the intended destination.
- Never create or select a codex/* branch automatically. A new branch requires
  an explicit user instruction naming or authorizing that branch.
- Before editing, committing, or pushing, verify the repository, remote,
  branch, and working-tree status. Keep unrelated changes out of the commit.
- Do not switch branches, reset files, or discard unrelated uncommitted work.
  Use a separate checkout when necessary.
- If instructions disagree about the destination, clarify before committing.
- Fetch origin before publishing. On main, base the change on the latest
  origin/main. On an assigned topic branch, rebase onto origin/main before
  pushing, resolving conflicts without including unrelated changes.
- Keep new history linear. Do not create merge commits or rewrite existing
  user commits.
- Prefer ordinary fast-forward pushes. Use --force-with-lease only when a
  rebase requires it; never use an unguarded force push.
- When publishing through the GitHub connector, use the expected branch SHA
  as a lease and create a single-parent commit on the current destination.
- Before publishing, check the final diff and relevant validation results.
  Report the destination branch and commit URL after publishing.

## Language and scope

- Write all new code, comments, documentation, commit messages, and PR text
  in English. Use synthetic examples rather than live operational data.
- Keep fixes minimal and scoped. Use one PR per issue when a PR is needed.
- Do not publish secrets, real identity records, private documents, or
  deployment receipts.
