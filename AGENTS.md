# Repository instructions

Read CONTRIBUTING.md before changing any tool.

## Repository and branch policy

- Work only in salvaalba-dev/phantomyard-tools for this repository.
- Never push to, merge into, or otherwise modify phantomyard/phantomtools.
- Use the existing branch explicitly assigned to the task.
- If no task branch has been assigned, prepare and review changes, but confirm
  the destination with the user before publishing. Do not assume that main
  or the currently checked-out branch is the intended destination.
- Use a pull request by default. Commit or push directly to main only with
  explicit user authorization for that change. Do not merge a PR without
  user authorization.
- Never create or select a codex/* branch automatically. A new branch requires
  an explicit user instruction naming or authorizing that branch.
- Before editing, committing, or pushing, verify the repository, remote,
  branch, and working-tree status. Keep unrelated changes out of the commit.
- Do not switch branches, reset files, or discard unrelated uncommitted work.
  Use a separate checkout when necessary.
- If instructions disagree about the destination, clarify before committing.
- Fetch origin before publishing. For an explicitly authorized direct change
  to main, base it on the latest origin/main.
- Rebase onto origin/main only on a task branch owned exclusively by this
  task, preserving unrelated changes. Never rebase or force-push a shared
  branch without explicit agreement on the update strategy.
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
