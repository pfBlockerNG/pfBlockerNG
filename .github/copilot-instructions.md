# Copilot adapter — pfBlockerNG

[`AGENTS.md`](../AGENTS.md) is the canonical, vendor-neutral agent policy bootstrap; this file
is only the GitHub Copilot adapter. Copilot does not expand imports, so **read `AGENTS.md`
now** and follow it, including its routing table into `.agents/policy/`, `.agents/context/`,
and `docs/misc/`. The Copilot noun translation lives in
[`.agents/context/copilot-adapter.md`](../.agents/context/copilot-adapter.md) — read it at
session start.

The hard invariants are in `AGENTS.md`'s never-list and are not restated here: work in a
dedicated worktree, rebase-only linear history, tests ship with every change and carry a
red-to-green proof, every config field goes through `PfbConfig`, no direct Python on the
appliance, POSIX sh only.

## Copilot-only surfaces

- Skills are discovered from `.agents/skills/` (canonical) and the `.claude/skills/`
  symlinks onto it — no Copilot-specific copy exists or should be created. The vendored
  `mattpocock-skills` plugin installs from `plugins/mattpocock-skills/.github/plugin/`.
- Session lifecycle hooks run from `~/.copilot/hooks/pfblockerng.json`, installed once with
  `sh scripts/agent/install-copilot-hooks.sh`: they inject the mode capsules and write the
  session record the git hooks read. Repo-level `.github/hooks/pfblockerng.json` holds the
  same wiring for the day the CLI honours it — as of 1.0.78 it does not.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- Copilot exports no environment marker to spawned shells, so `.githooks/pre-push` and
  `.githooks/prepare-commit-msg` detect sessions through those records. Never delete one
  mid-session, and never work around a guard it trips.
- Copilot has no verified co-author identity here: the human owner stays author, committer,
  and signer, and Copilot authorship is disclosed in the PR body, never as a
  `Co-authored-by:` trailer for Copilot itself.
- **Copilot code review stays disabled** (owner directive, `.agents/policy/landing.md`).
  That directive is about the review bot and does not restrict Copilot as an agent client.

## Communication

Activate PONYTAIL full (build the laziest solution that actually works) and CAVEMAN full
(terse: drop articles, filler, pleasantries, hedging; fragments fine; technical terms and
code exact). Two exceptions get normal professional grammar: external or public-facing text
(issues, PR bodies, commits) and documentation. Commits: `<scope>: <imperative summary>`.
