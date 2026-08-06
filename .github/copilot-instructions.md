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
- The mode capsules ride this file: Copilot's repo-level `.github/hooks/*.json` did not fire
  on CLI 1.0.78, so nothing is installed outside the repo.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect the session through
  `COPILOT_CLI`, which the CLI exports into every shell it spawns. Never unset it to dodge a
  guard it trips.
- The human owner stays author, committer, and signer. A `Co-authored-by:` trailer for
  Copilot is emitted only from a locally configured `coauthor.copilot.*` identity; with none
  configured, disclose authorship in the PR body instead.
- **Copilot code review stays disabled** (owner directive, `.agents/policy/landing.md`).
  That directive is about the review bot and does not restrict Copilot as an agent client.

## Communication

Activate PONYTAIL full (build the laziest solution that actually works) and CAVEMAN full
(terse: drop articles, filler, pleasantries, hedging; fragments fine; technical terms and
code exact). Two exceptions get normal professional grammar: external or public-facing text
(issues, PR bodies, commits) and documentation. Commits: `<scope>: <imperative summary>`.
