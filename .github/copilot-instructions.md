# Copilot adapter — pfBlockerNG

[`AGENTS.md`](../AGENTS.md) is canonical vendor-neutral agent policy bootstrap; this file only GitHub Copilot adapter. Copilot no expand imports, so **read `AGENTS.md` now** and follow it, including routing table into `.agents/policy/`, `.agents/context/`, `docs/misc/`. Copilot noun translation lives in
[`.agents/context/copilot-adapter.md`](../.agents/context/copilot-adapter.md) — read at session start.

Hard invariants in `AGENTS.md` never-list, not restated here: work in dedicated worktree, rebase-only linear history, tests ship with every change and carry red-to-green proof, every config field goes through `PfbConfig`, no direct Python on appliance, POSIX sh only.

## Copilot-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/`
  symlinks onto it — no Copilot-specific copy exists or should be created. Vendored
  `mattpocock-skills` plugin installs from `plugins/mattpocock-skills/.github/plugin/`.
- Mode capsules ride this file: Copilot repo-level `.github/hooks/*.json` did not fire
  on CLI 1.0.78, so nothing installed outside repo.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through
  `COPILOT_CLI`, which CLI exports into every shell it spawns. Never unset to dodge
  guard it trips.
- Human owner stays author, committer, signer. `Co-authored-by:` trailer for
  Copilot emitted only from locally configured `coauthor.copilot.*` identity; none
  configured → disclose authorship in PR body instead.
- **Copilot code review stays disabled** (owner directive, `.agents/policy/landing.md`).
  Directive about review bot, not restrict Copilot as agent client.

## Communication

Activate PONYTAIL full (build laziest solution that actually works) and CAVEMAN full
(terse: drop articles, filler, pleasantries, hedging; fragments fine; technical terms and
code exact). Two exceptions get normal professional grammar: external or public-facing text
(issues, PR bodies, commits) and documentation. Commits: `<scope>: <imperative summary>`.
