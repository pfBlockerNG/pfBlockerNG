# Copilot adapter — pfBlockerNG

[`AGENTS.md`](../AGENTS.md) is canonical vendor-neutral agent policy bootstrap; this file only GitHub Copilot adapter. Copilot no expand imports, so **read `AGENTS.md` now** and follow it, including routing table into `.agents/policy/`, `.agents/context/`, `docs/misc/`. Copilot noun translation lives in
[`.agents/context/copilot-adapter.md`](../.agents/context/copilot-adapter.md) — read at session start.

Hard invariants in `AGENTS.md` never-list, not restated here: work in dedicated worktree, rebase-only linear history, tests ship with every change and carry red-to-green proof, every config field goes through `PfbConfig`, no direct Python on appliance, POSIX sh only.

## Copilot-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/`
  symlinks onto it — no Copilot-specific copy exists or should be created.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through
  `COPILOT_CLI`, which CLI exports into every shell it spawns. Never unset to dodge
  guard it trips.
- Copilot adds no commit or public-body attribution. Configured user identity remains
  authoritative.
- **Copilot code review stays disabled** (owner directive, `.agents/policy/landing.md`).
  Directive about review bot, not restrict Copilot as agent client.
