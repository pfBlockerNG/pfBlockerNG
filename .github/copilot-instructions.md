# Copilot adapter — pfBlockerNG

[`AGENTS.md`](../AGENTS.md) is canonical vendor-neutral agent policy bootstrap; this file only GitHub Copilot adapter. Copilot no expand imports, so **read `AGENTS.md` now** and follow it, including routing table into `.agents/policy/`, `.agents/context/`, `docs/misc/`. Copilot noun translation lives in
[`.agents/context/copilot-adapter.md`](../.agents/context/copilot-adapter.md) — read at session start.

Hard invariants in `AGENTS.md` never-list, not restated here: work in a dedicated worktree, rebase onto the live base before each push, land a fully gated PR by explicit GitHub squash or reviewed signed local fast-forward, keep linear history, ship tests with every change and red-to-green proof, route every config field through `PfbConfig`, never invoke Python directly on the appliance, and use POSIX shell only.

## Copilot-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/`
  symlinks onto it — no Copilot-specific copy exists or should be created.
- Custom agents live in `.github/agents/*.agent.md`, tiered per `.agents/model-tiers.conf`.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through
  `COPILOT_CLI`, which CLI exports into every shell it spawns. Never unset to dodge
  guard it trips.
- Copilot adds no commit or public-body attribution. Configured user identity remains
  authoritative.
