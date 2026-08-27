# Grok adapter — pfBlockerNG

[`AGENTS.md`](AGENTS.md) is canonical vendor-neutral agent policy bootstrap; this file only Grok adapter. Grok load `AGENTS.md` native. Read `AGENTS.md` now and follow, including routing table into `.agents/policy/`, `.agents/context/`, `docs/misc/`. Grok noun translation lives in
[`.agents/context/grok-adapter.md`](.agents/context/grok-adapter.md) — read at session start.

Hard invariants in `AGENTS.md` never-list, not restated here: work in dedicated worktree, rebase-only linear history, tests ship with every change and carry red-to-green proof, every config field goes through `PfbConfig`, no direct Python on appliance, POSIX sh only.

## Grok-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/`
  symlinks onto it — no Grok-specific copy exists or should be created. Grok also
  scans `.grok/skills/` if one is added.
- `.grok/rules/harness.md` auto-loads the adapter pointer (`<dir>/.grok/rules/`
  always scanned — Grok 1.0.4 user-guide `12-project-rules.md`). Smoke-1 bus
  hooks live in `.grok/hooks/bus.json` (PreToolUse + Stop); install them into
  `~/.grok/hooks/` with `sh .grok/hooks/install-home` so a stale/detached
  worktree still enforces them. Other session hooks are not wired.
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through
  `GROK_SESSION_ID` and `GROK_AGENT` (probed on 1.0.4, 2026-08-15: exported into
  nested sh/bash). Never unset to dodge guard it trips.
- Human owner stays author, committer, signer. `Co-authored-by:` trailer for
  Grok emitted only from locally configured `coauthor.grok.*` identity; none
  configured → disclose authorship in PR body instead.
- Reviews use an independent spawned reviewer per `.agents/policy/landing.md`.
  Grok has no in-repo custom-agent files; spawn `general-purpose` (or `explore` /
  `plan`) rather than inventing a fourth role tree.
- Smoke-1 `pfb-msg` bus: arm with the **monitor** tool (`persistent: true`), never
  background bash; never long-block the turn on CI while the bus is live.
  Home copy of the rule + hooks required (stale worktree / auto-compact).
  Details in `.grok/rules/bus.md` and `.agents/context/grok-adapter.md`.
