# Grok adapter — pfBlockerNG

[`AGENTS.md`](AGENTS.md) is canonical vendor-neutral agent policy bootstrap; this file only Grok adapter. Grok load `AGENTS.md` native. Read `AGENTS.md` now and follow, including routing table into `.agents/policy/`, `.agents/context/`, `docs/misc/`. Grok noun translation lives in
[`.agents/context/grok-adapter.md`](.agents/context/grok-adapter.md) — read at session start.

Hard invariants in `AGENTS.md` never-list, not restated here: work in dedicated worktree, rebase-only linear history, tests ship with every change and carry red-to-green proof, every config field goes through `PfbConfig`, no direct Python on appliance, POSIX sh only.

## Grok-only surfaces

- Skills discovered from `.agents/skills/` (canonical) and `.claude/skills/`
  symlinks onto it — no Grok-specific copy exists or should be created. Grok also
  scans `.grok/skills/` if one is added.
- No repo session hooks are wired. `.grok/rules/harness.md` auto-loads the adapter
  pointer (`<dir>/.grok/rules/` always scanned — Grok 1.0.4 user-guide
  `12-project-rules.md`).
- `.githooks/pre-push` and `.githooks/prepare-commit-msg` detect session through
  `GROK_SESSION_ID` and `GROK_AGENT` (probed on 1.0.4, 2026-08-15: exported into
  nested sh/bash). Never unset to dodge guard it trips.
- Human owner stays author, committer, signer. `Co-authored-by:` trailer for
  Grok emitted only from locally configured `coauthor.grok.*` identity; none
  configured → disclose authorship in PR body instead.
- Reviews use an independent spawned reviewer per `.agents/policy/landing.md`.
  Grok has no in-repo custom-agent files; spawn `general-purpose` (or `explore` /
  `plan`) rather than inventing a fourth role tree.
