---
name: adr-all
description: >
  Shortcut for `/adr-phase <ADR-number> all` — implement an entire ADR end-to-end.
  Same parameters as /adr-phase minus the phase selector. Args:
  <ADR-number> [--base <branch>]. Use when the user says "implement all of ADR-N",
  "run the whole ADR", "finish ADR-N", or invokes /adr-all.
---

`/adr-all` is a thin alias for `/adr-phase <ADR-number> all`. It owns **no logic
of its own** — `adr-phase` is the single source of truth for the worktree,
per-phase sub-agents, commit-and-push, review, resume, and landing.

## Step 1 — Parse args

Args string: `{{ args }}`

- **Token 1 — ADR number** (required). Bare digits: "1", "01". If missing, stop
  and ask.
- **`--base <branch>`** (optional) — forwarded unchanged.
- There is **no phase selector** here; it is always `all`.

## Step 2 — Delegate to `adr-phase`

Invoke the `adr-phase` skill (via the Skill tool) with args `<ADR-number> all`,
appending `--base <branch>` if it was given. Do not re-implement or summarise
`adr-phase`'s behaviour — just run it and let it drive the full ADR.

The `skill-branch-sync.sh` PreToolUse hook (`.claude/hooks/`) already synced the checkout onto
`origin/devel` before this invocation started, and fires again for the nested `adr-phase` call —
no need to pre-fetch here. A non-default `--base` still isn't hook-covered (see `adr-phase`
Step 0); it's forwarded unchanged so `adr-phase` handles it.
