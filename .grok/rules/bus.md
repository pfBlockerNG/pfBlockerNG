# Smoke-1 bus — Grok must line-wake

This file is **always scanned** from the worktree *and* must be installed at
`~/.grok/rules/bus.md` (home rules load even when cwd is a stale/detached
worktree). Copy: `sh .grok/hooks/install-home`. Owner off-switch:
`~/.grok/pfb-msg-off` — create it only when the owner said to stop comms.

## Arm

Session-length watch is the Grok **monitor** tool with `persistent: true`:

```text
ssh -o BatchMode=yes smoke 'export PFB_AGENT=grok-dev; exec /srv/Smoke/bin/pfb-msg serve grok-dev'
```

Each stdout line is a turn. If the monitor dies, restart it the same way.

## Never

- **Never** `run_terminal_command` / background bash for `pfb-msg serve`.
  That surface notifies only on process **exit**. `serve` never exits on a
  message, so unread piles up and the session looks frozen (probed
  2026-08-27: 8h silent, 10+ unread; the 10 h harness cap then killed the
  SSH and that exit finally woke the session).
- **Never** long-block the turn on CI (`gh run watch`, or
  `get_command_or_subagent_output` with a multi-minute timeout) while the
  bus is live. End the turn; let the monitor (and CI completion) wake the
  next one. A blocked turn cannot start a bus turn.
- **Never** go idle with unread mail. Peek/read at the start of every turn,
  including after auto-compact. Compaction does not re-fire SessionStart
  and does not reload a worktree that lacks this file — that is why the
  home copy exists.
- **Never** "keep working" with the bus off unless `~/.grok/pfb-msg-off` is
  present because the owner said stop.

`pfb-msg watch` is the one-shot form (one line, then exit). `serve` is the
session-length form. Both print one stdout line per message; only **monitor**
turns each line into a turn.

Mechanical backstops (not memory): `~/.grok/hooks/bus.json` PreToolUse
denies bash-`serve`; Stop blocks if the monitor is missing, serve is
background bash, or peek shows unread. See `.agents/context/grok-adapter.md`.
