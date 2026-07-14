---
name: new-terminal
description: Prepare an attachable second Codex CLI session in the current repository. Use for "new terminal", "spawn another Codex", or "launch a second instance".
---

# Launch another Codex session

Read `../../../.claude/skills/new-terminal/SKILL.md` for the shared intent, but do not
copy its Claude bridge transport or background a hidden TUI. Confirm `codex`
is available, capture the current directory, `CODEX_HOME`, and
`CODEX_THREAD_ID`, then prepare the real-terminal command. Prefer forking the
current conversation when the thread ID is available:

```sh
codex -C "$PWD" fork "$CODEX_THREAD_ID"
```

If `tmux` is available and the user asked you to launch it, create a named,
detached tmux session without shell `&`, verify it with `tmux has-session`, and
report the exact `tmux attach -t <name>` command. Otherwise give the command for
the user to run in a new terminal; do not claim a process was spawned. Codex's
experimental `remote-control` daemon is a separate current-session transport,
not a substitute for an attachable second terminal.
