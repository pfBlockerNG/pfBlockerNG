# No orphaned waits — every trigger dies with its task

Scope: any background wait, poll, cron check-in, wakeup, subscription. Load when: waiting on anything external (CI, reviewer bot, remote queue) or arming any timer.

**First — is there anything to wait on at all?** Harness-tracked work re-invokes you when done: `Workflow`, `Agent`, Bash with `run_in_background: true`. For those, **arm nothing** — no sleep, no poll, no `ScheduleWakeup`; end turn, answer completion notification. Wait is for state harness cannot see (reviewer bot, CI run, remote queue). Polling own tracked work = waste, and each expiring timer re-invokes you into thinking wait still unresolved — that loop, not first sleep, is real defect.

Background waits found running **20+ hours** after task ended; no platform-level timeout on polls/cron/`ScheduleWakeup`/subscriptions, so guarantees ours. Four, ALL mandatory:

1. **Self-terminating by construction.** Every background wait carries hard iteration cap AND wall-clock deadline *inside loop itself* (`scripts/agent/wait-*.sh` = exemplars, and standard transport when `gh` exists) so it dies on own even if orphaned. Wait without cap = defect — never launch one. Event waits also follow heartbeat ladder (10, 10/10/15/15/30/30 min, ≈2 h total, then give up + report wait abandoned; never re-arm past it).
2. **Cancel-on-resolution sweep.** Instant work item hits terminal state by ANY path — success, failure, give-up, or user-driven check that supersedes wait — sweep every trigger tied to it, by class: background polls → `TaskStop`; cron check-ins → `CronDelete`; PR/event subscriptions → unsubscribe. `ScheduleWakeup` **cannot be cancelled**, so: **never one long wakeup at speculative future time** — arm SHORTEST sensible rung, minimal state check on firing, re-arm next rung only if still unresolved (the ladder). Every wakeup prompt uses self-invalidating template: `CHECK <concrete state/command>; IF RESOLVED: no-op, do NOT re-arm; ELSE <next action> + re-arm <n> min`. Wakeups are *fallback* to harness completion notifications, never primary wake. Wait-spawning skills carry this sweep as explicit terminal step; not optional, not from memory.
3. **Pickup hygiene.** Starting or finishing any work item, run `TaskList` once and stop every stale wait you own from earlier items. Task moved on → its future triggers dead, good or bad outcome alike.
4. **Portability — no `gh`, no bash polls.** Background bash loops presume local toolbox (`gh`); managed environments may lack it, and MCP tools are harness tools — unreachable from inside shell loop. Detect once at task start (`command -v gh` + `gh auth status`); when absent, do GitHub reads/writes via `mcp__github__*` equivalents and run every wait as **wakeup-paced checks**: one minimal MCP state check now → still unresolved → `ScheduleWakeup` next ladder rung (self-invalidating template) → repeat. Same rungs, same 2 h cap, same sweep — only transport changes.

## The full ladder

Two independent guards, **both required** — but only once §0 says wait warranted at all:

### 0 — First: is the awaited thing harness-tracked? Then do not wait on it

`Workflow`, `Agent`, Bash with `run_in_background: true` = **tracked**: completion re-invokes you. Arm **nothing** for them — no background `sleep`, no poll, no `ScheduleWakeup`. Launch, end turn, answer notification.

Only **untracked** state gets wait, and always wait on something harness has no visibility into:

| Awaited thing | Tracked? | Correct move |
| ------------- | -------- | ------------ |
| A `Workflow` you launched | yes | end the turn; the completion notification wakes you |
| An `Agent` / subagent you spawned | yes | same |
| `wait-checks.sh` / `wait-reviewer.sh` run with `run_in_background: true` | yes | same — the script self-exits and notifies; do not also poll it |
| CodeRabbit answering an `@coderabbitai review` you asked for; a CI run; a remote queue | **no** | a bounded wait: the script above, or the ladder in §1. Never wait on CodeRabbit before asking — automatic review is off. Quota notice: wait the stated "Next review available in", then one more `@coderabbitai review` ([`coderabbit.md`](coderabbit.md)) |

Ladder's self-invalidating discipline applies to **every** timer you arm, not just `ScheduleWakeup`: on firing, CHECK concrete state first; if resolved, no-op and do NOT re-arm. Chain of re-armed sleeps with no resolution check = unbounded ladder wearing a cap — cap is per-rung, loop never ends.

### 1 — Never trust the event trigger alone: arm a self-check heartbeat ladder

Trigger can be mis-wired (wrong PR/run id, webhook that never arrives) — then event-driven wake never fires. So **always** also arm *self*-check-in, independent of event:

- **First self-check: 10 minutes** after arming wait — wake and **check real state yourself** (poll PR / CI run / job directly via its CLI or API).
- **If still unresolved, re-arm on the ladder: 10, 10, 15, 15, 30, 30 minutes** — six further self-checks. Total budget ≈ **120 min (2 h)** across seven checks.
- **After the final 30-minute rung with the awaited thing still not done → give up and die:** `unsubscribe` / `CronDelete` check-in (and any subscription), then report wait **abandoned because the event never fired** and trigger may have been mis-configured. **Never re-arm past the ladder.**
- **Any check where the awaited thing HAS happened ends the ladder early.** Genuine in-flight progress (CI still legitimately running) does not reset ladder; 2 h cap is hard — extending it is user's call, never silent re-arm.
- **Cancel on resolution — leave no orphaned trigger.** Instant task hits terminal state by any path — self-check or event finds it done (good or bad), give-up rung hit, or user interrupts to ask you to check — cancel **every** still-pending trigger tied to it (`CronDelete`, drop the `ScheduleWakeup`, `unsubscribe`). User-driven check supersedes scheduled ones. Task moved on → its future triggers dead.

### 2 — Event-deadline on the happy path

Waiting on normal event (CI green, PR merge, queued job), event-driven wait still carries own **explicit deadline** — never open-ended re-arm. Default cap: same 2 h / seven-check budget unless user sets longer one.

### 3 — The cancel-on-resolution sweep, per trigger class

Background waits found alive **20+ hours** after task ended. Sweep runs moment awaited item hits ANY terminal state, and again at work-item pickup/finish (`TaskList` once; stop stale waits you own):

| Trigger class | Kill mechanism | Notes |
| ------------- | -------------- | ----- |
| Background Bash poll (`run_in_background`) | `TaskStop <task-id>` | Also self-terminating by construction: hard iteration cap + wall-clock deadline INSIDE loop. Poll without both = defect — never launch it. |
| Cron check-in | `CronDelete` | Heartbeat ladder's rungs are crons — delete every remaining rung on resolution, not just next. |
| PR/event subscription | unsubscribe | User-driven check supersedes subscription — kill it then and there. |
| `ScheduleWakeup` | **none — cannot be cancelled** | Fires regardless. Therefore: (a) FALLBACK only — harness completion notifications are primary wake; (b) **short rung + minimal check + re-arm**, never one long wakeup at speculative future time: arm shortest sensible delay, on firing do minimal state check and re-arm next ladder rung only if still unresolved (pick rung by how fast watched state actually changes; slow externals take 10 min+ rungs); (c) fixed self-invalidating prompt template: `CHECK <concrete state/command>; IF RESOLVED: no-op, do NOT re-arm; ELSE <next action> + re-arm <n> min` — stale firing then costs one cheap turn. |

Sweep is explicit terminal step of every wait-spawning flow (review/CI waits in [`landing.md`](landing.md)) — mechanical, not remembered. Cannot be a workflow: `TaskStop`/`CronDelete` are orchestrator tools, invisible to workflow agents.

### 4 — Managed environments (no `gh`): wakeup-paced MCP checks

Background bash polls presume `gh`; managed (web/app) environments may not ship it, and MCP tools cannot be called from inside shell loop. Portable wait:

1. **Detect once** at Step 0/1 of skill: `command -v gh && gh auth status`. Present → bash-poll snippets as written. Absent → adaptation below; never mix per-call.
2. **Reads/writes** go through session's GitHub MCP server (`mcp__github__*` — discover exact tools via ToolSearch; names vary by server). Same data, same verdict logic.
3. **Waits become wakeup-paced checks:** one minimal MCP state check NOW; if unresolved, `ScheduleWakeup` next ladder rung with self-invalidating template, and on firing check again + re-arm. Rung ladder IS poll cadence — same escalation, same 2 h hard cap, same give-up-and-report rung. Sweep simplifies: no bash task to `TaskStop`; wakeups self-invalidate by template.
4. **Workflows and scripts are unaffected:** named workflows use only `git` + local commands (both present in managed environments), and workflow agents reach MCP tools via ToolSearch when they genuinely need GitHub state. Caveat: interactively-authenticated MCP servers may be absent in headless/cron runs — skill that finds NEITHER `gh` nor GitHub MCP server stops and reports rather than improvising.
