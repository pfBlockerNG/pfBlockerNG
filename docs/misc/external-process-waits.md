# Launching and waiting on external processes

Scope: launch + wait on external processes, FreeBSD/pfSense. Load when: code runs `timeout(1)`, `mwexec_bg()`, spawned daemon, or live-tail/poll loop.

Running external OS process from PHP or shell then *waiting on it* has non-obvious semantics that bit this package — post-update hook falsely timing out and killing daemon it just (re)started, Update-page live tail hanging. Read before writing or changing code that runs `timeout(1)`, `mwexec_bg()`, spawned daemon / `service` restart, or live-tail / poll loop.

## FreeBSD `timeout(1)` is a process *reaper* by default

Default mode: `/usr/bin/timeout` calls `procctl(PROC_REAP_ACQUIRE)`, becomes **process reaper** (FreeBSD source: `bin/timeout/timeout.c`). Changes two things:

- **Does not exit when direct child exits.** Waits until *every* descendant gone (loop breaks only when reaper status reports `rs_children == 0`), then on alarm signals **whole reaped tree**.
- **Backgrounding cannot escape it.** `&`, `nohup`, even proper double-fork + `setsid` daemonization normally reparent child to `init` (pid 1) and detach from original parent — but reaper *intercepts that reparenting*, so descendant reparents to **timeout** instead and still counts. Daemonizing does **not** detach process from default-mode `timeout`.

**Consequence:** command that deliberately starts long-lived daemon — e.g. HAProxy graceful reload — keeps `timeout` alive whole budget, then reaper-kill on alarm takes freshly-started daemon down with it. Symptom: false `TIMED OUT after <budget>s (killed)` logged *after* command's own work already finished in milliseconds.

## `--foreground` (`-f`): wait on / kill only the direct child

With `--foreground` no reaper:

- `timeout` exits as soon as **direct child** exits, ignoring anything that child backgrounded (those reparent to `init` normally, keep running).
- On overrun, `timeout` sends signal with `kill(child_pid)` — **direct process only**, not tree (genuine overrun still killed, SIGKILL after `-k` grace).

So command under `--foreground` may freely start daemon that survives command.

## Choosing the mode — match the command's intent

| Command pattern | Mode | Why |
| --- | --- | --- |
| Starts a survivor on purpose (service restart, daemon reload) | `--foreground` | let daemon live; finish when command's own work done |
| Transform pipeline / transient helpers that should die on overrun (`curl … \| jq … \| iprange …`) | default (reaper) | hung pipeline killed cleanly as whole tree; `--foreground` would SIGKILL only shell and orphan inner stages (blocked `curl` keeps running, reparented to `init`) |

In-tree, exactly that split:

- **ADR-12 update hooks** (`pfb_run_hooks()` in `pfblockerng.inc`) run under `timeout --foreground` — documented HAProxy recipe restarts daemon *meant* to survive.
- **`list_scripts` feed pre/post scripts** stay **default** — transform pipelines, hung `curl | jq` must die as whole tree on overrun, not orphaned. Feed script that starts a service is misuse: use **post-update hook** instead, where daemon case handled right.

### Mixed survivor + transient tree: supervise a process group

Unbound startup needs both properties: the resolver that daemonizes successfully must
survive, but a stuck launcher and its ordinary helpers must all die. Neither timeout mode
can provide both: default reaper mode captures the daemon too; `--foreground` kills only
the launcher and orphans helpers.

`pfb_stop_start_unbound()` therefore starts a small PHP supervisor in its own process
group behind a five-second setup barrier. The supervisor executable is the package's
canonical CLI path (`$pfb['php']`, falling back to `PHP_BINDIR . '/php'`), never
`PHP_BINARY`: under a pfSense web request that constant names `php-cgi`, which rejects
the CLI-only `-r` option.

The parent verifies `PGID == launcher PID` before release; only the child's subsequent
start acknowledgement begins the configured command's 30-second deadline, so scheduler
delay while creating the supervisor cannot become a false command expiry. A real daemon's
`setsid()` moves it out of that group; ordinary helpers remain. Completion or deadline
sends TERM, then SIGKILL after the grace, to the negative PGID and explicitly reaps the
supervisor. Stdio targets `/dev/null` plus a regular output file, never a capture pipe.

## Don't let a daemon hold the capture pipe

PHP `exec()` / `$(command substitution)` read command stdout **to EOF**. Daemon the command spawned inherits command stdout/stderr, and while it lives pipe never reaches EOF — capture **blocks** even though command itself exited. (`timeout` reaper-wait above is *second*, independent way same hook hangs.)

Fix: send command output to **file**, read stdin from `/dev/null`:

```text
cmd > /tmp/somefile 2>&1 < /dev/null
```

Spawned daemon then holds harmless regular-file fd, capture returns moment direct command exits. Read output back from file.

## Package-page visibility is the mirror image: stream to stdout, not just the log file

Same fd stray daemon must *not* hold is one pfSense **Software page reads** to show install/upgrade/uninstall progress: **stdout**. Once Update/Uninstall buttons delegate to pfSense native `pkg_mgr_install.php`, that page shows only what package operation writes to stdout. But `pfb_logger()` writes whole sync pass to **log file** (and, during Run Now, per-run log the Update page AJAX viewer tails) — never stdout. So delegated page sits **silent** through (longstanding) disable/enable passes — worst case up-to-30 s `pfb_stop_start_unbound()` wait — looks like frozen/lost pipe even though nothing stuck (issue #690). **Visibility** gap, distinct from fd-hold hang above.

Fix (issue #690, widened by ADR-58): `pfb_logger()` **mirrors main-log lines (cases 1/2) to stdout** so page streams live progress. Gate: `pfb_run_streams_to_stdout()` — mirror only when stdout is **real watched surface**: lifecycle callback (`$pfb['hook_lifecycle']`, pkg `| tee` pipe — original #690 case) **OR interactive terminal** (`pfb_stdout_is_terminal()` = `stream_isatty(php://stdout)`, ADR-58 addition, so hand-run pass streams too). Does **not** print when stdout is **log file logger already writes** — cron tick `>> log`, detached Run-Now `>> runlog`, nested extras dispatch (`dc`/`bls`/…) — neither tty nor lifecycle, printing there would double every line; nor for **web in-process caller** (settings-save that resyncs then `header('Location')`, where stdout is HTTP response). Per-run-log fwrite-mirror (populates run-log Update viewer tails, regardless of where stdout points) unchanged. Unbound-stop wait logs keepalive dots through same path, closing that silent gap. Visibility only: fd-detach, `--foreground`, redirect safety above untouched.

**Update hook's own** stdout/stderr needs same treatment, but can't just be printed live through pipe: hook body redirected to log file precisely so daemon it starts can't hold capture pipe (above), so mirroring with `tee`/pipe would reintroduce hang. Instead, during lifecycle callback `pfb_run_hooks()` runs hook under `proc_open()` with stdout/stderr pointed at log **file** via descriptor spec (never pipe back to PHP — spawned daemon inherits only harmless file fd), tracks child with `proc_get_status()`, and **tails file to stdout with `pfb_log_tail_chunk()` while hook runs** — page shows `[ pfB Hook ] …` markers *and* hook real output streaming live between them, not one block after exit (issues #693/#883). Exit code (124 on timeout, else hook's own) comes off status; plain file read can't hang, so daemon-safety preserved. On non-lifecycle cron/manual/Run-Now path hook stays blocking `exec()` (Update page AJAX viewer already tails per-run log); `pfb_mirror_hook_output()` remains only as `proc_open`-failure fallback.

## Following one specific dispatched process — pidfile, not a `ps` pattern or a log string

- **`mwexec_bg()` returns no PID** — only launcher status. Cannot wait on what you cannot name.
- To track *one* process you dispatched, launch under `/usr/sbin/daemon -p <pidfile>` and poll pfSense **`isvalidpid($pidfile)`** — authoritative per-process liveness, pidfile self-clearing when process exits.
- **Do not** decide "is it done?" by grepping `ps` for command pattern (matches concurrent unrelated runs) or by waiting for magic **log string** (brittle: crash that never writes string loops wait forever — bug the `UPDATE PROCESS ENDED` live-tail probe had; live-log tail (`?ajax=tail` poll endpoint, `pfb_log_tail_payload()`) now keys "done" signal on `isvalidpid()` instead).
- Inherent small **launch-lag** (any process takes nonzero time to become observable). Bound with short grace; if process hasn't appeared within few seconds something already wrong — give up rather than loop.

## A *global* "is anything running?" guard still needs `ps`

Per-run pidfile answers "is process **I** launched alive?" — cannot answer "is **any** instance running?". Scheduled cron tick that fired independently has no per-run pidfile, so guard that refuses second run must scan **`ps`** (sees every process regardless of who launched it). In this package anti-double-run guard (`pfb_active_task_running()` → `pfb_feed_task_running()`) is `ps`-based for exactly this reason, while per-run live-log tail (AJAX poll "done" check) uses pidfile.

## Testing: launch detached, never drive-and-wait over SSH

Test that launches work **over SSH** and waits inline hangs on backgrounded child via sshd *own* channel-EOF wait — conflates SSH-channel wait with process stall you test (failure becomes indistinguishable from bug). Launch work **detached** (`nohup … >> log 2>&1 </dev/null &`) and poll on-disk log / markers, so only thing under observation is process behaviour itself.

## See also

- `pfb_run_hooks()` (`--foreground` + temp-file capture) in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — landed in PR #634.
- Detached `daemon -p` dispatch (`pfb_runnow()` / `pfb_runnow_forcecheck()` in `pfblockerng_update.php`, `pfb_software_dispatch()` in `pfblockerng_software.php`) feeding `?ajax=tail` poll endpoint (`pfb_log_tail_payload()` keyed on `isvalidpid`) — live-log tail.
- Bounded nested-`pfblockerng.php` re-entry (issue #2016): `pfb_reentry_cmd()` / `pfb_reentry_exec()` in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` use default (reaper) mode, output to a file and stdin `/dev/null`; `pfb_reentry()` in `src/usr/local/pkg/pfblockerng/pfblockerng.sh` uses default (reaper) mode with inherited stdio. Both name a 124 failure; `scripts/check_reentry_bounds.py` keeps new callers on the seam. The budget is **one global operator setting** since issue #2851 (General → Advanced, *Nested pass timeout*, registered `gen/pfb_reentry_timeout`): each language normalizes the stored value where it enters the process — `pfb_reentry_budget()` in PHP, the init block's `pfb_reentry_timeout()` in shell — accepting whole seconds in `[60, 7200]` and resolving anything else to the finite 1800-second default. A knob can therefore raise the wait for a slow link but never remove it.
- CLAUDE.md "Bounded waits" and Python "no fixed-time waits to coordinate concurrency" rule — agent/test-side analogue: synchronise on signal, bound every wait, never sleep-poll blindly.
- FreeBSD `bin/timeout/timeout.c` — `PROC_REAP_ACQUIRE`, `rs_children == 0` exit condition, `send_sig()` (`kill(child)` under `--foreground` vs reaper kill by default).
