# Launching and waiting on external processes

Running an external OS process from PHP or shell and then *waiting on it* has several
non-obvious semantics that have bitten this package — a post-update hook falsely timing
out and killing the daemon it had just (re)started, and the Update-page live tail hanging.
Read this before writing or changing code that runs `timeout(1)`, `mwexec_bg()`, a spawned
daemon / `service` restart, or a live-tail / poll loop.

## FreeBSD `timeout(1)` is a process *reaper* by default

In its default mode `/usr/bin/timeout` calls `procctl(PROC_REAP_ACQUIRE)` and becomes a
**process reaper** (FreeBSD source: `bin/timeout/timeout.c`). That changes two things:

- **It does not exit when its direct child exits.** It waits until *every* descendant is
  gone (its loop breaks only when the reaper status reports `rs_children == 0`), then on the
  alarm it signals the **whole reaped tree**.
- **Backgrounding cannot escape it.** `&`, `nohup`, and even a "proper" double-fork +
  `setsid` daemonization normally reparent the child to `init` (pid 1) and detach it from its
  original parent — but a reaper *intercepts that reparenting*, so the descendant reparents to
  **timeout** instead and still counts. Daemonizing does **not** detach a process from a
  default-mode `timeout`.

**Consequence:** a command that deliberately starts a long-lived daemon — e.g. an HAProxy
graceful reload — keeps `timeout` alive for the entire budget, and then the reaper-kill on the
alarm takes the freshly-started daemon down with it. The symptom is a false
`TIMED OUT after <budget>s (killed)` logged *after* the command's own work already finished in
milliseconds.

## `--foreground` (`-f`): wait on / kill only the direct child

With `--foreground` there is no reaper:

- `timeout` exits as soon as the **direct child** exits, ignoring anything that child
  backgrounded (those reparent to `init` normally and keep running).
- On an overrun, `timeout` sends the signal with `kill(child_pid)` — the **direct process
  only**, not the tree (a genuine overrun is still killed, SIGKILL after the `-k` grace).

So a command run under `--foreground` may freely start a daemon that survives the command.

## Choosing the mode — match the command's intent

| Command pattern | Mode | Why |
| --- | --- | --- |
| Starts a survivor on purpose (service restart, daemon reload) | `--foreground` | let the daemon live; finish when the command's own work is done |
| Transform pipeline / transient helpers that should die on overrun (`curl … \| jq … \| iprange …`) | default (reaper) | a hung pipeline is killed cleanly as a whole tree; `--foreground` would SIGKILL only the shell and orphan the inner stages (a blocked `curl` keeps running, reparented to `init`) |

In-tree this is exactly the split:

- The **ADR-12 update hooks** (`pfb_run_hooks()` in `pfblockerng.inc`) run under
  `timeout --foreground` — the documented HAProxy recipe restarts a daemon that is *meant* to
  survive.
- The **`list_scripts` feed pre/post scripts** stay on **default** mode — they are transform
  pipelines, and a hung `curl | jq` must be killed as a whole tree on overrun, not orphaned.
  A feed script that needs to start a service is misuse: use a **post-update hook** instead,
  where the daemon case is handled correctly.

## Don't let a daemon hold the capture pipe

PHP `exec()` / `$(command substitution)` read the command's stdout **to EOF**. A daemon the
command spawned inherits the command's stdout/stderr, and while it lives the pipe never reaches
EOF — so the capture **blocks** even though the command itself exited. (`timeout`'s reaper-wait
above is a *second*, independent way the same hook hangs.)

Fix: send the command's output to a **file** and read stdin from `/dev/null`:

```text
cmd > /tmp/somefile 2>&1 < /dev/null
```

A spawned daemon then holds a harmless regular-file fd, and the capture returns the moment the
direct command exits. Read the output back from the file.

## Package-page visibility is the mirror image: stream to stdout, not just the log file

The same fd that a stray daemon must *not* hold is the one the pfSense **Software page reads** to
show install/upgrade/uninstall progress: **stdout**. Once the Update/Uninstall buttons delegate to
pfSense's native `pkg_mgr_install.php`, that page shows only what the package operation writes to
stdout. But `pfb_logger()` writes the whole sync pass to the **log file** (and, during a Run Now,
the per-run log the Update page's AJAX viewer tails) — never stdout. So the delegated page sits
**silent** through the (longstanding) disable/enable passes — worst case the up-to-30 s
`pfb_stop_start_unbound()` wait — and looks like a frozen/lost pipe even though nothing is stuck
(issue #690). This is a **visibility** gap, distinct from the fd-hold hang above.

Fix: while a package lifecycle callback is active — `$pfb['hook_lifecycle']` is set by the install
command (`'install'`) and the pre-deinstall (`'uninstall'`), unset on every normal
cron/manual/Run-Now pass — `pfb_logger()` also **mirrors its main-log lines (cases 1/2) to stdout**,
so the page streams live progress. The unbound-stop wait logs its keepalive dots through the same
path, so that closes the silent gap too. Visibility only: the fd-detach, `--foreground`, and
redirect safety above are untouched.

## Following one specific dispatched process — pidfile, not a `ps` pattern or a log string

- **`mwexec_bg()` returns no PID** — only the launcher's status. You cannot wait on what you
  cannot name.
- To track the *one* process you dispatched, launch it under `/usr/sbin/daemon -p <pidfile>`
  and poll pfSense's **`isvalidpid($pidfile)`** — authoritative per-process liveness, and the
  pidfile is self-clearing when the process exits.
- **Do not** decide "is it done?" by grepping `ps` for a command pattern (it matches concurrent
  unrelated runs) or by waiting for a magic **log string** (brittle: a crash that never writes
  the string loops the wait forever — this is the bug the `UPDATE PROCESS ENDED` live-tail probe
  had; the live-log tail (the `?ajax=tail` poll endpoint, `pfb_log_tail_payload()`) now keys its
  "done" signal on `isvalidpid()` instead).
- There is an inherent, small **launch-lag** (any process takes nonzero time to become
  observable). Bound it with a short grace; if the process hasn't appeared within a few seconds
  something is already wrong, so give up rather than loop.

## A *global* "is anything running?" guard still needs `ps`

A per-run pidfile answers "is the process **I** launched alive?" — it cannot answer "is **any**
instance running?". A scheduled cron tick that fired independently has no per-run pidfile, so a
guard that refuses to start a second run must scan **`ps`** (it sees every process regardless of
who launched it). In this package the anti-double-run guard (`pfb_active_task_running()` →
`pfb_feed_task_running()`) is `ps`-based for exactly this reason, while the per-run live-log tail
(the AJAX poll's "done" check) uses the pidfile.

## Testing: launch detached, never drive-and-wait over SSH

A test that launches the work **over SSH** and waits inline will hang on a backgrounded child
via sshd's *own* channel-EOF wait — which conflates the SSH-channel wait with the process stall
you are trying to test (the failure becomes indistinguishable from the bug). Launch the work
**detached** (`nohup … >> log 2>&1 </dev/null &`) and poll the on-disk log / markers, so the only
thing under observation is the process behaviour itself.

## See also

- `pfb_run_hooks()` (the `--foreground` + temp-file capture) in
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — landed in PR #634.
- The detached `daemon -p` dispatch (`pfb_runnow()` / `pfb_runnow_forcecheck()` in
  `pfblockerng_update.php`, `pfb_software_dispatch()` in `pfblockerng_software.php`) feeding the
  `?ajax=tail` poll endpoint (`pfb_log_tail_payload()` keyed on `isvalidpid`) — the live-log tail.
- CLAUDE.md "Bounded waits" and the Python "no fixed-time waits to coordinate concurrency" rule —
  the agent/test-side analogue: synchronise on a signal and bound every wait, never sleep-poll
  blindly.
- FreeBSD `bin/timeout/timeout.c` — `PROC_REAP_ACQUIRE`, the `rs_children == 0` exit condition,
  and `send_sig()` (`kill(child)` under `--foreground` vs the reaper kill by default).
