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
- **The boot hook's `dns_check`** (`pfb_upstream_observer_include.inc`, `timeout --foreground`, 360 s) confirms the proxy start and, when a stranger holds Unbound's loopback ports, moves Unbound's backend pair (issue #3848): that restarts Unbound and the gateway, daemons meant to survive the check, so `--foreground`; the reaper mode would take them down when the check exited. When the rc start refused for that stranger and left its marker, there is no start to confirm: `dns_check` then runs the update pass's own check (`pfb_dns_proxy_ensure_running()`), which moves Unbound to a free pair and starts the gateway, or keeps the gateway blocked with its notice when none is free. With no marker it never calls that check, so it cannot start a second gateway beside the rc start that is still launching one; a marker that appears while it waits ends the wait without a startup problem.
- **`list_scripts` feed pre/post scripts** stay **default** — transform pipelines, hung `curl | jq` must die as whole tree on overrun, not orphaned. Feed script that starts a service is misuse: use **post-update hook** instead, where daemon case handled right.

### Core's Go process lifetimes

`internal/process` provides two entry points, and each one encodes a separate lifetime policy. `Run` is the strict policy, and `RunIndependent` is the independent policy.

| Entry point | Caller | Leader still running | After the leader exits | Owner (Core) dies |
| --- | --- | --- | --- | --- |
| `Run` (strict) | The feed pre-script (`feedparse.RunPreScript`). No production path calls it yet: the Go Update pipeline will run user scripts and external programs through it. | The command is Core's direct child in a watchdog-led process group. On cancellation or the pre-script's 300-second limit, the group receives TERM. If the leader is still running 5 seconds later, the whole group is KILLed. | The remaining attached group is KILLed before `Run` returns. A child that calls `setsid()` leaves the group and survives. | On Linux and FreeBSD, the watchdog cleans up the group. |
| `RunIndependent` (independent) | The Update's apply program (the holder in `update/worker.go`). | The runner starts the program, waits for it, and returns its real exit status. It never signals the program or its descendants. | The runner returns the status and signals nothing, so descendants keep running. | Core stop, crash or restart ends observation, not the transaction. |

The Update program runs in an independent worker protected by `update.log.lock` and private receipts. Core stop or death
ends observation, not the transaction; a restarted Core observes a live worker or reconciles its completion. There is no
whole-Update cap or process-group kill; each download or script keeps its operation-level bound. Scheduled maintenance is not
present in this worktree: when #3996 integrates, it must use its own independent lane, not this strict runner or the Update lease.

#### User scripts

- Finish feed transforms and all writes to staged data **synchronously**, before returning.
- `&` and `nohup` do **not** detach a process from its process group. `setsid()` or a daemonizing `daemon(8)` launch establishes
  independent session or group ownership.
- Redirect stdio yourself when detaching (see "Don't let a daemon hold an output pipe").
- For an intentional long-lived service, use the **post-update hook** and the service's real daemonizing rc interface, not a
  transform script that backgrounds a process.

PHP's legacy `list_scripts` default-mode `timeout` reaper still captures detached descendants (see the reaper section above);
use the post-update hook.

#### Services the Update's apply can start

Nothing signals the apply's process group any more (PR #4025, issue #4022), so a service that remains in that group is not killed
by Core stop, crash or cancellation. This includes native Kea DHCPv4 and DHCPv6 (started by pfSense `mwexec_bg()`, which does not
leave the group), the firewall reload and the filter-log pipeline. The detach status below still determines what a strict caller
would kill.

The rows below are installed pfSense 2.8.1-RELEASE source and manual findings, plus the controlled native observations named after
the table. They are not a blanket runtime qualification of every service.

Core's `pfb_core_update.sh` execs PHP's `core_update` entry, whose
`pfb_core_update_run()` reaches `sync_package_pfblockerng()` directly or through the
scheduled pass. Package functions below live in `pfblockerng.inc` or
`pfblockerng_apply.inc`; native functions refer to the captured installed includes.
Conditional starts are in scope even when the source-capture guest did not enable them.

| Reachable leaf / entry | Actual wrapper and target mode | Source-level conclusion / remaining qualification |
| --- | --- | --- |
| `pfb-core` | Generated `pfb_core.sh`: `daemon -r -R 5 -t pfb_core -P … -p … -o … pfb-core …`, redirected stdio | Install calls `restart_service('pfb_core')`; aborted-removal recovery starts it only if absent. An ordinary Update does not restart its owning Core. Explicit daemon wrapper, not a service-runtime proof. |
| `pfb-dns` | `pfb_dns_proxy_ensure_running()` / Resolver move → generated `pfb_dns_proxy.sh`: `daemon -r -R 5 -t pfb_dns_proxy -P … -p … -o …` → gateway wrapper/exec; redirected stdio and closed extra descriptors | Explicit daemon wrapper. The Unbound include's background start and `dns_check` are additional routes to the same rc interface, not independent service owners. |
| Unbound supervisor | `pfb_stop_start_unbound()` gives the PHP launcher a verified new PGID, then runs `/usr/local/sbin/unbound -c /var/unbound/unbound.conf` | The launcher group is explicit; group cleanup is not itself daemon detachment. Installed config says `do-daemonize: yes`; installed Unbound 1.24.2 manual identifies `-d` as no-fork, absent here. |
| Unbound direct configuration | Listener-advertisement changes and Resolver moves → `services_unbound_configure(TRUE/FALSE)` → `sync_unbound_service()` → `do_as_unbound_user('start')` → `unbound -c …` | Same native target mode, without the package startup supervisor. `TRUE` also configures DHCP; both enabled-Resolver paths call `system_dhcpleases_configure()`, which returns immediately for Kea and conditionally starts the ISC lease monitor below. |
| `pfb_filter` readers and PHP consumer | `start_service()` / `restart_service()` → generated `pfb_filter.sh`: `{ tail_pfb … \| php_pfb … filterlog ; } >/dev/null 2>&1 </dev/null &` (legacy `clog_pfb` alternative) | Backgrounded brace group with outer stdio redirected; not detached, so the whole pipeline stays in the caller's process group. Not killed by Core: nothing signals the apply's group. |
| Firewall reload | `pfb_filter_reload_exec()` runs `/etc/rc.filter_configure_sync > /dev/null 2>&1 < /dev/null &` through PHP `exec()` | Backgrounded with stdio redirected, not detached: it stays in the caller's process group (a controlled target through the actual helper retained the caller's PGID on pfSense 2.8.1). Not killed by Core: nothing signals the apply's group. The reload can finish after the Update. |
| Native `filterlog` | Reload → `filter_pflog_start()` → `mwexec('filterlog -i pflog0 -p /var/run/filterlog.pid')` when absent | Installed package is 0.1_10. Matching official ports source calls `daemon(0, 0)` unless offline `-P` is supplied; actual argv has no `-P`. |
| Native `filterdns` | Reload → `filter_configure_sync()` → `filterdns -p … -i <interval> -c /var/etc/filterdns.conf -d 1`, or HUP if already running | Installed 2.2 matches official ports source: `-d` sets verbosity; `-f` sets foreground. With no `-f`, `main()` calls `daemon(0, 0)`. Source evidence, not a native runtime claim. |
| Native `xinetd` and on-demand children | Reload → NAT generation → `xinetd -syslog daemon -f /var/etc/xinetd.conf -pidfile /var/run/xinetd.pid`, or HUP | Installed 2.3.15_3 manual says `-dontfork` stays attached; it is absent. Generated services can later launch `nc` reflection helpers and `tftp-proxy`; these are xinetd descendants, not directly Update-launched daemons. |
| After-filter user command / plugin tree | Reload writes `/tmp/commands.txt`, runs `mwexec('sh /tmp/commands.txt &')`, and invokes `/usr/local/pkg/pf/` plugins | Arbitrary configured commands cannot be enumerated as fixed leaves. `&` does not detach them from their caller group; they stay in the reload's process group. No promise that every user command self-daemonizes. |
| ISC DHCPv4 / DHCPv6 | Listener changes → `services_dhcpd_configure()` → native `dhcpd [-6] -user dhcpd -group _dhcp -chroot … -cf /etc/dhcp[d/v6].conf -pf … <interfaces>` through `mwexec()` | Installed ISC 4.4.3P1_5 manual identifies `-f` / `-d` as foreground; neither is supplied. Native rc.d scripts are not the actual launch route here. |
| `radvd` | Same DHCP configure path → `services_radvd_configure()` → `radvd -p … -C /var/etc/radvd.conf -m syslog`, or HUP | Installed 2.20 manual says `-n` prevents daemonization; absent here. Native rc.d script is not this launch route. |
| `dhcpleases6` and prefix callback | ISC DHCPv6 configure → `dhcpleases6 -c "/usr/local/bin/php-cgi -f /usr/local/sbin/prefixes.php" -l …/dhcpd6.leases` through `mwexec()` | Installed 0.1_3 has no captured manual. Matching official ports source calls `closefrom(3); daemon(0, 0)` before initial and later `system(command)` callbacks. Installed `prefixes.php` adds/deletes routes through `/sbin/route` helpers and reads DHCP logs through a cat/decompression command; it starts no additional service daemon. |
| Kea DHCPv4 / DHCPv6 | Same DHCP configure dispatcher → `mwexec_bg('kea-dhcp4 -c /usr/local/etc/kea/kea-dhcp4.conf')` / corresponding `kea-dhcp6` | Stays in the caller's process group: installed 2.6.2 binaries launched with private, port-free configurations retained the caller's PGID (native observation). The native launch is only `nohup … &`. Not a violation since #4025: nothing signals that group, and its native matrix shows both servers surviving Core TERM and SIGKILL. |
| Kea hook helpers | Asynchronous `libdhcp_run_script` hooks invoke installed `kea_run4/6`, which run executable scripts from the first matching `/conf` or `/cf/conf` family script directory through `/bin/sh` | Generated `kea2unbound … sync` queries Kea and uses transient `unbound-control` commands (`get_option pidfile`, `list_local_data`, `reload`, `local_datas`, `local_datas_remove`); it does not start Unbound. `kea2fib6 … sync` queries Kea and uses route add/delete helpers. These supplied scripts do not detach or start another daemon; arbitrary custom scripts remain an open-ended command tree. |
| `cron` | Reload's `filter_tdr_install_cron()` (when schedule entry changes) → `configure_cron()` → `cron -s` if absent, otherwise HUP | Era-matched FreeBSD 15-CURRENT source calls `daemon(1, 0)` unless `-n` or debug flags suppress it; `-s` only enables DST handling. Those suppressing flags are absent from installed source argv. Upstream source qualification, not installed-binary provenance or runtime proof. |
| `dhcpleases` | Enabled Unbound configuration → `system_dhcpleases_configure()` → `dhcpleases -l …/dhcpd.leases -d <domain> -p /var/run/unbound.pid -u /var/unbound/dhcpleases_entries.conf -h /etc/hosts` | Installed definition returns for Kea, and starts only for enabled DHCP plus Resolver/Forwarder lease registration. Matching official 0.5_1 source: `-d` is the domain, `-f` selects foreground (absent), default calls `daemon(0, 0)`. Without `-c`, it updates files and HUPs the existing DNS PID; it does not launch a DNS daemon. |
| `syslogd`, `sshguard` | Update's missing syslog-drop-in gate → `system_syslogd_start(TRUE)`; a missing syslog PID converts HUP into `mwexec_bg('syslogd …')`. Local logging enabled → `daemon -R 60 -P /var/run/daemon_sshguard.pid -t sshguard /usr/local/sbin/sshguard -i /var/run/sshguard.pid` | Both are reachable independently of DHCP configuration. Full installed `syslog.inc` proves the fallback and explicit sshguard wrapper. Era-matched FreeBSD 15-CURRENT syslogd source uses `waitdaemon(30)` → `fork()` → child `setsid()` unless `-F` or `-d` is supplied; neither is in installed source argv. Upstream mode evidence, not installed-binary provenance or runtime proof; nohup itself is not detachment. |

Audit evidence: native run `local-100037-1794709124-6edd2459a6710f59` (full installed includes,
generated rc scripts, target hashes and available manuals). Matching primary source:
[dhcpleases6 0.1_3](https://github.com/pfsense/FreeBSD-ports/tree/084b4ad9f65198720720f84d04eeed7c441ed49c/sysutils/dhcpleases6)
and [filterlog 0.1_10](https://github.com/pfsense/FreeBSD-ports/tree/2169affb228d3b5cb8f2ab9a7cdce298d1dbdf65/sysutils/filterlog),
[filterdns 2.2](https://github.com/pfsense/FreeBSD-ports/tree/0184d70244ece30e0c1c5224f3b881adc7183fe1/net/filterdns).
These version matches do not prove byte-identical builds. Public pfSense master
**2.9-dev** is not a substitute for installed **2.8.1** source.

Additional installed source and controlled-probe evidence: run `local-100031-1794710724-b1d6e97c3d8727f9`.
The controlled Kea observations
use the real installed binaries with private PID/control/log paths and no DHCP interfaces;
they establish that Kea stays in its caller's process group, not a test of the live DHCP service configuration.
[Matching dhcpleases 0.5_1 source](https://github.com/pfsense/FreeBSD-ports/tree/084b4ad9f65198720720f84d04eeed7c441ed49c/sysutils/dhcpleases)
supplies the lease monitor's missing installed manual evidence.

For base-system targets, [cron source](https://github.com/freebsd/freebsd-src/blob/fe590ffe40f49fe09d8275fbf29f0d46c5b99dc7/usr.sbin/cron/cron/cron.c)
and [syslogd source](https://github.com/freebsd/freebsd-src/blob/47785e6a39cdcbf4eb7d02c381a53916774ed991/usr.sbin/syslogd/syslogd.c)
are upstream `main` revisions predating the captured image's 2025-08-28 kernel build,
when it identified as FreeBSD 15-CURRENT. The image's private
pfSense build revision is not available in the public fork; these citations establish
version-appropriate upstream mechanisms, not exact installed build provenance.

Transient helpers are not service daemons: feed transform stages (`curl`, `jq`,
`iprange`), `unbound-control` under `chroot`, readiness probes (`sockstat`, `pgrep`),
lock/wait helpers (`lockf`, `sleep`), and bounded nested PHP/shell passes should finish
with their owning operation. Settings-adapter (`settings/adapter.go`) and rsync (`feedfetch/rsync_unix.go`) launchers keep their own process-group kill; they are outside #4020.

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

SIGKILL only queues the signal: a killed member stays in the group until it has exited
and been reaped, usually by init after its parent died too. So after either group SIGKILL the
function polls `kill(-PGID, 0)` every 10 ms until the group is gone, for at most one more
`PFB_HOOK_KILL_GRACE` (5 s); a group still present then is logged and the function returns
anyway (issue #3663). An expired start therefore returns at most two graces after its
30-second deadline: the TERM grace, then this post-KILL wait.

## Don't let a daemon hold an output pipe

PHP `exec()` / `$(command substitution)` read command stdout **to EOF**. A daemon the command spawned can inherit stdout/stderr
and keep a pipe open after the direct command exits, blocking capture. (`timeout` reaper-wait above is a second, independent
way the same hook can hang.)

When output must be retained, give the child a regular file for stdout/stderr and `/dev/null` for stdin:

```text
cmd > /tmp/somefile 2>&1 < /dev/null
```

The script-output runner uses one fresh private regular capture file per invocation. Scripts MUST emit UTF-8 or compatible
ASCII; output is not locale-detected or transcoded. Printable Unicode, LF and TAB stay unchanged. Other ASCII controls and
DEL, malformed UTF-8 bytes, and CR (including the CR in CRLF) become uppercase `\xNN`; Unicode `Cc`/`Cf` becomes `\u{HEX}`.
The full sanitized text goes to the main log and, when distinct, the viewer. The main log is uncapped; the viewer gets at
most 1,000,000 sanitized Unicode code points from combined stdout/stderr. It gets one overflow notice only if more output
exists. Later progress and invocations remain independent.

## Package-page visibility is the mirror image: stream to stdout, not just the log file

Same fd stray daemon must *not* hold is one pfSense **Software page reads** to show install/upgrade/uninstall progress: **stdout**. After Update/Uninstall buttons delegate to native `pkg_mgr_install.php`, that page shows only package-operation stdout. Core's Update viewer instead polls `GetUpdate`, which reads the retained, complete `update.log` transcript; it never tails the rotating main log. That transcript is not the Software page stream, so silence there remains a separate **visibility** gap.

Fix (issue #690, widened by ADR-58): `pfb_logger()` **mirrors main-log lines (cases 1/2) to stdout** so the Software page streams live progress. Gate: `pfb_run_streams_to_stdout()` — mirror only when stdout is **real watched surface**: lifecycle callback (`$pfb['hook_lifecycle']`, pkg `| tee` pipe — original #690 case) **OR interactive terminal** (`pfb_stdout_is_terminal()` = `stream_isatty(php://stdout)`, ADR-58 addition, so hand-run pass streams too). Does **not** print when stdout is **log file logger already writes** — cron tick `>> log`, detached Run-Now `>> runlog`, nested extras dispatch (`dc`/`bls`/…) — neither tty nor lifecycle, printing there would double every line; nor for **web in-process caller** (settings-save that resyncs then `header('Location')`, where stdout is HTTP response). Core captures Update stdout/stderr in the dedicated transcript and `GetUpdate` reads only that transcript; the rotating main log remains separate. Unbound-stop wait logs keepalive dots through the same path, closing that silent gap. Visibility only: fd-detach, `--foreground`, redirect safety above untouched.

**Hook and list-script output** uses `pfb_script_output_exec()`: stdout and stderr share a fresh private regular capture file,
not a pipe. The PHP status loop drains bounded chunks through the UTF-8 sanitizer and writes the full sanitized output to
the main log plus a character-limited prefix to a distinct viewer. It never waits for inherited-fd EOF; the cutoff is the
capture size observed when the direct runner exits. A daemon that outlives a global hook cannot hold the runner open. Global
hooks retain `timeout --foreground` so restarted services survive; list transforms retain default reaper mode so a hung
transform tree is killed. During package lifecycle callbacks, sanitized hook output is also mirrored from the capture to
stdout, preserving Software-page visibility without piping child output back to PHP.

## Following one specific dispatched process — pidfile, not a `ps` pattern or a log string

- **`mwexec_bg()` returns no PID** — only launcher status. Cannot wait on what you cannot name.
- To track *one* process you dispatched, launch under `/usr/sbin/daemon -p <pidfile>` and poll pfSense **`isvalidpid($pidfile)`** — authoritative per-process liveness, pidfile self-clearing when process exits.
- **Do not** decide "is it done?" by grepping `ps` for command pattern (matches concurrent unrelated runs) or by waiting for magic **log string** (brittle: crash that never writes string loops wait forever — bug the `UPDATE PROCESS ENDED` live-tail probe had; the Update page's live view (`?ajax=update`, `pfb_update_view_response()`) takes "done" from Core's `GetUpdate.running`, the one Update's own state, since issue #3941).
- Inherent small **launch-lag** (any process takes nonzero time to become observable). Bound with short grace; if process hasn't appeared within few seconds something already wrong — give up rather than loop.

## A *global* "is anything running?" guard still needs `ps`

Per-run pidfile answers "is process **I** launched alive?" — cannot answer "is **any** instance running?". Scheduled cron tick that fired independently has no per-run pidfile, so guard that refuses second run must scan **`ps`** (sees every process regardless of who launched it). In this package the Update page's anti-double-run guard was `ps`-based for exactly this reason; since issue #3941 Core's singleton Update gate is that guard (`StartUpdate` is refused with `conflict` while one runs), and `pfb_update_pass_running()` is the `ps`-based check left, for the tick's log-maintenance gate.

## Testing: launch detached, never drive-and-wait over SSH

Test that launches work **over SSH** and waits inline hangs on backgrounded child via sshd *own* channel-EOF wait — conflates SSH-channel wait with process stall you test (failure becomes indistinguishable from bug). Launch work **detached** (`nohup … >> log 2>&1 </dev/null &`) and poll on-disk log / markers, so only thing under observation is process behaviour itself.

## Testing: cap every agent run's memory and wall time

Every test an agent runs outside CI (suites, `scripts/agent/run-gates.sh`, mutation runners and probes) runs under a memory and wall-time cap, so a runaway dies in its own cgroup instead of taking the host down:

```sh
systemd-run --scope -q -p MemoryMax=6G -p MemorySwapMax=0 timeout -k 10 <secs> <command>
```

A mutant that raises or removes a size ceiling keeps the cap: that mutant is exactly the run that publishes gigabytes (2026-11-14 OOM, `docs/history/incidents.md`). Never `chmod` or `chown` a shared directory such as `/tmp` recursively; a test run as another user gets a private `mktemp -d` directory.

## See also

- `pfb_run_hooks()` (`--foreground` + temp-file capture) in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — landed in PR #634.
- Detached `daemon -p` dispatch of `pfb_software_dispatch()` in `pfblockerng_software.php`. The Update page no longer dispatches a process (issue #3941): Run Now is Core's `StartUpdate` (`pfb_update_start()`), and the live view polls `?ajax=update` (`pfb_update_view_response()`), which relays `GetUpdate`.
- Bounded nested-`pfblockerng.php` re-entry (issue #2016): `pfb_reentry_cmd()` / `pfb_reentry_exec()` in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` use default (reaper) mode, output to a file and stdin `/dev/null`; `pfb_reentry()` in `src/usr/local/pkg/pfblockerng/pfblockerng.sh` uses default (reaper) mode with inherited stdio. Both name a 124 failure; `scripts/check_reentry_bounds.py` keeps new callers on the seam. The budget is **one global operator setting** since issue #2851 (General → Advanced, *Nested pass timeout*, registered `gen/pfb_reentry_timeout`): each language normalizes the stored value where it enters the process — `pfb_reentry_budget()` in PHP, the init block's `pfb_reentry_timeout()` in shell — accepting whole seconds in `[60, 7200]` and resolving anything else to the finite 1800-second default. A knob can therefore raise the wait for a slow link but never remove it.
- Detached firewall-configuration reload (`pfb_filter_reload_exec()` in `src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc`; owner directive 2026-09-05 supersedes the issue #2878 `timeout --foreground` bound): `rc.filter_configure_sync` is fired `> /dev/null 2>&1 < /dev/null &` and never waited on — pfSense's reload is uncontrollable, and the survivors it starts are its own. The script itself loads the ruleset synchronously under pfSense's `filter` lock (`filter_configure_sync()` → `pfctl -f rules.debug`) before it exits; the rules land after pfBlockerNG's pass returns only because the launch is detached. The only owned failure is the launch: a missing/non-executable script gate returns -1, marks the pass pending, and names itself in the logs.
- Core API service (issue #3908): generated `pfb_core.sh` `start` and `stop` each run themselves once more under `/usr/bin/lockf -k -t 20 /var/run/pfb_core.lock` (the inner run is marked by an environment variable so it does not lock again, and the variable is unset before `daemon(8)` runs), so concurrent starts cannot both pass the "already serving?" check before `daemon(8)` has written a pidfile, and a stop never removes the pidfile of a supervisor that has not written its pid yet; lockf giving up (a holder takes up to 12 s: its stop and the confirmation) logs one error and exits 75. A `daemon(8)` that exits non-zero is logged and fails the start. Inside the lock the start then confirms the supervisor, polling once per `/bin/sleep 1` tick for at most 5 ticks until the daemon pidfile names a process whose command line is the supervisor's (the `daemon -t pfb_core` title, or `daemon(8)`'s own command line until it sets the title); none → one error and exit 1, so the next serialized start finds the supervisor serving. The stop polls both pidfiles the same way (TERM at 0 s, KILL at 5 s, give up at 7 s with `rc_stop` returning 1 and the pidfiles kept); `start` (and the script's own `restart`) fail over a survivor instead of launching over it. **Readiness:** pfSense's `start_service()` backgrounds the start (`mwexec_bg`) and `restart_service('pfb_core')` runs the stop, then that background start, so both return before Core is confirmed, let alone listening, and a failed start is seen only in the system log; a caller that needs the API handles `pfb_core_call()`'s status 0 (the smoke test waits for the socket).
- DNS proxy stop (issues #3515, #3561): generated `pfb_dns_proxy.sh` TERMs the `daemon(8)` supervisor and the proxy child named by its two pidfiles, polls their liveness once per second (TERM at 0 s, KILL at 5 s, give up at 7 s with `rc_stop` returning 1), and signals a pid only while its `ps` command line is one of three (`$proxyArgs` in `pfb_dns_proxy_service()`, one pattern for the stop and for `rc_start`'s survivor check): the supervisor's (`*pfb_dns_proxy*`, its `daemon -t` title), the wrapper's before it execs (`/bin/sh .../dns_proxy/pfb_dns.sh *`, so a child still in the wrapper is not left behind), or, since issue #3513, the installed gateway's (`dns_proxy/bin/freebsd-*/pfb-dns`, which `pfb_dns.sh` exec'd). The Resolver restore runs the installed rc script's `stop` synchronously through `mwexec()`, independently of service registration, so it waits at most 7 s for the Resolver's port to free, inside the config lock below (`pfb_dns_proxy_resolver(FALSE)` stops the proxy only once it holds the lock); `rc_start` never launches over a survivor. A restore abandoned because the proxy outlived its stop restarts the proxy after the lock is released: one stop, up to 7 s, outside the lock.
- DNS proxy start (issues #3515, #3560, #3845): `start_service()` and `restart_service()` return before the new proxy has bound anything, so actual activation and boot confirm through `pfb_dns_proxy_confirm_ready()`. The update pass and tick use `pfb_dns_proxy_confirm_started()`, passing whether they started or restarted the gateway themselves. Its `pfb_dns_proxy_await_ready()` polls every 100 ms against the `PFB_DNS_PROXY_START_WAIT` `hrtime()` deadline (the Unbound startup budget, 30 s), on `pfb_dns_proxy_serving_ready()`. Serving readiness requires the live child PID and matching ready marker, a validated applied-status response from the existing private control socket, and Unbound-owned TCP and UDP sockets on the response's applied upstream endpoint. Saved settings and the rc script are not runtime evidence. The status exchange bounds connect, send and reply separately by `PFB_DNS_PROXY_CTL_TIMEOUT`; native `sockstat` retains its one-second budget plus `PFB_HOOK_KILL_GRACE`, in default reaper mode. A final check can extend the outer deadline only by these bounds. The wait never runs under the DNS config lock. A start that is not serving within the budget is reported by the startup check and changes nothing else: nothing rolls it back and the Resolver stays moved (issue #3848).
- DNS proxy pass without a start/restart (issues #3845, #3848): failed control-status reads and a missing Resolver backend do not start an activation wait, and nothing gives the Resolver back. Existing startup diagnostics still run; a lost backend makes **Service** say `Resolver backend not answering: <why>` and is a problem of the startup notice. A READY gateway whose Unbound upstream a foreign process owns is the one finding that acts: it moves Unbound's backend ports, or stops the gateway when no move is possible (next bullets). No argv/config fallback or new retry is added here.
- DNS proxy no-start check (issues #3845, #3848): a pass that started nothing first asks `pfb_dns_proxy_backend_move_off_holder()`: one bounded `sockstat` scan of the pair the clause names (`pfb_dns_proxy_backend_holder()` over `pfb_dns_proxy_listening_sockets()`, the PHP-side parser `pfb_dns_proxy_upstream_state()` uses too; the rc script's start has its own `sh` check, below), and only a holder of the pair moves anything or stops the gateway. `pfb_dns_proxy_startup_check()` then makes its own single bounded status read; no other deadline is introduced. A gateway stopped for a holder that no move could clear is not waited for: `pfb_dns_proxy_confirm_ready()` returns at once while the marker stands.
- DNS proxy backend port move (issue #3848): `pfb_dns_proxy_backend_move()` runs when another process holds a port of Unbound's loopback pair, or the Resolver's Listen Port is on it: `pfb_dns_proxy_ensure_running()` asks `pfb_dns_proxy_backend_holder()` (one bounded `sockstat` scan of both ports) before it starts or restarts the gateway, `pfb_dns_proxy_confirm_ready()` and `pfb_dns_proxy_confirm_started()` ask `pfb_dns_proxy_backend_move_off_holder()`, and the Resolver pass (`pfb_dns_proxy_resolver_locked()`) moves the pair itself for a Listen Port. Its waits: one bounded `sockstat` scan for the free pair (`pfb_dns_proxy_backend_pick()`, 1 s; for a holder move it runs before the lock, for a Listen Port move inside it), the config lock (`PFB_DNS_CONFIG_LOCK_WAIT`, 10 s, held for the one read-modify-write, plus that scan when the Listen Port is on the pair), pfSense's own `services_unbound_configure()` (not bounded by pfBlockerNG, as in the Resolver pass), one `restart_service()` of the gateway and `pfb_dns_proxy_await_ready()` (`PFB_DNS_PROXY_START_WAIT`, 30 s, holds nothing). When no move can be made (no free pair, the Resolver disabled, a package operation, a second move in the pass) it instead makes one `stop_service()` of the gateway (the rc script's stop, up to 7 s) and starts nothing; the rc script's start then refuses while the marker `/var/run/pfb_dns_proxy_backend_blocked` stands (no lock taken), and every start of the script first makes one `/usr/bin/timeout -s TERM -k 1 2 /usr/bin/sockstat -46lw -p <P>` scan of its upstream port (default reaper mode, a transient helper: at most 2 s plus the 1 s kill grace, run before the start lock is taken) and refuses, writing the marker, for a listener that is not `unbound`; a scan that fails or times out is a failed scan and names nobody (unknown is never foreign). The next tick and update pass search again. At most one move a pass (`$pfb['dns_proxy_backend_move']`: every apply, tick and boot check is its own process), none under a package operation or while the Resolver is disabled; a move the gateway did not follow is not waited on again: the next update restarts a gateway whose applied upstream is not the stored pair.
- DNS proxy start lock (issue #3515): the generated `pfb_dns_proxy.sh` `start` runs itself once more under `/usr/bin/lockf -k -t 10 /var/run/pfb_dns_proxy.lock` (the lock file is kept between starts; the inner run is marked by an environment variable so it does not lock again), so the boot hook's background start and an apply's `start_service()` cannot both pass the "already serving?" check before `daemon(8)` has written a pidfile. `-t 10` is the whole wait: lockf gives up with status 75, the script logs one error and exits 75. `stop` takes no lock, so a start that waits can still be stopped. The lock is held for one run of the script: its stop (up to 7 s), a stored marker's `dns_saved` check when the marker is not the one the script was written for (`timeout -s TERM -k 5 30`, up to 35 s; issue #3556), and the launch. The `daemon` launch also closes the descriptors above stdio, defensively: FreeBSD's lockf(1) closes its lock descriptor before it runs the command, so the proxy does not inherit the lock. A lockf that left it open would let a proxy hold the lock for as long as it runs, and every later start would wait the 10 s and fail.
- DNS proxy boot hook (issue #3515): `pfb_upstream_observer_include.inc`, which pfSense's `services_unbound_configure()` `require_once`s while it restarts Unbound, runs `pfb_dns_proxy.sh start` through core `mwexec_bg()`: detached, never waited on, so `rc.bootup` and the Resolver restart proceed at once; it launches only when neither proxy pidfile names a live process, and the script serializes that start with an apply's (above). The rc script's own start is bounded by its upstream-port scan before the lock (2 s plus a 1 s kill grace, above), the lock wait (10 s), its stop above (up to 7 s), and, for a stored marker the script was not written for, its `dns_saved` check under the lock (up to 35 s, issue #3556), and runs outside the hook's process. The hook backgrounds its own `dns_check` beside that start to confirm it; a later apply confirms only its own start/restart.
- DNS proxy startup check (issues #3538, #3625, #3845): `pfb_dns_proxy_startup_check()` reads the applied-status listener inventory (`FF FF FF FA` on the control socket) and the rc script. The caller supplies readiness: serving readiness after its activation wait, or marker readiness when it started nothing. Its only wait is that one status exchange, with each step bounded by `PFB_DNS_PROXY_CTL_TIMEOUT`; it polls nothing. Only the not-ready branch reads the log's last `pfb_dns_gateway:` line, bounded to bytes after the pre-start `$since` size. The boot hook backgrounds its start's confirmation through `mwexec_bg()`: `/usr/bin/timeout --foreground -s TERM -k 5 360 /usr/local/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dns_check <size>`: the confirmation can move Unbound's backend ports (issue #3848), which restarts Unbound and the gateway, daemons meant to outlive the check, so it runs in `--foreground` mode (the table above: a command that starts a survivor on purpose), not in the reaper mode that would kill them when the check exits. Its 360 s cap is an outer salvage deadline, not a proved whole-path completion bound. A tick that restarts nothing runs diagnostics directly.
- DNS proxy config lock (issue #3515): the Save DNS settings save on DNS > General and `pfb_dns_proxy_resolver()` hold one named pfSense lock (`PFB_DNS_CONFIG_LOCK`) from a fresh read of config.xml through `write_config()`, taken by `pfb_dns_config_lock()` with `try_lock()`: a non-blocking `flock()` polled once a second, giving up after `PFB_DNS_CONFIG_LOCK_WAIT` = 10 s and returning NULL. The save then fails with an input error and the Resolver move or restore is abandoned with a notice (snapshot kept, retried by the next apply, the proxy not stopped); nothing waits beyond 10 s, and the kernel drops the lock with the process. The longest hold is a restore's: the proxy's stop (7 s) plus the fresh read and the write, about 8 s, so a settings save that queues behind it still gets the lock inside its 10 s (`DnsProxyConfigLockTest` pins the wait above the stop's give-up tick plus one second). The DNS > DNSBL and General saves also hold it across Core's dry run (`pfb_core_settings_validate()`, issue #3922): that call is bounded by `PFB_CORE_VALIDATE_TIMEOUT` = 3 s, not the 30 s default of `pfb_core_call()`, and a Core that has not answered by then counts as one that could not judge, so the save goes on (`CoreSettingsValidateTimeoutTest` pins the budget plus one second below the wait). pfSense's own `lock('config')` is not used: `write_config()` takes it itself, and a second handle in the same process would wait on the first.
- DNS proxy boot check budget (issue #3848): the readiness wait (`pfb_dns_proxy_await_ready()`, 30 s, holds nothing) plus the startup check's one bounded control exchange and one bounded native socket-ownership probe. A move of Unbound's backend ports adds the bounded steps of the move bullet above: its config lock wait (10 s), Unbound's regeneration by pfSense (not bounded by pfBlockerNG) and a second 30 s readiness wait. After an rc start that refused (the marker stands), `dns_check` skips the first readiness wait and runs the update pass's check, whose waits are those of the move bullet and, when it starts the gateway, one readiness wait. These are component bounds, not a measured whole-path limit or proof of headroom under the outer 360 s salvage deadline.
- DNS proxy config lock check (issue #3515): after the restore, the package removal (`pfb_dns_proxy_deinstall()`) calls `pfb_dns_config_refresh()` and the wizard's reset `pfb_dns_config_lock()`: one more `try_lock()` (at most `PFB_DNS_CONFIG_LOCK_WAIT` = 10 s). The removal holds it only for a fresh read of config.xml; the reset holds it through its in-memory sweep and `write_config()` (issue #3558) and releases it before it clears the package files and restarts Unbound. A lock that stays taken, or a read that fails, counts as a Resolver that is still moved: the removal stops with pkg's abort status and the reset is refused. Nothing waits beyond that.
- Bounded `unbound-control` IPC (issue #2879): `pfb_unbound_control_cmd()` / `pfb_unbound_control_exec()` in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` wrap every request/response control call (`status`, `flush`, `flush_zone`, `flush_stats`) in default (reaper) mode — the control command is a transient helper under `chroot(8)`, so expiry must reap the tree, and `--foreground` would orphan a blocked `unbound-control` still holding the capture pipe. Budget `PFB_UNBOUND_CONTROL_WAIT` = 30 s, the value the sibling resolver waits use; kill grace `PFB_HOOK_KILL_GRACE`. It is also the **whole-batch** ceiling for `pfb_unbound_py_ccache_flush()`, whose per-command deadline is clipped to the time the batch has left, so a name list cannot multiply the wait. 124 is named in both logs; a non-zero reply is named separately.
- `.agents/policy/waits.md` (bounded waits) and Python "no fixed-time waits to coordinate concurrency" rule — agent/test-side analogue: synchronise on signal, bound every wait, never sleep-poll blindly.
- FreeBSD `bin/timeout/timeout.c` — `PROC_REAP_ACQUIRE`, `rs_children == 0` exit condition, `send_sig()` (`kill(child)` under `--foreground` vs reaper kill by default).
