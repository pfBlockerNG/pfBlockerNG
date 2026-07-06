# ADR-58: Unify run output on one stdout→run-log→tail path for every surface

- **Status:** **Proposed (Draft)** (2026-07-06) — authored on `adr/58-unified-run-output-streaming`
  off `devel`. Not yet phased. Builds on the streaming groundwork already landed by PR #883
  (`proc_open` live hook streaming) and its live-VM contract test.
- **Date:** 2026-07-06
- **Branch:** `adr/58-unified-run-output-streaming` (off **`devel`**; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming").
- **Component(s):** the run-output/visibility layer — its **write** side, its **dispatch** side, and
  its **read** (live-tail) side:
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — `pfb_logger()` (`:3078`–`:3165`, incl. the
    #690 stdout-mirror at `:3151`–`:3164`), `pfb_mirror_hook_output()` (`:4100`–`:4115`, #693),
    `pfb_run_hooks()` (`:4130`–`:4317`, incl. the PR #883 `proc_open` streaming block), the 18
    `$elog = ">> {$pfb['log']} 2>&1"` `exec()` redirect sites, the cron-tick command build
    (`:18922`), the run-log helpers (`pfb_run_log_target()` `:14088`, `pfb_runlog_begin()`
    `:14075`, `pfb_log_tail_chunk()` `:13975`, `pfb_log_tail_payload()` `:14024`).
  - `src/usr/local/www/pfblockerng/pfblockerng_update.php` — the `?ajax=tail` endpoint (`:44`–`:57`),
    the Run-Now / force-check dispatch (`pfb_runnow()` `:80`, `pfb_runnow_forcecheck()` `:134`).
  - `src/usr/local/www/pfblockerng/pfblockerng_ip.php` — the MaxMind `ugc` dispatch (`:184`).
  - `src/usr/local/pkg/pfblockerng/pfblockerng.sh` — its own `tee -a "${errorlog}"` / `>> "${…}"`
    progress writes (17 `tee` sites + the extras/geoip appends).
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the sink/dispatch/tail; POSIX `sh` for the
  `pfblockerng.sh` progress writes. No Python (the DNSBL/IP **event** logs and syslog export —
  ADR-38 — are out of scope; see §2.4).
- **Test suite:** `tests/php/` (PHPUnit — the pure tail/target helpers already pinned by
  `LiveLogTailChunkTest`, `LiveLogTailPayloadTest`, `LiveRunLogTargetTest`, `PfbUpdateAutotailTest`,
  `PfbHookOutputMirrorTest`), `tests/smoke/` (live-VM ADR-04 — `test_hook_stream_visibility` and
  `test_lifecycle_hook_visibility` are the streaming/visibility oracles this ADR must keep green),
  `tests/smoke/ui/` (ADR-14 Tier A/B — the Update page live viewer).

> **This ADR is a consolidation, not a new feature.** It removes accumulated special-casing without
> changing what an operator sees. The visible behaviour — the Update page live viewer, and the pkg
> Software page showing install/upgrade/uninstall progress — must be **identical or strictly better**
> after each phase. Every phase is behaviour-preserving and pinned by the existing oracles above; the
> net diff is **negative** (see the §3 removal inventory).

---

## 1. Context (today)

pfBlockerNG's run output reaches two operator surfaces:

1. **The pfBlockerNG Update page** — a Run-Now/Force button dispatches the pass detached and the page
   polls `?ajax=tail` for a live view of the per-run log.
2. **The pfSense Software page** — the stock package manager (`pkg_mgr_install.php` →
   `pfSense-upgrade`) drives install/upgrade/uninstall and shows whatever the package operation
   writes to **stdout** (`pfSense-upgrade` runs `pkg-static <op> 2>/dev/null | tee -a <log>` and the
   page renders `<log>.txt`).

These two surfaces have **different capture mechanisms** (a file the page tails vs. the process's
stdout), and over several issues the package grew **one bespoke bridge per gap**. The result is four
overlapping output mechanisms that all exist to answer the same question — "show the operator what the
run is doing" — plus manual per-call-site redirects that bypass all of them.

### 1.1 The four overlapping mechanisms

**(a) `pfb_logger()` writes to files, and *sometimes* also to stdout (#690).**
`pfb_logger($log, $logtype)` (`pfblockerng.inc:3078`) switches on `$logtype`: cases 1/2 write the
cumulative `$pfb['log']` (and mirror into the per-run `$pfb['runlog']` while `$pfb['runlog_active']`
is set); case 2 also writes `$pfb['errlog']`; cases 3/4 write `$pfb['extraslog']`; case 6 writes
`$pfb['errlog']`. On top of that, issue #690 bolted on a **stdout mirror** so the Software page isn't
silent during a lifecycle callback (`pfblockerng.inc:3151`):

```php
if (($logtype == 1 || $logtype == 2) && !empty($pfb['hook_lifecycle'])) {
    print "{$log}";
}
```

So the *same* line can be written to a file *and* printed to stdout, gated on a process-scoped
`$pfb['hook_lifecycle']` flag (set to `'install'` at `pfblockerng_install.inc:38`, `'uninstall'` in
the pre-deinstall at `pfblockerng.inc:19087`; never explicitly unset — a normal pass just never sets
it).

**(b) An update hook's own output needs a *third* path (#693 → #883).** A hook's stdout can't be a
pipe back to PHP — a daemon it restarts (an HAProxy reload) would inherit the pipe, never close it,
and hang the read at EOF (#662; `docs/misc/external-process-waits.md`). So the hook body is redirected
to the run-log **file**. Issue #693 then added `pfb_mirror_hook_output()` (`pfblockerng.inc:4100`) to
read the appended bytes back and print them after the hook returned; PR #883 replaced that post-hoc
block with **live streaming** — `pfb_run_hooks()` (`pfblockerng.inc:4130`) now runs the hook under
`proc_open()` (stdout/stderr → the run-log file via the descriptor spec), tails the file to stdout
with `pfb_log_tail_chunk()` while it runs, and reads the exit code off `proc_get_status()`.
`pfb_mirror_hook_output()` survives only as the `proc_open`-failure fallback.

**(c) The Run-Now dispatch redirects to the run-log and tails it.** `pfb_runnow()`
(`pfblockerng_update.php:80`) and `pfb_runnow_forcecheck()` (`:134`) dispatch the pass detached and
redirect its output to the file:

```php
mwexec_bg("/usr/sbin/daemon -p " . escapeshellarg($pidfile) .
    " /usr/local/bin/php …/pfblockerng.php pfb_trigger scope=… force=… trigger=… >> {$pfb['runlog']} 2>&1");
```

with `$pidfile = /var/run/pfb_runnow.pid`. The `?ajax=tail` endpoint (`:44`) then reads that file via
`pfb_log_tail_payload('update', …)` and decides "done" purely from the pidfile:
`'done' => !isvalidpid('/var/run/pfb_runnow.pid')`.

**(d) Many call sites redirect their own output to a file directly, bypassing (a)–(c).** A literal
`$elog = ">> {$pfb['log']} 2>&1"` is appended to **18** `exec()` invocations of `pfblockerng.sh`
(built at `pfblockerng.inc:9734` and `:14929`; used at `:9838`, `:10226`, `:10350`, `:10439`,
`:15325`, `:17438`, `:17443`, `:17747`, `:17766`, `:17784`, `:18109`, `:18116`, `:18175`, `:18179`,
`:18306`, `:18313`, `:18315`, `:18987`). The scheduled cron tick is installed with its own redirect
(`… tick >> {$pfb['log']} 2>&1`, `:18922`). `pfblockerng_ip.php:184` dispatches the MaxMind `ugc`
job with `>> {$pfb['extraslog']} 2>&1`. And `pfblockerng.sh` writes its own progress with 17
`echo … | tee -a "${errorlog}"` plus direct `>> "${extraslog}"` / `>> "${geoiplog}"` appends.

### 1.2 Why this is a problem

- **Every new surface adds a bridge.** #690 mirrors `pfb_logger`; #693/#883 mirror hooks; each is a
  separate mechanism reading/writing the same conceptual stream. A future surface would add a fifth.
- **The `hook_lifecycle` flag is load-bearing in two places** (the `pfb_logger` mirror and the
  `pfb_run_hooks` branch) purely to answer "am I being watched via stdout right now?" — a question a
  single sink would never need to ask.
- **Two writers, one truth.** A line can land in the file via `fwrite` *and* on stdout via `print`;
  the 18 `$elog` sites and the `pfblockerng.sh` tees write progress the logger never sees, so the
  run-log the Update page tails and the stdout the Software page shows are **assembled differently**
  and can diverge.
- **The daemon-safety rule is re-derived per site.** "Redirect to a file, never a pipe" is the load
  bearing invariant (#662), but it's currently enforced independently in the hook path, the dispatch,
  and each manual redirect — easy to get wrong at the next call site.

The through-line: **there is one logical stream** (what this run is doing) and **four physical
representations** of it, bridged pairwise.

---

## 2. Decision

Collapse the four mechanisms into **one path**: a run writes everything to its own
**stdout/stderr**, that fd is redirected **once** to the per-run log **file**, and **one** tail
renders that file to whichever surface is watching. The two operator surfaces converge because they
read the *same bytes*, not because we bridge one into the other.

### 2.1 One sink — the process redirects its own stdout/stderr to the run-log file, once

At the entry of a pfBlockerNG run (the `pfblockerng.php` verb dispatch that begins a pass), the PHP
process points its own `STDOUT`/`STDERR` at `$pfb['runlog']` (via `freopen()` on the CLI SAPI, or by
the dispatcher's existing `>> {runlog} 2>&1` where it already applies). From that point:

- **`pfb_logger()`'s run-progress cases just print.** The main-log cases emit to stdout; being a
  regular **file** fd, the write is daemon-safe and lands in the run-log with no `fwrite`-to-file and
  no #690 stdout-mirror. (The cumulative `$pfb['log']` and the categorised `errlog`/`extraslog` files
  are handled by §2.3, not deleted.)
- **Hooks inherit the redirected stdout.** A hook is a child of the run; it inherits an fd that
  already points at the run-log file. It writes there directly — **no per-hook `proc_open`, no
  `>> $logf` in the command, no `pfb_mirror_hook_output`**. A daemon the hook spawns inherits the
  same **file** fd (harmless), so #662 is satisfied structurally, once, for every descendant.
- **`pfblockerng.sh` inherits it too.** Its progress `echo`s go to the inherited stdout → run-log;
  the 18 `$elog` redirects and the shell's own `tee -a` for *progress* become unnecessary.

### 2.2 One bridge for the pkg-GUI surface — a single tail, not per-writer mirrors

The Update page already tails the run-log file directly (`?ajax=tail`), so it needs nothing new. The
pkg Software page is the case that used to need per-writer mirrors, because there the run's stdout is
**inherited from `pkg-static`'s pipe to `tee`** — writing to it directly is the #662 hazard.

Resolve it **once**: when a run detects it is executing under a package lifecycle callback, it
`freopen`s its own stdout to the run-log **file** (§2.1, making all descendants daemon-safe) and
starts **one** bridge-tail — a single controlled reader that copies new run-log bytes to the
*original* inherited stdout (the `pkg-static | tee` pipe) until the run ends. The bridge-tail is the
**only** process holding the pipe; hooks and their daemons never touch it. This is the #883 tail loop
**promoted from per-hook to per-run** — so the Software page shows the entire pass live (feed
progress, the up-to-30 s unbound stop/start, and hook output) with one mechanism, and the
`hook_lifecycle`-gated `pfb_logger` mirror disappears.

### 2.3 What stays: the cumulative log, the categorised logs, and detachment

Unification is of the **run-progress stream**, not of every file:

- **The cumulative `$pfb['log']`** (history across runs) is preserved. The per-run log is the live
  view; the cumulative log is derived from it (the run-log content is appended to the cumulative log
  at run end, or the cumulative log tees off the same sink) — the existing `pfb_log_mgmt()` rotation
  contract is unchanged.
- **The categorised logs stay categorised.** `errlog` (errors), `extraslog` (extras/DCC), the DNSBL/IP
  **event** CSVs, and the ADR-38 syslog export are **not** the run-progress stream and are out of
  scope (§2.4). A `pfb_logger` error case still writes `errlog` *and* now also reaches stdout→run-log
  so the operator sees it live.
- **Detachment is kept exactly where the work must outlive its trigger.** The async Run-Now/force-check
  dispatch stays `mwexec_bg("daemon -p …")` — a web request returns immediately while the pass
  continues, so `proc_open` (whose child dies with the request) cannot replace it. What simplifies is
  the *content*: the detached process applies §2.1 (redirect-to-run-log) itself, so the dispatch is
  just "launch detached, sink to the run-log," with no downstream mirror logic. `pfb_runnow.pid` +
  `isvalidpid` (the tail's done-signal) are unchanged.

### 2.4 Explicitly out of scope

- The **event logs** and **syslog export** (ADR-38) — DNSBL/IP block/permit/match CSVs, the syslog
  emitter. Those are structured security events, not run progress.
- **`config.xml`**, the manifest, and any wire/serialized value — untouched (no schema change).
- The **Python** side (`pfb_unbound.py`) — it does not participate in the run-progress stream.
- **Log rotation / retention** semantics (`pfb_log_mgmt()`) — preserved as-is.

---

## 3. Removal inventory (first-class — this ADR is net-negative)

The point of the change is deletion. Each item below is removed or reduced once its function is
subsumed by the single sink (§2.1) + single tail (§2.2). Verify each `file:line` at implementation
time (they drift); the count, not the exact line, is the commitment.

| # | Removed / reduced | Where (on `devel` at authoring) | Subsumed by |
| - | ----------------- | ------------------------------- | ----------- |
| 1 | **#690 `pfb_logger` stdout-mirror** — the `($logtype==1\|\|2) && hook_lifecycle` `print` block | `pfblockerng.inc:3151`–`:3164` | §2.1 (logger prints to the redirected stdout) |
| 2 | **#693 `pfb_mirror_hook_output()`** — the whole function + its fallback call site | `pfblockerng.inc:4100`–`:4115`, call at `:4269` | §2.1 (hooks inherit the sink) |
| 3 | **The `proc_open` per-hook streaming block** in `pfb_run_hooks()` (the entire `hook_lifecycle` if/else split, the descriptor spec, the tail loop, the wedge guard) | `pfblockerng.inc:4241`–`:4307` | §2.1 + §2.2 (per-run bridge-tail, not per-hook) |
| 4 | **The `>> $logf 2>&1` in the hook `$cmd`** and the split `$cmd`/`$proccmd` build | `pfblockerng.inc:4188`–`:4196` | §2.1 (inherited fd) |
| 5 | **The 18 `$elog = ">> {$pfb['log']} 2>&1"` `exec()` redirects** (progress capture only — not the `2>&1`-for-return sites at `:4837`/`:12731`) | `pfblockerng.inc:9734`, `:14929` + 18 uses | §2.1 (`pfblockerng.sh` inherits the sink) |
| 6 | **`pfblockerng.sh` progress `tee -a "${errorlog}"` / `>> "${…}"` for run progress** (the *error*/*extras* categorised writes are re-pointed, not deleted — see §2.3) | `pfblockerng.sh` — 17 `tee` sites + appends | §2.1 (script stdout → sink; errlog kept via a single tee, not per-line) |
| 7 | **The `hook_lifecycle`-as-"am-I-watched" role** — the flag stops gating output paths (it keeps its ADR-12 `PFB_POST_INSTALL`/`PFB_PRE_UNINSTALL` env role, which is unrelated) | `pfblockerng.inc:3152`, `:4241` | §2.1/§2.2 (a run always sinks to the run-log; watching is the tail's job) |

Rough order-of-magnitude: items 1–4 remove ~90 lines from `pfblockerng.inc` (the streaming block that
PR #883 *added* is the largest single deletion here — expected and intended, per the ADR-vs-#883
trade-off recorded when #883 landed); items 5–6 remove/simplify ~35 redirect fragments across the
`.inc` and `.sh`. Net change is a **reduction**; any new code (the per-run bridge-tail, the entry
`freopen`) is small and centralised.

---

## 4. The load-bearing invariant (why a file, and why one bridge)

The whole design rests on one FreeBSD fact (`docs/misc/external-process-waits.md`): a pipe read to EOF
blocks until **every** inheritor of the write-end closes it, so a hook that leaves a daemon holding an
inherited pipe hangs the reader forever (#662). A **regular file** fd has no such semantics — a write
just lands, and a lingering daemon holding a file fd is inert.

Therefore the sink is **always a file**, and the *only* process that may hold the surface's live pipe
(the `pkg-static | tee` write-end, or a socket) is **our single bridge-tail** — a controlled reader
that we start and stop, never a hook and never a hook's child. This is exactly why §2.2 promotes the
tail to per-run: one owner of the pipe, chosen by us, for the whole pass. Any implementation that lets
a hook write to the inherited pipe directly (rather than the file) reintroduces #662 and is rejected
(§9).

---

## 5. Alternatives considered

1. **Keep the four mechanisms; just document them.** Rejected — the `hook_lifecycle`-as-watch flag and
   the two-writers-one-truth divergence are latent bugs, not just clutter. The next surface adds a
   fifth bridge.
2. **Give hooks the inherited pipe directly (no file, no bridge).** Rejected — reintroduces the #662
   daemon-hang for the exact case hooks exist for (service reloads). §4.
3. **`proc_open` everywhere, including Run-Now.** Rejected — the async Run-Now must outlive its web
   request; `proc_open`'s child dies with the request. Detachment is irreducible there (§2.3).
4. **A structured logging library / new log framework.** Rejected — YAGNI and out of proportion. The
   package needs *one sink and one tail*, not a logging abstraction; the categorised logs already
   exist and are out of scope (§2.4).
5. **Ship #883's per-hook streaming as the end state.** Rejected as the *final* shape — it's a correct
   stepping stone (and the reason the daemon-safety is already proven live), but it special-cases hooks
   when the same sink serves everything. This ADR generalises it and deletes the special case.

---

## 6. Consequences

**Positive**

- One mechanism, one invariant, one place to reason about run visibility. A new surface is "point the
  bridge-tail at it," not "add a mirror."
- The two operator surfaces show **identical** bytes by construction (same file), ending the
  two-writers divergence.
- `hook_lifecycle` sheds its output-gating role; it keeps only its ADR-12 env-context meaning.
- Net-negative diff (§3); the daemon-safety is centralised, not re-derived per call site.

**Negative / cost**

- Touches a hot, safety-critical path (`pfb_run_hooks`, the logger). Every phase must be
  behaviour-preserving and pinned by the live-VM oracles before the next.
- The entry `freopen` + per-run bridge-tail is new central machinery; a bug there affects *all* run
  output, not one hook. Mitigated by the existing `test_hook_stream_visibility` /
  `test_lifecycle_hook_visibility` contracts and a bridge-tail unit/live test.
- CLI-SAPI stdout must stay unbuffered for live streaming (already true: `output_buffering=Off`,
  verified live during #883). The ADR pins this with a test rather than an assumption.

---

## 7. Implementation phases (each behaviour-preserving, each its own commit)

1. **Entry sink.** Add the run-entry `freopen(STDOUT/STDERR → runlog)` (CLI) + the per-run bridge-tail
   for the lifecycle-callback case (promote #883's loop from `pfb_run_hooks` to run scope). Keep the
   old mechanisms live in parallel; assert the surfaces are unchanged. Pin with the two smoke oracles.
2. **Hooks inherit.** Delete the `proc_open` per-hook block + `pfb_mirror_hook_output` + the hook
   `$cmd` file-redirect (§3 items 2–4); hooks now inherit the entry sink. `test_hook_stream_visibility`
   must stay green (its contract is exactly what phase 1 preserved).
3. **Logger prints.** Remove the #690 mirror (item 1); route `pfb_logger` run-progress cases through
   stdout; keep `errlog`/`extraslog`/cumulative-log writes (§2.3). Pin the Update page live view.
4. **Redirect cleanup.** Remove the 18 `$elog` redirects (item 5) and re-point `pfblockerng.sh`
   progress writes (item 6). The cron tick and `ip.php` `ugc` dispatch inherit or keep their own sink
   as appropriate.
5. **Flag demotion + docs.** Strip `hook_lifecycle`'s output-gating role (item 7); rewrite the
   `docs/misc/external-process-waits.md` "visibility" section to the single-sink model.

Each phase gates on the same live-VM fan-out before the next (CLAUDE.md "Plan with a higher model";
`/adr-phase`).

## 8. Test plan

- **Preserve, do not rewrite, the contracts.** `test_hook_stream_visibility` (hook output streams live
  to the pkg surface *while the hook runs*) and `test_lifecycle_hook_visibility` (hooks fire with the
  right env; output survives `pfSense-upgrade`'s stderr-drop+tee) are the oracles. They were authored
  against #883 precisely so this ADR's rewrite is *proven* to preserve behaviour — they must stay green
  across every phase (behaviour-preserving exception to the red→green mandate, per CLAUDE.md "Test
  coverage").
- **New coverage:** a unit/live test that the entry sink + bridge-tail streams **non-hook** run
  progress (a `pfb_logger` line, a `pfblockerng.sh` echo) to *both* surfaces live — the property that
  used to require the #690 mirror. Assert both surfaces show the *same* bytes (the anti-divergence
  property). Pin CLI-SAPI unbuffered-stdout with a focused check.
- The PHPUnit tail/target suite (`LiveLogTailChunkTest`, `LiveLogTailPayloadTest`,
  `LiveRunLogTargetTest`, `PfbUpdateAutotailTest`) stays green; `PfbHookOutputMirrorTest` is deleted
  with its function (item 2).

## 9. Reject / revisit criteria

- If any phase cannot keep both smoke oracles green without regressing what a surface shows, **stop** —
  the single-sink model is wrong for that case; document it and keep the bridge for it.
- If a hook is found that legitimately needs its stdout to be a live pipe (not a file) — none is known
  — the file-sink invariant (§4) must be revisited before proceeding; do not special-case it silently.
- If the entry `freopen` proves unsafe on any supported pfSense CLI/web entrypoint (e.g. a caller that
  needs PHP's stdout for its own protocol), scope the sink to the run dispatch only and keep the
  categorised writers as they are.
