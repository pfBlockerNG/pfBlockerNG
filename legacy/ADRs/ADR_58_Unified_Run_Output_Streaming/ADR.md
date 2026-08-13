# ADR-58: Stream a run's progress to STDOUT in a command context (generalise the #690 mirror)

- **Status:** **Accepted** (2026-07-06; landed in PR #889) — the live-VM hook/visibility smoke
  (`test_smoke_hooks` incl. the timeout-kill + stream oracles, `test_hook_stream_visibility`,
  `test_lifecycle_hook_visibility`) is **green on CE + Plus**. **Scope corrected 2026-07-06** after the
  smoke rejected two broader designs (see §5). The change that landed is modest: `pfb_logger()`'s #690
  stdout mirror, previously gated on a package lifecycle callback only, is **widened to fire also for an
  interactive terminal** (`pfb_run_streams_to_stdout()` = `hook_lifecycle || pfb_stdout_is_terminal()`),
  and does **not** fire when stdout is redirected to a log file it already writes (the cron tick, the
  detached Run-Now, a nested extras dispatch) or for a web in-process caller. **Hooks are unchanged** —
  they keep the #883 file-sink + live-tail model, because #662 forbids a hook writing to the run's
  captured pipe.
- **Date:** 2026-07-06
- **Branch:** `adr/58-unified-run-output-streaming` (off **`devel`**).
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — **only** `pfb_logger()`'s #690 stdout-mirror gate
    (`pfb_run_streams_to_stdout()` + `pfb_stdout_is_terminal()`). Everything else — the file writes, the
    per-run-log fwrite-mirror, **`pfb_run_hooks()`, `pfb_mirror_hook_output()`** (the #693/#883 hook path)
    — is UNCHANGED from `devel`. `pfblockerng.php` is unchanged (no per-verb override needed — §2.1).
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). **`freopen()` does not exist in this PHP build.**
- **Test suite:** `tests/php/` — `LiveLogStdoutTest` (the run-progress print + its gate, branch-covered),
  `PfbHookOutputMirrorTest` / `HookLifecycleCtxTest` / the tail-target suite (all unchanged, still green).
  `tests/smoke/` — `test_smoke_hooks.py` (the hook timeout/stream/#662 oracles) and
  `test_hook_stream_visibility` / `test_lifecycle_hook_visibility` (ADR-04) are the out-of-CI gate; they
  must stay green, which is why the hook path was left intact.

> **This is a consolidation, not a feature.** What an operator sees is the same or better; the one
> deliberate *addition* is that a CLI/terminal run now streams its progress (it was silent). The
> ambition of the earlier drafts — "everything to STDOUT, hooks inherit it, delete #883" — was **wrong**
> and the live-VM smoke caught it (§5). The design of record keeps hooks exactly as they were.

---

## 1. Context (today, pre-ADR-58)

A run's progress reaches operators three ways:

1. **pfSense Software page** (install/upgrade/uninstall): pfSense runs the op as
   `pkg-static <op> 2>/dev/null | tee -a <log>` and renders `<log>.txt` — it shows what our scripts
   write to **stdout** (a pipe drained to EOF by `tee`).
2. **pfBlockerNG Update page**: a Run-Now dispatches the pass **detached** (survives page-nav) and the
   AJAX viewer tails the **per-run log file**.
3. **A terminal**: a user can run `pfblockerng.php pfb_trigger …` from the CLI.

`pfb_logger()` writes the pass to **files** (the cumulative + categorised logs, and — while a run is
active — the per-run log the viewer tails). It did **not** write stdout, except: issue **#690** added a
mirror of its main-log lines to stdout **while a package lifecycle callback is active**
(`$pfb['hook_lifecycle']` = `'install'`/`'uninstall'`) so the Software page isn't silent during an
install/upgrade. On a normal cron/manual/Run-Now pass, and on a terminal run, the logger was
stdout-silent.

Update **hooks** are a separate, load-bearing mechanism (#662 → #693 → #883): `pfb_run_hooks()` points
each hook's stdout/stderr at the per-run **log file** (never the run's own stdout), and — during a
lifecycle callback — **tails that file to stdout while the hook runs** so the Software page shows the
hook body live. This file indirection is what makes a hook that restarts a daemon safe (§4).

---

## 2. Decision

**Generalise the #690 stdout mirror from "lifecycle callback only" to "any command context"; leave the
hook path alone.**

### 2.1 Widen #690's stdout mirror from "lifecycle only" to "lifecycle OR a terminal"

`pfb_logger()` is **unchanged from `devel` except one condition.** Issue #690 mirrored the main-log
lines (cases 1/2) to stdout only *while a package lifecycle callback was active*
(`!empty($pfb['hook_lifecycle'])`). That gate becomes:

```php
function pfb_run_streams_to_stdout(): bool {
    global $pfb;
    return $pfb['run_stdout_override'] ?? (!empty($pfb['hook_lifecycle']) || pfb_stdout_is_terminal());
}
// pfb_stdout_is_terminal(): stream_isatty(php://stdout), cached.
```

The rule is **"mirror to stdout only when stdout is a real watched surface":**

- **A lifecycle callback** — stdout is the pkg Software page's pipe to `tee` (#690, unchanged).
- **An interactive terminal** — `pfb_stdout_is_terminal()` (a hand-run `pfblockerng.php pfb_trigger`).
  This is the one behaviour **added**: a terminal pass now streams (was silent).

and **NOT** otherwise, which falls out for free — no per-verb exclusion list needed:

- The **cron tick** (`>> log`), the **detached Run-Now** (`>> runlog`), and every **nested extras
  dispatch** (`dc`/`bls`/… whose parent redirects/captures their stdout) have stdout = a **log file the
  logger already writes**, and it is not a tty, and no lifecycle → **no print → no double.**
- A **web in-process caller** (the General-settings save that resyncs then `header('Location')` + `exit`)
  has stdout = the HTTP response — not a tty, not a lifecycle → **no print**, so the redirect is intact.

The **per-run-log fwrite-mirror is KEPT** exactly as `devel` has it: while a run is active `pfb_logger()`
appends each main-log line to the run-log the Update viewer tails, **regardless of where stdout points**.
That is load-bearing — the detached Run-Now redirects its stdout to `>> runlog` but the viewer's header
detection relies on the *mirror* putting the `[ pfB Hook ]` line in the runlog (the smoke
`test_post_hook_output_streams_into_runlog_during_run` asserts exactly this). Removing it broke that test;
keeping it means the widened print never collides with it (the print only fires for the tty/lifecycle
surfaces, never for the `>> runlog`/`>> log` redirected ones).

### 2.2 Hooks are unchanged — the file sink stays

`pfb_run_hooks()`, `pfb_mirror_hook_output()`, and the #693/#883 path are **identical to `devel`**. A hook
writes to the per-run **log file** and (during a lifecycle callback) `pfb_run_hooks()` tails that file to
stdout while the hook runs. This is mandatory, not a preference (§4/§5).

### 2.3 What stays / out of scope

Cumulative + categorised logs, log rotation, the detached Run-Now dispatch, the feed-script `$elog`
redirects, `config.xml`/manifests/Python — all untouched. `hook_lifecycle` keeps **all** its roles
(ADR-12 env-context, #883 lifecycle-tail, and the #690 stdout mirror — it is still one arm of the gate);
the #690 print now *also* fires for an interactive terminal (`hook_lifecycle || pfb_stdout_is_terminal()`).

---

## 3. Removal inventory

Small, by design. The only thing removed is **#690's `hook_lifecycle` gate on the logger print** — the
`if (($logtype==1||2) && !empty($pfb['hook_lifecycle'])) print` block — replaced by the
`pfb_run_streams_to_stdout()`-gated print (§2.1). Everything else in the earlier drafts' removal list
(#693, #883, the per-hook file redirect) is **retained** — the smoke proved those deletions were wrong.

Net diff is tiny and roughly neutral: one changed condition on the #690 print, plus the two small gate
helpers (`pfb_run_streams_to_stdout()` + `pfb_stdout_is_terminal()`). No other code changes.

---

## 4. Why hooks CANNOT inherit the run's stdout (the load-bearing constraint)

A pipe reaches EOF only when **every** copy of the write-end is closed; a **regular file** fd has no such
semantics. The run's stdout, in the two captured contexts, is a **pipe drained to EOF**:
`pkg-static | tee` (Software page) and the SSH capture (smoke/`vm.ssh`). So if a hook writes to the run's
stdout and **anything it spawns outlives it holding that pipe**, the reader blocks until that thing dies:

- A **restart hook → persistent daemon** (HAProxy) holds it **forever** → the Software page freezes /
  the reload never returns.
- A **timeout-killed hook** — killed *because* it was mid-work, i.e. with a live subprocess — leaves that
  subprocess **orphaned**, holding the pipe for its lifetime. This is not a "bad hook"; it is inherent to
  enforcing a timeout, and it breaks the ADR-12 promise *"a timeout is logged and the pass CONTINUES."*

`timeout --foreground` (reaper off, so `timeout` doesn't wait on/kill the daemon) and `proc_close()`
(waitpid on the **direct** child) both return promptly — the hang is in the **outer reader**, not our PHP.
The fix is the same as the shell's (`cmd >file` not `x=$(cmd)`): give the hook a **file** sink so a
survivor holds an inert file fd, and have **PHP** tail that file to stdout (the exit code off
`proc_close()`, the bytes off a file read that never waits for EOF). That is exactly #883, and the run's
own stdout is then held only by PHP, which releases it on exit → the reader gets EOF. **This is why the
hook path is unchanged.**

---

## 5. Alternatives considered (both implemented, both rejected by the live-VM smoke)

1. **Draft A — run-entry `freopen(STDOUT → run-log file)` + a per-run bridge-tail daemon.** Rejected:
   `freopen()` does not exist in this PHP, and the bridge-tail is a background OS process copying
   file→pipe — the very daemon/detach machinery the effort meant to remove.
2. **Draft B — hooks inherit the run's stdout (`proc_open 1 => php://stdout`), delete #883.** **Rejected —
   the live-VM smoke HUNG.** `test_hooks_timeout_killed_update_continues` (a `sleep 30` hook killed at its
   2 s timeout) timed out on both CE and Plus: the orphaned `sleep` held the SSH-capture pipe, so
   `vm.ssh` never saw EOF (§4). An adversarial review independently found the same broadening polluted the
   nested `bls`/`dc`/`dcc`/`bl` dispatches (double-logging + a #711-prune corruption risk). Both signals
   agree: a run's output cannot go straight onto a captured pipe when hooks (or nested dispatches) are
   involved. The design of record (this ADR) keeps #883 and gates the logger print away from the nested
   and web callers.
3. **Keep #690 as-is (lifecycle-only).** Rejected — it left a terminal run silent and re-derived the
   "am I watched?" question from `hook_lifecycle`; the SAPI/override gate is cleaner and adds the
   terminal case.

---

## 6. Consequences

**Positive**

- A **CLI/terminal run now streams** its progress (was silent). The Software page keeps #690's live view
  via the same mechanism, now without the `hook_lifecycle` special-case.
- No new double-writes: the tick, the detached Run-Now, the nested extras dispatches, and the web
  settings-save all have a non-tty, non-lifecycle stdout, so the widened gate never prints there.

**Negative / cost**

- Small, not the sweeping consolidation first envisioned — the hook machinery (#693/#883) stays. That is
  the correct outcome: §4/§5.
- STDOUT must stay unbuffered for live streaming (`output_buffering=Off`, already true).
- **Behaviour proof is out-of-CI.** The hook oracles (`test_smoke_hooks`, `test_hook_stream_visibility`,
  `test_lifecycle_hook_visibility`) run only on a real box; because the hook path is unchanged they must
  stay green, and the timeout/stream tests that Draft B failed must pass again.

---

## 7. Implementation

One commit's worth of change (behaviour-preserving except the CLI-stream addition):

1. Add `pfb_run_streams_to_stdout()` (= override ?? `hook_lifecycle || pfb_stdout_is_terminal()`) and
   `pfb_stdout_is_terminal()` (`stream_isatty(php://stdout)`, cached). Change ONLY the #690 print gate in
   `pfb_logger()` from `!empty($pfb['hook_lifecycle'])` to `pfb_run_streams_to_stdout()`. All file writes
   AND the per-run-log fwrite-mirror are unchanged from `devel`.
2. Leave `pfb_run_hooks()` / `pfb_mirror_hook_output()` / the #883 path and `pfblockerng.php` untouched
   (Draft B's inherit-stdout + the per-verb override are both reverted — the tty gate makes the override
   unnecessary, §2.1).
3. Docs: the `docs/misc/external-process-waits.md` visibility section notes the #690→ADR-58 widening
   (lifecycle → lifecycle-or-tty) and the file-sink-for-hooks rationale.

## 8. Test plan

- **`LiveLogStdoutTest`** branch-covers the gate: a lifecycle pass mirrors to stdout; a plain
  non-lifecycle, non-tty pass is silent (the anti-double property); the override forces the mirror on
  WITHOUT a lifecycle (red on `devel`, which only printed under `hook_lifecycle` — proving the widening);
  the per-run-log fwrite-mirror still populates the runlog; case 2's error log; case 3 never prints.
- **Unchanged oracles stay green:** `PfbHookOutputMirrorTest`, `HookLifecycleCtxTest`, the tail-target
  suite.
- **Smoke (out-of-CI, the real gate):** `test_smoke_hooks.py` — the timeout-kill-continues and
  post-hook-streams-to-runlog tests (which Draft B hung) must PASS; `test_hook_stream_visibility` /
  `test_lifecycle_hook_visibility` must stay green. A regression test that a nested `bls`/`dc` dispatch
  does not double-log is the smoke-level guard for §2.1's extras narrowing.

## 9. Reject / revisit criteria

- If any surface shows **less** than #690 gave it, stop and reconsider the gate.
- If a nested verb's own direct output (not `pfb_logger`) is wrongly suppressed by the override, exclude
  that verb.
- The hook path is **not** to be "simplified" onto the run's stdout again — §4/§5 are the record of why.
