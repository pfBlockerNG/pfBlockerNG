# ADR-61: A sync-status ledger — unify widget error/out-of-sync reporting for IP and DNSBL

- **Status:** **Implemented (pending live-VM smoke)** (2026-07-08). All 7 phases landed;
  PHPUnit + pytest green, PHPCS/PHPStan clean. Phases 3-6 carried DONE-WITH-DEVIATION
  verdicts — each a disclosed, reasoned engineering choice, not a defect (Phase 6's first
  attempt separately failed its own gate on 2 real defects, both fixed in a corrective
  round; see `RESULTS/06_Results.txt`). One known, tracked gap remains open (not a blocker
  to this status, but not silently accepted as done either): the DNSBL tick-retry is a
  sentinel-reflip only, not the full restart path, so a genuinely stuck DNSBL condition
  does not always self-heal via tick alone (issue #998's DNSBL feed-download gap closed —
  `pfb_dnsbl_download_ledger_update()` now mirrors the IP call site). See
  `docs/misc/architecture-notes.md` "Sync-status ledger
  (ADR-61)" for the as-built system and §7 below for the live-VM acceptance checklist that
  flips this to **Accepted**.
- **Date:** 2026-07-08
- **Branch:** `adr/61-sync-status-ledger` (off `devel`; `{slug}` = sanitised ADR-title slug per
  CLAUDE.md "Branch naming") / **Component(s):** `pfblockerng.inc` (download/apply failure
  sites, `pfblockerng_tick()` reconciliation), `pfblockerng_extra.inc` (the ledger library,
  mirroring `pfb_due_ledger_*`), `pfblockerng.sh` (dedup-sanity signal), `pfb_unbound.py` (a new
  Python-owned structured status file for DNSBL parse failures), `src/usr/local/www/widgets/`
  (icon + reporting-list rewrite), `tests/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the ledger + widget; Python 3.11+, stdlib
  only (chrooted in Unbound's loader — `json` is stdlib, no new dependency) for the DNSBL-side
  status file.
- **Test suite:** `tests/php/` (PHPUnit — ledger library, writer/clearer pairs, tick
  reconciliation, widget render logic), `tests/` (pytest — the Python-side status-file
  read/write helpers), `tests/smoke/` (ADR-04 live VM) + `tests/smoke/ui/` (ADR-14 Tier A).

---

## 1. Context — today

### 1.1 The two status icons and what actually flips them

The dashboard widget (`src/usr/local/www/widgets/widgets/pfblockerng.widget.php`) shows one
rollup status icon per facility — `PFBSTATUS` (IP row, `:597-611`) and `DNSBLSTATUS` (DNSBL row,
`:614-648`). There is no per-alias/per-feed icon; the `$faicon` array at `:857-860` is unrelated
decorative column icons (Deny/Pass/Match/Suppression counters), confirmed by reading the render
loop at `:882-919`.

**IP row (`:597-611`):** disabled → red. Enabled → green, **unless** `enable_dup`
(deDuplication) is on AND the last `Sanity check` line in `pfblockerng.log` lacks `PASSED` →
yellow. That line is written by `pfblockerng.sh:1547-1552` (`Database Sanity check [ PASSED /
FAILED ]`, comparing the masterfile IP count against the deny-folder count). **This is the
only thing that can turn the IP row yellow today**, and it is gated entirely behind an optional,
default-off feature — a box with dedup off (the common case) can never show IP yellow, no matter
what actually fails.

**DNSBL row (`:614-648`):** not fully live (disabled, Unbound down, or `unbound.conf` doesn't
reference `pfb_unbound.py`) → red. Live → green, unless one of:

- the last `DNSBL update` line in `pfblockerng.log` contains `OUT OF SYNC` (`:625-628`) —
  **dead code**: `grep -rn "OUT OF SYNC" src/` returns nothing; no writer of that substring
  exists anywhere in the current tree.
- `py_error.log` filesize > 0 (`:635-638`) — a **monotonic** check: one exception ever written
  to that file, at any point in the file's lifetime, keeps the row yellow until an operator
  clears/rotates the log by hand. It never reflects "is this still a problem right now."

**The reporting list** (`pfBlockerNG_get_failed()`, `:446-513`) is a *separate* mechanism: it
greps `error.log` for lines containing `'FAIL'` on today's date (ISO `Y-m-d`, matching
`pfb_logger()`'s timestamp format — see the lockstep comment at `pfblockerng.inc:3094-3096`),
reverses them, and for any `pfB_*`/`DNSBL_*`-prefixed entry builds a deep link to that alias's
editor page. **This already surfaces DNSBL conf/build failures** (see 1.2) alongside download
failures — entries the icon logic never looks at.

### 1.2 Failure classes and where they're logged today (verified `file:line`)

`pfb_logger($log, $logtype)` (`pfblockerng.inc:3089-3131`): `logtype=1` → `pfblockerng.log` only;
`logtype=2` → `pfblockerng.log` **and** `error.log`; `logtype=3` → `extras.log`.

| Class | Facility | Write site | Level | Lands in `error.log`? |
| --- | --- | --- | --- | --- |
| Feed download fail | IP + DNSBL | `pfb_download_failure()` (`:10494`, log at `:10519-10520`), called from `:15973-15977` and `:17690-17694` | 2 | yes |
| DNSBL conf/build fail (`pfb_stop_start_unbound()` returns non-zero) | DNSBL | `:7936-7952` | 2 | yes |
| DNSBL swap-not-confirmed → restart fallback | DNSBL | `:7886-7896` | 2 | yes, but **not itself terminal** — see 1.3 |
| IP `pfctl` apply fail | IP | `pfb_pfctl_table_op()` (`:4733-4747`) | 2 (fixed by issue #980 / PR #987, was 1) | yes — but the widget's case-sensitive `grep 'FAIL'` still misses it: `pfb_pfctl_error_message()` emits lowercase `failed` (issue #990) |
| DNSBL Python parse/load exception | DNSBL | `pfb_unbound.py`, ~20 `sys.stderr.write(...)` sites (e.g. `:1318`, `:1418`, `:1451`, `:1481`, `:1492`) → `py_error.log` | n/a (stderr redirect) | n/a — separate file, not `error.log` |

Most Python-side lines name the offending file (`pfb["pfb_py_zone"]`, `pfb_py_data`,
`pfb_py_whitelist`, `pfb_py_hsts`); some are subsystem-level with no file (module-load failures
at `:903-912`, the applied-marker write failure at `:352`) — a reporting mechanism built on these
lines cannot assume every one names a file.

### 1.3 The IP mirror write is optimistic, not confirmed — the real gap this ADR targets

`pfb_write_canonical_alias($alias_mirror, $canonical_set)` (`:18332`) writes the last-applied
mirror `/var/db/aliastables/pfB_<Alias>_v{4,6}.txt` **before** the apply step runs.
`pfb_apply_alias_delta()` → `pfb_pfctl_table_op()` (`:5133-5203` → `:4733-4747`) is
fire-and-forget: on a `pfctl` failure it now logs at level 2 into `error.log` too (issue #980,
fixed by PR #987) — but the widget still can't see it (issue #990: lowercase `failed`, above).
**Nothing compares the live kernel table back against the mirror after the fact, and nothing
retries.** A failed
apply is invisible today and stays wrong until the source changes again (which re-triggers a
fresh attempt) or an operator manually Force-Reloads.

DNSBL's equivalent handshake is **not** optimistic in the same way: PHP publishes a generation
sentinel `/var/unbound/pfb_py_reload` (`pfb_unbound_py_flip_sentinel()`, `~:6492-6524`); the
Python reload-watcher (`pfb_unbound.py:1004-1021`) only writes the **applied**-generation marker
`/var/unbound/pfb_py_reload.applied` *after* it has actually swapped the new snapshot in.
`pfb_unbound_py_wait_applied($gen, $timeout_s=30)` (`:6560-6569`) blocks (bounded, ~2s poll)
until applied catches up to sentinel; **on timeout it falls back to a full Unbound restart
in the same pass** (`:7886-7896`, explicitly "fail-safe by design," not itself an error) — so a
transient swap stall self-heals synchronously before the pass returns. The genuine DNSBL
apply-stage failure is the restart itself then failing (`$final['retval'] != 0`, `:7936-7952`).

### 1.4 Failed downloads/parses already retry — just slowly, which is fine

`pfb_hash_write()` (`:12018`, called at `:10464`) is only reached **after** a successful body
write — a failed download never poisons the ADR-42 change-detection sidecar (`.xxhash128`/
`.etag`/`.lastmod`), so the next scheduled attempt correctly sees "still needs fetching," not a
false "unchanged." `pfblockerng_tick()` (`pfblockerng_extra.inc:2670`) dispatches a due job's
pass via a **backgrounded** `exec(...)` and calls `pfb_due_ledger_mark_ran[_anchored]()`
**unconditionally** on dispatch — success or failure of the backgrounded pass never reaches the
tick, so a download/parse failure is retried no sooner than that job's normal cadence (up to a
day for `dcc`/`bl`). This is a real latency gap, but not a correctness one (per §1.4 above,
nothing is silently marked "fixed" when it isn't) — **out of scope for active retry** (see §2.4);
this ADR still needs these failures **visible** in the ledger, just not tick-retried.

### 1.5 The reusable pattern already in this codebase (ADR-43's due-ledger)

`pfb_due_ledger.json` under `$pfb['dbdir']` (`pfblockerng_extra.inc:2195-2470`) is a pure,
clock+seed-injectable, atomically-written JSON sidecar, one entry per job
(`{last_run, next_due, jitter}`), read/written via `pfb_due_ledger_*` helpers. This ADR's ledger
mirrors that exact idiom (atomic write, self-contained pure helpers, off-appliance testable) for
a different question: not "when is X next due" but "is X currently in a known-bad state."

## 2. Decision

Replace all four ad-hoc widget checks (dedup-sanity grep, dead OUT-OF-SYNC grep, `py_error.log`
filesize, `error.log` FAIL-grep) with **one PHP-owned, general-purpose open-issues ledger** that
every failure/success site in the pipeline writes to directly, plus a **Python-owned** companion
status file for DNSBL parse-stage signals (cross-process/chroot boundary — see §2.3), merged for
display. The widget becomes a pure reader of these two files. `error.log`/`py_error.log` stop
being read by the widget entirely and become free-form operator logs, governed only by their
existing rotation (ADR-30) — no format constraint, no need to ever "clear" them for the icon to
go green.

### 2.1 The ledger is general-purpose, not download-only

Per direct instruction: **anything that should be signalled about pfBlockerNG's health can open
a ledger entry** — this ADR wires the failure classes enumerated in §1.2/§1.3 as the initial
writer set, but the mechanism itself (`facility`, `item`, `stage`, free-text `message`) is not
scoped to any one class. A future stage (e.g. a GeoIP DB fetch failure) is a new writer against
the same library, not a new mechanism.

### 2.2 Ledger shape (PHP-owned, `{$pfb['dbdir']}/pfb_sync_status.json`)

Mirrors `pfb_due_ledger.json`'s persistence idiom exactly: pure, injectable, atomic
(stage → `fsync` → `rename`) writes via `pfb_sync_status_*()` helpers in `pfblockerng_extra.inc`.

| Field | Meaning |
| --- | --- |
| `facility` | `ip` \| `dnsbl` |
| `item` | the alias/group/feed name the entry is about |
| `stage` | `download` \| `parse` \| `apply` \| `dedup` — **enumerated from source in Phase 1**, not assumed here |
| `message` | human string, e.g. `"Feed X failed to download: status code 404"` |
| `first_seen` / `last_seen` | ISO timestamps |

**Open is idempotent-by-key**: opening an already-open `(facility, item, stage)` entry refreshes
`message`/`last_seen`, never duplicates. **Symmetric ownership (MUST, per direct instruction):**
every code path that can open an entry for a given `(facility, item, stage)` is paired with the
code path that clears that *same* key on its own next success — no orphaned entries left for a
different mechanism to clean up.

### 2.3 The DNSBL parse-stage cross-process boundary

`pfb_unbound.py` runs chrooted inside Unbound's Python loader — a separate process from PHP,
stdlib-only. It cannot safely co-write the PHP-owned JSON file (write contention, and PHP is not
chrooted so the paths don't even resolve the same way). Python instead owns a **second**,
structurally identical status file at a chroot-relative path (mirroring the existing
`pfb_py_reload`/`pfb_py_reload.applied` marker convention: PHP never writes it, Python never
writes the PHP one), written/cleared by the same try/except sites that already log to
`py_error.log` (§1.2) — using stdlib `json`, no new dependency. The widget-serving PHP code reads
**both** files (read-only merge) for one combined view; symmetric ownership (§2.2) still holds
*within* each language — Python clears its own entries, PHP clears its own.

### 2.4 Tick-driven reconciliation — apply-stage ONLY (per direct instruction)

Per direct instruction: **only the `apply` stage gets active retry.** Download/parse failures
stay ledger-visible (§2.1) but are NOT tick-retried — they already retry at their normal cadence
(§1.4), and that latency is accepted as fine. `pfblockerng_tick()` (`pfblockerng_extra.inc:2670`)
gains one **unconditional** step — runs every tick regardless of due-ness — that, for every open
`stage=apply` entry:

- **IP**: re-run just the apply step (`pfb_apply_alias_delta()`) against the **already-persisted**
  mirror/canonical set — no re-download, no re-parse, no re-dedup.
- **DNSBL**: re-check convergence (sentinel == applied, Unbound running, `unbound.conf`
  references `pfb_unbound.py`); if not converged, re-attempt the swap/restart path.

This is cheap (no network I/O, no feed re-parse) so it runs **synchronously inline** in the tick,
unlike the heavy cron/dcc/bl passes which stay backgrounded. **Retry cadence, per direct
instruction: every tick, unbounded, until it clears or the item gets a fresh update** (a normal
successful pipeline run for that item supersedes the stuck entry through the ordinary path) — no
attempt counter, no backoff knob. On success: clear the entry (§2.2). On failure: leave it open,
retried again next tick.

### 2.5 Widget rewrite

- **Icon** (both rows): yellow iff the ledger (merged PHP+Python) has **any** open entry for that
  facility — symmetric between IP and DNSBL, closing the exact asymmetry `enable_dup`-gating
  created (§1.1). Red/green logic for "is the facility even running" is unchanged.
- **Reporting list**: `pfBlockerNG_get_failed()` rebuilt to enumerate open ledger entries
  (message + item + stage), preserving the existing alias/group-editor deep-link UX for entries
  whose `item` matches a known alias — the same link-building shape as today (`:466-513`), just
  fed from ledger entries instead of grepped log lines.
- `error.log`/`py_error.log` become pure operator logs — free-form wording (no longer
  grep-pattern-constrained by the widget), governed only by ADR-30 rotation, never required to be
  "cleared" for the widget to go green.

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. A facility that is genuinely disabled/not-running still shows **red**, never yellow (icon
   red/green logic for "is it live at all" is untouched by this ADR).
2. Every existing writer's `pfb_logger(..., 2)` call (or Python `sys.stderr.write`) is
   **unchanged** — this ADR ADDS ledger writes alongside them, never removes or reformats the
   log line itself (issue #980's logging-level fix already landed via PR #987 — this ADR
   touches no logging level, only adds ledger writes alongside).
3. Opening the same `(facility, item, stage)` key twice never duplicates an entry — refresh only.
4. Every writer site has a paired clearer for the same key (§2.2) — no phase ships a writer
   without also shipping its clearer.
5. Tick-driven reconciliation touches **only** the `apply` stage — download/parse entries are
   never auto-retried by tick (§2.4).
6. A wiped/absent/corrupt ledger file reads as **no open entries** (fail-open for display, never
   a crash) — matching the due-ledger's downgrade-safe precedent, but note this is a *display*
   fail-open, not a correctness one: the underlying condition (if still real) re-opens the entry
   on the pipeline's own next pass.
7. The reporting list's alias/group-editor deep-link behavior for a recognized `item` is
   unchanged from today's `pfBlockerNG_get_failed()` UX.

### Coverage matrix (enumerated from source in Phase 1 — table above is the seed, not the final list)

Every writer site in §1.2/§1.3's table gets its own row: `{write site, its paired clear site,
facility, stage}`. Phase 1 re-derives this from a fresh grep against the live tree (reality
overrides this draft) and each row maps to a Phase-2/3/4 test or an explicit deferral.

### Explicitly kept / out of scope

- Issue #980 (pfctl failure logging level) — already fixed separately (PR #987, merged
  2026-07-08), not part of this ADR. Residual gap it left behind (the widget's case-sensitive
  `FAIL` grep still misses the fix's lowercase `failed` wording) is tracked as issue #990 and
  moot regardless — Phase 6 retires that grep entirely in favor of the ledger.
- Active retry for `download`/`parse` stages — stays on normal cadence (§2.4).
- A UI settings knob to disable/tune the ledger — none proposed; always-on, matching how the
  due-ledger itself has no on/off switch.
- Attempt-count/backoff throttling on apply retry — explicitly unbounded per direct instruction.
- Riding the ledger on issue #468's reboot persist/restore set — a reboot naturally re-runs the
  full IP/DNSBL bootstrap pass, which either clears a stale entry or re-opens it fresh; not
  persisting avoids stale-across-reboot entries masquerading as current.

## 3. Consequences

**Positive**

- IP and DNSBL report symmetrically — the `enable_dup`-only gate that made IP structurally unable
  to show yellow for real problems is gone.
- A stuck `pfctl` apply failure (today: silent forever) now self-heals within one tick interval
  (default 15 min) with zero operator action.
- `error.log`/`py_error.log` are freed from being a de-facto structured-data format the widget
  parses — future log wording changes can't accidentally break the dashboard.
- The ledger is a genuine general-purpose signal channel (§2.1), not a single-purpose bolt-on.

**Negative / risks**

- **New cross-process file boundary** (§2.3) is the most novel piece — a bug there (a Python
  write racing a PHP read, or a chroot-path mismatch) is a new failure mode the current
  freetext-log design didn't have. Isolated to its own phase (P4) for focused review.
- **Unbounded per-tick apply retry** (§2.4) means a genuinely un-fixable `pfctl` condition (e.g.
  a full kernel table, cf. issue #314) retries forever at 15-minute cadence — cheap per-attempt,
  but a permanent condition never stops trying. Accepted per direct instruction; revisit if it
  proves noisy in practice.
- Two ledger files (PHP + Python) to keep in sync conceptually, though not in code — a
  reader-merge bug could show a stale Python-side entry after PHP's view would say "healthy."

## 4. Requirements (acceptance)

1. IP row turns yellow on: (a) dedup-sanity failure (dedup on, unchanged from today) **or**
   (b) any open `facility=ip` ledger entry of any stage — verified independent of `enable_dup`.
2. DNSBL row turns yellow on: any open `facility=dnsbl` entry (merged PHP+Python) — the dead
   OUT-OF-SYNC check and the monotonic `py_error.log` filesize check are both retired.
3. A synthetic download/apply/parse failure opens the expected entry with a human-readable
   message; the entry disappears on the next successful attempt at that same stage, with
   `error.log`/`py_error.log` untouched (still containing the historical failure line).
4. Tick-driven apply reconciliation clears a stuck `stage=apply` IP or DNSBL entry once the
   underlying condition is fixed, without a source change / Force Reload.
5. Reporting-list entries for a recognized alias/group still deep-link to its editor page.
6. A `www/` change carries Tier-A `ui_render` coverage (icon + list, both empty-ledger and
   populated-ledger states).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()/exit()`; PFBL-01/`RequireConfigGateway`/
  `UppercaseBooleanLiteral` sniffs stay green (the ledger path is not a registered config field —
  no gateway involvement).
- Python: stdlib only (chrooted, no external deps) — `json` is stdlib, fine.
- Test-coverage mandate: every behaviour-changing phase (P2-P6) fails-before/passes-after; P1's
  ledger-library phase is itself new code with its own oracle-style branch coverage (not a
  refactor, so "behaviour-preserving" doesn't quite apply — treat every branch as needing its own
  fail/pass pair against a fresh call). `www/` (P6) → Tier-A. No coverage theater.
- No fixed-time waits (issue #456) — the tick's reconciliation step is a single synchronous
  attempt per firing, not a poll loop; no new wait primitive needed.

## 6. Action plan (phases — early ones are behaviour-preserving prep)

### Phase 1 — Pin today's icon/report behavior + the ledger library (behaviour-preserving)

- Prompt: `01_Oracle_And_Ledger_Library.txt`
- Freeze today's IP/DNSBL icon decisions (every branch: red/green/yellow × each trigger) and the
  reporting-list link-building behavior as golden oracles — these protect P6's rewrite. Re-derive
  the coverage-matrix table (§2's seed) from a fresh grep against the live tree; re-verify every
  `file:line` cited in §1 and flag any drift loudly in the handoff.
- Introduce `pfb_sync_status_open($facility, $item, $stage, $message, $clock_fn)` /
  `pfb_sync_status_close(...)` / `pfb_sync_status_list_open(...)` in `pfblockerng_extra.inc`,
  mirroring `pfb_due_ledger_*`'s shape (pure, injectable, atomic write, downgrade-safe on
  corrupt/absent file). No production caller yet.
- Tests: full branch coverage of the ledger helpers (open/reopen-refresh/close/close-absent/
  corrupt-file/list); the frozen oracles for today's widget behavior.

### Phase 2 — Wire PHP-side IP writers + clearers

- Prompt: `02_IP_Writers_And_Clearers.txt`
- Download fail/success at both call sites (`:15973-15977`, `:17690-17694` — re-verify which is
  IP vs DNSBL vs shared from source, per Phase 1's fresh matrix).
- Dedup-sanity: translate the existing shell `Sanity check [ PASSED/FAILED ]` line (still
  produced by `pfblockerng.sh`, unchanged) into an open/close call from whichever PHP path
  already reads it.
- IP apply fail/success in `pfb_pfctl_table_op()` / its caller — open alongside the EXISTING
  level-2 log call (issue #980 already fixed this via PR #987; do not touch its logging level
  further).
- Tests: fail-before/pass-after per writer — synthetic failure opens the entry; synthetic
  success (same key) closes it; a second failure on an already-open key refreshes, not
  duplicates.

### Phase 3 — Wire PHP-side DNSBL writers + clearers

- Prompt: `03_DNSBL_Writers_And_Clearers.txt`
- DNSBL conf/build fail (`:7936-7952`) → open; normal completion → close.
- Convergence helper: pure `pfb_dnsbl_converged(): bool` (sentinel == applied AND Unbound running
  AND `unbound.conf` references `pfb_unbound.py`) — used here to decide open/close, and reused by
  Phase 5's reconciliation.
- Tests: fail-before/pass-after for the conf/build-fail path; the convergence helper's full
  truth table.

### Phase 4 — Python-side DNSBL parse-stage status file

- Prompt: `04_Python_Status_File.txt`
- A new chroot-relative JSON file Python owns exclusively (path mirrors the
  `pfb_py_reload`/`.applied` convention), written/cleared by the existing per-file try/except
  sites (§1.2's Python table) using stdlib `json`. PHP gains a read-only merge helper.
- Hostile-input rows: absent file, empty file, truncated/corrupt JSON, a file the chroot can't
  write (permissions) — every case degrades to "no open Python-side entries" for PHP's reader,
  never a crash on either side.
- Tests: pytest for the Python write/clear helpers (every existing try/except site that gains a
  write, paired with its success clear); PHPUnit for the PHP-side reader against each hostile
  input.

### Phase 5 — Tick-driven apply-stage reconciliation

- Prompt: `05_Tick_Reconciliation.txt`
- `pfblockerng_tick()` gains the unconditional synchronous step (§2.4): for every open
  `stage=apply` entry (IP or DNSBL), re-attempt just the apply operation using already-persisted
  content; clear on success, leave open (retried again next firing) on failure.
- Tests: fail-before/pass-after — seed a stuck `stage=apply` entry with no other pipeline state
  change, run one tick, assert (a) the retry actually happened (a spy/counter), (b) success
  clears the entry, (c) continued failure leaves it open for the next tick to retry again
  (no backoff, no counter — §2.4).

### Phase 6 — Widget rewrite (icon + reporting list)

- Prompt: `06_Widget_Rewrite.txt`
- Icon logic (both rows) reads the merged ledger exclusively for the yellow trigger; red/green
  "is it running" logic untouched (Semantics #1). Retire the dead OUT-OF-SYNC grep, the
  monotonic `py_error.log` filesize check, and the `error.log` FAIL-grep reporting list —
  `pfBlockerNG_get_failed()` rebuilt from merged ledger entries with the same deep-link UX.
- Tier-A `ui_render`: empty-ledger (green, empty list) and populated-ledger (yellow, entries with
  working links) states for both rows.
- Tests: the Phase-1 oracles now assert the NEW behavior (fail-before against old code showing
  the wrong old-oracle result would be backwards here — this phase's tests are the new
  fail-before/pass-after pair, superseding P1's frozen-old-behavior oracle which was scaffolding,
  not a permanent pin).

### Phase 7 — Docs, DoD, manual smoke checklist

- Prompt: `07_Docs_DoD_Smoke.txt`
- `docs/misc/architecture-notes.md` entry for the sync-status ledger (mirrors the ADR-43
  due-ledger writeup style). Update this ADR's Status. Manual/live-VM smoke checklist (§7 below).

## 7. Definition of done

- All 7 phases landed (`RESULTS/01-07_Results.txt` + `*_Gate.txt`); full PHPUnit + pytest
  green; PHPCS/PHPStan clean; Tier-A `ui_render` **authored** (`tests/smoke/ui/
  test_render_widget_ledger.py`) but not yet executed against a live box (no VM was
  reachable in the implementing session) — step 1 below is that execution.
- **Live-VM manual smoke checklist (CE + Plus fan-out, per CLAUDE.md "ADR acceptance").**
  Each step names its expected, falsifiable observable — "should work" is not an
  acceptable substitute for any of these.

  1. **Run the authored Tier-A suite for real:**
     `python3 -m pytest tests/smoke/ui -k widget_ledger -m ui_render --override-ini="addopts="`
     with `SMOKE_ADMIN_PASSWORD` set. Expected: all cases in
     `test_render_widget_ledger.py` pass (empty-ledger green states, seeded-entry yellow
     states + working deep link for both rows, the DNSBL disabled-row wording
     distinction) — a skip is not a pass.
  2. **IP feed download failure:** point an IP list at an unreachable/404 URL, run an
     update pass. Expected: IP row turns yellow within that pass; the reporting list
     shows the entry with a working deep link to the alias editor; `error.log` gains the
     historical FAIL line and is left untouched afterward. Fix the URL, run again.
     Expected: entry clears, row returns to green (assuming no other open IP entry).
  3. **IP `pfctl` apply failure, then self-heal:** trigger a genuine `pfctl` failure if
     reproducible on the box (or PHPUnit-simulate at the `pfb_pfctl_table_op()` boundary
     per `PfctlTableOpTest`'s `mock_pfctl()` seam if a live trigger isn't reliable).
     Expected: IP row yellow, generic "N open issue(s)" wording (not the dedup-specific
     text). Fix the underlying condition out-of-band (no source change, no Force
     Reload). Expected: within **one tick interval** (`pfb_tick_interval`, default 15
     min) the entry self-clears — this is the ADR's core self-healing claim for IP;
     confirm it actually happens unattended, not just that the retry code exists.
  4. **DNSBL swap-not-confirmed fallback opens nothing by itself:** force a slow/stalled
     zero-downtime swap so `pfb_reload_unbound()` falls back to a restart. Expected: NO
     ledger entry opens from the fallback alone (§1.3, "fail-safe by design"); only a
     genuine post-restart failure (Unbound still not confirmed running afterward) opens
     one.
  5. **DNSBL apply failure — confirm the narrower retry, don't assume the IP behavior
     generalizes:** force a genuine DNSBL apply failure (a real conf/build error, or
     Unbound stopped underneath the pipeline). Expected: DNSBL row yellow. Wait past
     one tick interval WITHOUT fixing the underlying condition or forcing an
     operator Reload. Expected: the entry is **still open** — per the ADR's own
     sentinel-reflip-only retry narrowing (see architecture-notes), a genuinely stuck
     DNSBL condition does NOT self-heal via tick alone. THEN perform an operator Force
     Reload / Update pass (which runs the full restart path). Expected: the entry
     clears. This step exists specifically to catch a wrong assumption that DNSBL
     mirrors IP's tick-only self-heal — it does not.
  6. **DNSBL parse-stage (Python-side) failure:** corrupt or make unreadable one of the
     Python-loaded files (`pfb_py_zone.txt`, `pfb_py_data.txt`, `pfb_py_whitelist.txt`,
     `pfb_py_hsts.txt`, `pfb_py_ss.txt`, or `pfb_unbound.ini`) and trigger a reload.
     Expected: DNSBL row turns yellow via the merged Python-owned file read (this ADR
     run's own UI test only ever injected a synthetic `pfb_py_status.json`, never
     exercised a REAL Python writer — this step is the first genuine end-to-end proof).
     Fix the file, reload again. Expected: entry clears.
  7. **Reboot:** confirm the ledger is NOT in issue #468's MFS persist/restore set (by
     design, per §2's "Explicitly kept / out of scope") — after a clean reboot, both
     ledger files read as absent/empty (Semantics #6, fail-open display) regardless of
     any pre-reboot open entry; a still-real underlying condition re-opens its entry on
     the pipeline's own next natural pass, not automatically at boot.
  8. **DNSBL feed download failure, then self-heal (issue #998 follow-up, now wired):**
     point a DNSBL feed at an unreachable/404 URL, run an update pass. Expected: DNSBL
     row turns yellow within that pass; the reporting list shows the entry with a
     working deep link to the alias editor (`pfb_dnsbl_download_ledger_update()` keys
     on the `DNSBL_`-prefixed `$alias`, mirroring step 2's IP behavior);
     `error.log` gains the historical FAIL line and is left untouched. Fix the URL, run
     again. Expected: entry clears, row returns to green (assuming no other open DNSBL
     entry).

- **Accepted** requires steps 1-8 green: a genuine DNSBL apply failure that fails to
  self-heal via tick alone (step 5) is the EXPECTED, documented behavior, not a
  regression — do not treat it as a smoke failure.
- **Reject criteria (already resolved, kept for record):** Phase 4's Python-side chroot
  status file proved straightforward to write from inside the jail — no chroot-boundary
  fallback was needed; the file mirrors the existing `pfb_py_reload`/`.applied` marker
  idiom directly. This reject path is retained here only as the documented alternative
  that was considered and not required.
