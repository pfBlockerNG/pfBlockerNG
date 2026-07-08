# ADR-60: Uniform log timestamps and continuous age-based log retention

- **Status:** **Proposed** (2026-07-08)
- **Date:** 2026-07-08
- **Branch:** `adr/60-age-based-log-retention` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Supersedes:** **ADR-30** (`Scheduled_Log_Reset`) — retires `pfb_log_reset()`, `log_rotate_<type>`,
  `log_reset_keep_<type>`, and the `log_rotate.last` marker file entirely. ADR-30's own §8.3/8.4
  explicitly deferred age-based retention pending exactly the timestamp-reliability work this ADR
  does first — see §1.3.
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — `pfb_logger()` (`:3089`), `pfb_log_mgmt()`
    (`:2778`), `pfb_log_max_lines()` (`:2767`), `pfb_log_reset()` + helpers (`:2865`-`:3060`,
    DELETE), `pfb_daemon_filterlog()`'s timestamp branch (`:12780`-`:12785`), `pfb_parsed_fail()`
    (`:4448`), the 6 `pfb_open_sqlite()` bypass writes (`:13635` etc.), `pfb_update_pass_running()`
    (`:13848`, kept — now gates `pfb_log_mgmt()` alone), `pfb_failures()` (`:10619`).
  - `src/usr/local/pkg/pfblockerng/pfb_unbound.py` — `make_timestamp()` (`:2702`), its 4 call sites
    (`:2617`, `:2650`, `:2680`, `:2962`).
  - `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` — `pfb_cfg_registry()` (`:528`-`:626`,
    remove the `log_rotate_*`/`log_reset_keep_*` loop, add `log_max_days_*`), `pfb_log_rotate_period()`
    / `pfb_log_should_reset()` / marker parse-serialize helpers (`:1878`-`:1930`ish, DELETE),
    `pfblockerng_tick()` (`:2670`, the `pfb_log_mgmt()`/`pfb_log_reset()` call site at `:2777`-`:2778`).
  - `src/usr/local/www/pfblockerng/pfblockerng_general.php` — the Log Settings section (`:75`-`:450`
    ish): remove the `log_rotate_<type>`/`log_reset_keep_<type>` selects (ADR-30 Phase 4), add
    `log_max_days_<type>`.
  - `tests/phpcs/PfBlockerNG/Sniffs/Config/RequireConfigGatewaySniff.php` — `$registeredPaths`
    (`:71`-`:100`).
  - `tests/php/` — `PfbLoggerIsoTimestampTest.php`, `PfbIsoTimestampTest.php`,
    `UnifiedFormatTest.php` (update); `LogRotateScheduleTest.php`, `LogRotateResetTest.php` (delete).
  - `tests/smoke/test_log_rotate.py` (delete the ADR-30 cases; add the age-trim live-VM case).
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the PHP-side logs; Python 3.11+ stdlib-only
  inside Unbound's pythonmod for `dnslog`/`dnsreplylog`.
- **Test suite:** `tests/php/` (PHPUnit), `python -m pytest` (pfb_unbound.py unit tests),
  `tests/smoke/` (ADR-04 live-VM), `tests/smoke/ui/` (Tier-A `ui_render`).

---

## 1. Context (today)

### 1.1 The two existing retention mechanisms

- **`pfb_log_mgmt()`** (`pfblockerng.inc:2778`) — continuous, runs every cron tick
  (`pfblockerng_tick()`, `pfblockerng_extra.inc:2777`). Caps each of **10** log types
  (`log, errlog, extraslog, ip_blocklog, ip_permitlog, ip_matchlog, dnslog, dnsbl_parse_err,
  dnsreplylog, unilog`) to a per-type **line count** (`log_max_<type>`, default `'20000'`,
  `'nolimit'` opts a type out entirely — `pfb_log_max_lines()`, `:2767`). Mechanism: `tail -n N
  file > temp; cat temp > file` — truncates **in place** to preserve the inode (#264/#280): a
  remote syslog shipper keyed on `(inode, offset)` would treat a renamed file as a fresh rotation
  and re-ship everything.
- **`pfb_log_reset()`** (ADR-30, `pfblockerng.inc:2937`) — opt-in, **calendar-boundary** full reset
  (`log_rotate_<type>`: off/daily/weekly/monthly) with an optional keep-last-K-lines cushion
  (`log_reset_keep_<type>`, Amendment #416), tracked via a `log_rotate.last` marker file. A sawtooth,
  not a rolling window: a log reset on `daily` holds between 0 and ~24h of data depending on when in
  the period you look.

### 1.2 Why age-based retention wasn't done in ADR-30

ADR-30 §8.3/8.4 considered exactly this and explicitly deferred it:

> "The request was framed as 'keep the last few minutes/hours.' A true time window would need to
> parse a timestamp from every line, but the 10 log types have heterogeneous formats (some lines
> are not cleanly timestamped) — fragile and format-coupled. A line count is a robust,
> format-agnostic proxy... [Time-window retention] — deferred (the per-format timestamp parsing
> above); revisit only on a concrete need."

This ADR is that revisit, backed by a full per-type timestamp audit (below) instead of a guess.

### 1.3 Timestamp coverage today — verified per type, not assumed

| logtype | timestamp today | year? | written by |
| --- | --- | --- | --- |
| `log` | **opt-in**: only present if the caller embeds a literal `NOW` token in the message (most calls don't). Even then, a process-global same-second dedup strips it to nothing if two `pfb_logger()` calls land in the same wall-clock second (see §1.4). | n/a (often absent) | PHP `pfb_logger()` (`:3089`) |
| `extraslog` | same opt-in `NOW`-token + dedup mechanics as `log` | n/a (often absent) | PHP `pfb_logger()` cases 3/4 |
| `errlog` | (a) via `pfb_logger()`'s `$elog` — always stamped `date('Y-m-d H:i:s')`, but position varies (wherever the caller put `NOW`, else a trailing `" [ ts ]"`). (b) `pfb_open_sqlite()` bypass (`:13635`, `:13642`, `:13657`, `:13661`, `:13670`, `:13698`, 6 sites) writes **directly via `file_put_contents`, no timestamp at all**. | yes (path a only) | PHP, two independent writers |
| `ip_blocklog`/`ip_permitlog`/`ip_matchlog` | first CSV field. `pfb_daemon_filterlog()` (`:12780`): `'BSD'` branch copies pf's raw syslog fields verbatim (`Mon D HH:MM:SS`, classic BSD syslog — **no year exists in the source**); the `'syslog'` branch (RFC-5424 input) does `date('M j H:i:s', strtotime($f[1]))` — **`$f[1]` is already a full ISO-8601 timestamp with year**, and this line **throws the year away** reformatting it down. | BSD: no (none available); syslog: available but discarded today | PHP `pfb_daemon_filterlog()`, single daemon |
| `dnsbl_parse_err` | `pfb_parsed_fail()` (`:4448`): `date('m/j/y H:i:s', time())` — has a 2-digit year, but ambiguous `m/d/y` ordering | yes (2-digit, ambiguous format) | PHP, synchronous per feed-parse |
| `dnslog`/`dnsreplylog` | `make_timestamp()` (`pfb_unbound.py:2702`): `datetime.now().strftime("%b %-d %H:%M:%S")` — no year; returns `""` if `%-d` raises `TypeError` twice (a real code path, not hypothetical) | no | Python, `pfb_unbound.py` |
| `unilog` | passthrough of whichever source row it came from — python `%b %-d %H:%M:%S` (DNSBL/DNS-reply rows) or BSD/`M j H:i:s` (IP rows) — **two formats mixed in the same CSV column** | no (either flavor) | PHP `pfb_daemon_filterlog()`, single daemon, 3 upstream tails |

### 1.4 The `$pfb['pnow']` same-second dedup — legacy, undocumented, actively harmful here

`pfb_logger()` (`:3095`-`:3109`):

```php
$now = date('Y-m-d H:i:s', time());
if (strpos($log, 'NOW') !== FALSE) {
    $elog = str_replace('NOW', $now, "{$log}");
    if ($now == ($pfb['pnow'] ?? '')) {
        $log = str_replace(' [ NOW ]', '', "{$log}");   // strips the timestamp to NOTHING
    } else {
        $log = str_replace('NOW', $now, "{$log}");
    }
    $pfb['pnow'] = "{$now}";
}
```

`$pfb['pnow']` is a single process-global shared across every call regardless of logtype. Verified via
`git log -S"pnow"` and `git show 0846aa7c:.../pfblockerng.inc` (this repo's literal first commit,
"pfBlockerNG 3.2.15 - initial commit") — this dedup predates the repo entirely; no comment, issue, or
ADR anywhere documents its rationale. It is retired as part of this rework (§2.2).

### 1.5 The two existing trim mechanisms already race always-on writers — pre-existing, unchanged

`pfblockerng_tick()` (`pfblockerng_extra.inc:2670`) gates both `pfb_log_mgmt()` and `pfb_log_reset()`
behind `pfb_update_pass_running()` (`pfblockerng.inc:13848`), a `ps`-scan regex matching only discrete
`pfblockerng.php <verb>` CLI invocations. It **cannot** see the three always-on writers —
`pfb_daemon_filterlog()`, `pfb_daemon_dnsbl()`, and the embedded Python module — so trims of
`ip_blocklog`/`ip_permitlog`/`ip_matchlog`/`unilog`/`dnslog`/`dnsreplylog` are unprotected against a
concurrent append today. `dnslog` additionally has a genuine two-OS-process writer (Python's
`WatchedFileHandler`, no flock, plus PHP's `pfb_daemon_dnsbl()`, same physical file via nullfs). This
ADR does not fix or worsen this — it is called out because the age-cutoff scan (§2.2) inherits the
identical hazard the line-count trim already has, and is explicitly out of scope here (§2.4).

### 1.6 Not a constraint: syslog-export compatibility

Checked and refuted during triage: `pfb_syslog_event()` (`pfblockerng_extra.inc:2166`, ADR-38) uses
PHP `openlog()`/`syslog()` — the wire-format envelope timestamp comes from syslogd/the OS, not from
our code. The message body (`pfb_syslog_format_ip()`/`pfb_syslog_format_dnsbl()`,
`pfblockerng_extra.inc:1965`/`:2036`) is pure `key=value` with **no timestamp field at all**. Changing
our internal log-file timestamp format has no bearing on the syslog-export path.

### 1.7 Not a constraint: `runlog`/ADR-58

`$pfb['runlog']` (`pfblockerng_run.log`) exists to solve the *run-progress visibility* problem across
the Update page live-tail, the pfSense Software page, and hook-output streaming (issue #662's
daemon-pipe hazard) — see the Proposed/Draft ADR-58 (`Unified_Run_Output_Streaming`). ADR-58 §2.4
explicitly states *"Log rotation / retention semantics (`pfb_log_mgmt()`) — preserved as-is"* and
never references `pfb_log_reset()`/ADR-30. The two are orthogonal; retiring `pfb_log_reset()` here has
no effect on `runlog`'s reason to exist.

## 2. Decision

### 2.1 Per-area decision table

| Area | Today | ADR-60 |
| --- | --- | --- |
| Timestamp format | 4 different shapes across 10 types, 3 of which are frequently absent, none carrying an unambiguous year except `dnsbl_parse_err`'s ambiguous 2-digit one | **One format, one position, all 10 types**: `Y-m-d H:i:s` (ISO-8601, unambiguous, sorts lexically — already `pfb_logger()`'s existing `$elog`/errlog convention, already pinned by `PfbLoggerIsoTimestampTest.php`), as a fixed **line-start prefix** for the free-text logs and CSV **field 0** for the CSV-shaped logs. Always present, never opt-in. |
| `log`/`extraslog` timestamp | opt-in `NOW` token + same-second dedup that can blank it | Always stamped; `$pfb['pnow']` dedup deleted; any leftover literal `NOW`/`" [ NOW ]"` token in a caller's message string is defensively scrubbed **once, inside `pfb_logger()`** (not per call site — ~30+ call sites keep their existing text unchanged and simply gain a real, unconditional prefix) |
| `errlog` | opt-in via `pfb_logger()`, zero timestamp via the `pfb_open_sqlite()` bypass | Both paths go through the same helper; always stamped |
| `ip_block/permit/matchlog`, IP rows of `unilog` | 'BSD' branch: no year available; 'syslog' branch: year available but discarded | 'syslog' branch: use `strtotime($f[1])`'s already-correct year verbatim — a free fidelity win, zero ambiguity. 'BSD' branch: year-infer (assume current year; roll back one if the resulting date is in the future relative to now — the standard BSD-syslog fix) since pf's raw output never carries one. Both branches emit `date('Y-m-d H:i:s', $ts)`. |
| `dnsbl_parse_err` | `m/j/y H:i:s`, ambiguous | `Y-m-d H:i:s` |
| `dnslog`/`dnsreplylog`, python rows of `unilog` | `make_timestamp()`, no year | `make_timestamp()` gains the year: `"%Y-%m-%d %H:%M:%S"` |
| Continuous retention | line-count only (`log_max_<type>`) | **adds** `log_max_days_<type>` (numeric string, default `'0'` = off) — both caps apply independently every tick; whichever is more restrictive wins |
| Calendar-boundary reset (ADR-30) | `log_rotate_<type>` / `log_reset_keep_<type>` / `pfb_log_reset()` / marker file | **removed** — superseded by the continuous age cap above |

### 2.2 The age-cutoff mechanism (mechanically simple, reuses the existing trim)

`pfb_log_mgmt()` already produces a `tail -n $logmax` **candidate** (the last N lines) before
`cat`-ing it back over the live file. When `log_max_days_<type> > 0`, add **one extra pass over that
already-small candidate** (not the original file): scan from the top, parse each line's leading/field-0
`Y-m-d H:i:s` timestamp, and drop the leading run of lines older than `now - N days`. Because log
lines are chronologically appended, this is a single linear scan with an early stop at the first
line that is NOT expired — no need to touch the rest of the (already line-capped) candidate.

**Unparseable line policy:** a line with no valid leading timestamp (e.g. a legacy pre-upgrade line
still in the file the first time an operator opts in) is treated as **expired** (safe to drop) — it
predates this rework by construction, and `log_max_days_<type>` defaults to `'0'` (off), so this only
ever surfaces once an operator explicitly opts in. Same fallback for a `strtotime()` parse failure in
the 'BSD' year-inference path.

**Independence from `nolimit`:** today, `pfb_log_mgmt()` `continue`s entirely for a type when
`log_max_<type> === 'nolimit'` (`:2791`-`:2793`), which would currently also skip an age cap. This ADR
restructures the function so the two caps are evaluated independently — `nolimit` disables only the
line-count cap; `log_max_days_<type}` still applies if set. Pinned as a coverage-matrix row (§2.5).

### 2.3 Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Inode + ownership preserved** on every trim path (line-count, age-cutoff, and their
   combination) — never `mv`/recreate; chrooted python logs keep `chown unbound` (#264/#280).
2. **Default `log_max_days_<type> = '0'` (off) ⇒ zero behaviour change** to the existing line-count
   trim for every operator who doesn't opt in.
3. **`nolimit` on `log_max_<type>` and a set `log_max_days_<type>` are independent** — each cap
   applies (or doesn't) on its own; `nolimit` no longer short-circuits the whole function.
4. **Every log line, across all 10 types, carries a `Y-m-d H:i:s` timestamp with a real year** —
   `log`/`extraslog`/`errlog` unconditionally; the CSV types at a fixed field position. No log type
   can end up with a fully blank/absent timestamp on a normal write path (the `pfb_open_sqlite()`
   bypass sites included).
5. **`pfb_failures()`'s date-match (`:10619`-`:10635`) keeps working** — it greps `errlog` for `'FAIL'`
   and today's `Y-m-d` string; the new always-on prefix is a superset guarantee (every line has it,
   not just `NOW`-tagged ones), so this only gets more reliable, never less.
6. **A failed `tail`/`cat` exec (nonzero exit) never blanks or corrupts the live log** — the existing
   per-exec-exit-code gating in `pfb_log_mgmt()` is preserved through the new age-cutoff pass.
7. **`config.xml` stored values for the removed `log_rotate_<type>`/`log_reset_keep_<type>` keys are
   left untouched on disk** (ADR-28 §2.2 "hard-frozen" convention) — deregistering just stops reading
   them; no active migration/strip step.

### 2.4 Explicitly kept / out of scope

- **The race between the trim/age-cutoff pass and the always-on daemon writers** (§1.5) — pre-existing,
  unchanged. No new locking added.
- **`runlog`/ADR-58** — untouched, orthogonal (§1.7).
- **The syslog-export path (ADR-38)** — untouched, unaffected (§1.6).
- **A per-call-site cleanup of the now-vestigial literal `NOW`/`" [ NOW ]"` text** in the ~30+
  `pfb_logger()` caller strings — the defensive scrub inside `pfb_logger()` (§2.1) makes this
  cosmetic only; deferred, not required for correctness.

### 2.5 Coverage matrix (from source, not memory)

| Axis | Rows | Covered by |
| --- | --- | --- |
| Log type × writer | `log`, `errlog` (2 writers: `pfb_logger` + `pfb_open_sqlite` bypass), `extraslog`, `ip_blocklog`, `ip_permitlog`, `ip_matchlog`, `dnsbl_parse_err`, `dnslog` (2 writers: Python + PHP `pfb_daemon_dnsbl`), `dnsreplylog`, `unilog` (mixed-format passthrough) | Phases 2-4 |
| `pfb_daemon_filterlog()` input format | `'BSD'` branch, `'syslog'` (RFC-5424) branch | Phase 3 |
| `log_max_<type>` × `log_max_days_<type>` | off×off, off×set, `nolimit`×off, `nolimit`×set, set×off, set×set (tighter cap wins each direction) | Phase 5 |
| Unparseable-line handling | legacy pre-rework line (no/old-format timestamp) present in a file when age-cutoff first runs | Phase 5 (hostile-input row) |
| Config removal | every one of the 10 `log_rotate_<type>` + 10 `log_reset_keep_<type>` registry entries and sniff paths | Phase 6 |

### 2.6 Hostile-input rows for the new age-cutoff parser (Phase 5)

- Empty file.
- File with only unparseable (legacy-format) lines.
- File with a mix of legacy and new-format lines (the realistic upgrade scenario).
- A line whose timestamp parses but is exactly at the cutoff boundary (off-by-one day).
- A line with a corrupted/truncated timestamp prefix (partial write from a crash mid-line).
- `log_max_days_<type>` set to a non-numeric/garbage config value (treat as off, mirroring
  `pfb_log_max_lines()`'s existing fallback-to-default pattern).

## 3. Consequences

**Positive**

- One retention mechanism instead of two; `pfb_log_reset()`'s marker file, calendar-math, and UI
  surface disappear entirely.
- Every log line gets a real, unambiguous, year-bearing timestamp — fixes a genuine (if minor)
  operator-facing defect (`ip_block/permit/matchlog`/`dnslog`/`dnsreplylog`/`unilog` were all
  effectively undateable across a year boundary).
- `pfb_failures()` becomes strictly more reliable (every errlog line dateable, not just `NOW`-tagged
  ones).
- The age-cutoff implementation is cheap: one extra linear pass over an already line-capped (small)
  candidate, reusing the proven inode-preserving trim.

**Negative / risks**

- **Reverses an Accepted ADR (ADR-30).** Any operator who set `log_rotate_<type>`/`log_reset_keep_<type>`
  loses that behavior on upgrade (silently — the keys are simply no longer read). Mitigated by: this
  was a per-log opt-in, default-off feature (ADR-30 §2.2 item 1), so most installs are unaffected; the
  functional intent (fresh, bounded log data) is fully replaced by the new continuous age cap, which
  is arguably a better fit for the original issue #341 ask (`daily`/`weekly`/`monthly` reset was
  always an awkward proxy for "keep N days").
- **Format change touches 3 writer call sites across 2 languages** (PHP `pfb_logger`/
  `pfb_daemon_filterlog`/`pfb_parsed_fail`/`pfb_open_sqlite`; Python `make_timestamp`) — real
  cross-cutting surface, contained by the coverage matrix (§2.5) and front-loaded oracle tests
  (§6 Phase 1).
- **The BSD-branch year-inference is a heuristic** (assume current year, roll back if future) — the
  classic BSD-syslog problem, unavoidable given the source format carries no year; documented as a
  known limitation, not silently swept under.
- **The always-on-writer race (§1.5) is unchanged** — an operator who opts into a tight
  `log_max_days_<type>` on a busy `ip_blocklog` inherits the same pre-existing (if rare) chance of a
  lost line mid-trim as today's line-count trim already has.

## 4. Requirements (acceptance)

1. All 10 log types emit a `Y-m-d H:i:s` timestamp, unconditionally, on every normal write path —
   verified per type, per writer (§2.5).
2. `log_max_days_<type>` (default `'0'`) trims each opted-in log to lines within the retention window,
   inode + ownership preserved, independent of `log_max_<type>`'s state (including `nolimit`).
3. `pfb_log_reset()`, `log_rotate_<type>`, `log_reset_keep_<type>`, and the marker file are gone —
   `pfb_cfg_registry()`, the sniff, the UI, and the tick call site all agree.
4. `pfb_failures()` and every other errlog/`FAIL`-date consumer keep working unchanged.
5. A `www/` change carries Tier-A `ui_render` coverage.
6. All gates green; the §2.3 contract pinned by tests; red→green proof for every behaviour-changing
   phase.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()`/`exit()` in library code.
- Python: stdlib only inside `pfb_unbound.py` (Unbound's loader) — `make_timestamp()`'s change stays
  within `datetime`/`time`, already the case.
- A registered field added/removed ⇒ registry entry + `since` + `RequireConfigGateway` sniff
  `$registeredPaths` + round-trip test, all kept in lockstep (ADR-29).
- `config.xml` stored values are hard-frozen (ADR-28 §2.2) — removed keys are deregistered, not
  actively stripped from any operator's existing config.
- Test-coverage mandate: every behaviour-changing phase fails-before/passes-after with pasted
  command output; behaviour-preserving phases pin an oracle; `www/` ⇒ Tier-A; no coverage theater.
- Comment-narration check (`scripts/check_comment_narration.py`) and version-literal check stay green
  on touched lines.

## 6. Action plan (phases — early ones are behaviour-preserving prep)

### Phase 1 — Pin today's inconsistent timestamp behaviour as the "before" oracle (behaviour-preserving)

- Prompt: `01_Baseline_Oracles.txt`
- Add/extend PHPUnit + pytest tests that pin the CURRENT (inconsistent) output of all 10 log types
  exactly as documented in §1.3 — including the `'BSD'` vs `'syslog'` filterlog branches, the
  `pfb_open_sqlite()` bypass's zero-timestamp writes, and `make_timestamp()`'s no-year format. These
  become the "before" side of every later phase's red→green proof.
- Extract two small pure helpers (no behaviour change): PHP `pfb_log_iso_timestamp(): string`
  (wraps `date('Y-m-d H:i:s', time())`) and a Python `iso_timestamp()` beside `make_timestamp()` —
  neither is wired in yet.
- Tests: golden/oracle tests for every row in §1.3's table; existing suite stays green.

### Phase 2 — Uniform, always-on timestamp for `log`/`extraslog`/`errlog`

- Prompt: `02_Php_Freetext_Logs.txt`
- Rewrite `pfb_logger()`: every `log`/`extraslog`/`errlog` write is unconditionally prefixed via
  `pfb_log_iso_timestamp()`; delete `$pfb['pnow']` and the `NOW`-token substitution branch; defensively
  `str_replace` any leftover literal `NOW`/`" [ NOW ]"` substring out of the message (one place, not
  per call site). Route all 6 `pfb_open_sqlite()` bypass writes through the same helper.
- Tests: red-before (Phase 1's oracles for `log`/`extraslog`/`errlog`/the bypass sites now fail against
  the NEW code — prove the old assertions actually pinned the old behaviour), green-after (new
  assertions: every line stamped, no dedup-induced blank, `pfb_open_sqlite()` sites stamped). Rewrite
  `PfbLoggerIsoTimestampTest.php`'s dedup-specific assertions (the `'pnow'` mechanic it exercises is
  gone).

### Phase 3 — Uniform timestamp for the IP-side CSV logs

- Prompt: `03_Php_Ip_Csv_Logs.txt`
- `pfb_daemon_filterlog()`: replace the `'BSD'`-raw-copy / `'syslog'`-lossy-reformat split with one
  output path — `'syslog'` branch keeps `strtotime($f[1])`'s real year; `'BSD'` branch year-infers
  (current year, roll back one if resulting date is in the future). Both emit
  `date('Y-m-d H:i:s', $ts)`. `pfb_parsed_fail()` switches `dnsbl_parse_err` from `m/j/y H:i:s` to the
  same format via `pfb_log_iso_timestamp()`.
- Tests: red-before/green-after against Phase 1's oracles for `ip_blocklog`/`ip_permitlog`/
  `ip_matchlog`/`dnsbl_parse_err`; both filterlog input-format branches; the year-inference
  boundary (a December log line parsed in January, and vice versa). Update `UnifiedFormatTest.php`'s
  fixtures to the new format.

### Phase 4 — Uniform timestamp for the Python-side logs

- Prompt: `04_Python_Logs.txt`
- `make_timestamp()`: `"%b %-d %H:%M:%S"` → `"%Y-%m-%d %H:%M:%S"`. Verify `unilog`'s passthrough of
  `dnslog`/`dnsreplylog` rows inherits the new format with no separate PHP-side change (it's a
  straight field copy).
- Tests: `python -m pytest` red-before/green-after against Phase 1's oracle for `dnslog`/
  `dnsreplylog`; the `TypeError`-twice fallback path still returns `""` (unchanged, still a real edge
  case, now just documented); a PHP-side `UnifiedFormatTest.php` case confirming a python-sourced
  `unilog` row shows the new year-bearing format.

### Phase 5 — `log_max_days_<type>`: the age-cutoff cap

- Prompt: `05_Age_Cutoff.txt`
- Register `log_max_days_<type>` (10 keys, default `'0'`, mirroring `log_max_<type>`'s loop shape) in
  `pfb_cfg_registry()` + the sniff `$registeredPaths`. Restructure `pfb_log_mgmt()` so `nolimit` on
  `log_max_<type>` no longer short-circuits the function — the age cap evaluates independently. Add
  the age-cutoff pass: over the `tail -n N` candidate, drop the leading run of lines older than
  `now - log_max_days_<type>` days (parse the now-uniform `Y-m-d H:i:s` prefix/field); unparseable
  lines are treated as expired.
- Tests: every §2.5/§2.6 coverage-matrix and hostile-input row; red-before (today's `pfb_log_mgmt()`
  has no age cap at all — the new test fails against pre-Phase-5 code) / green-after; inode +
  ownership preserved (both plain and chrooted python-log paths); a failed `tail`/`cat` still never
  blanks the log.

### Phase 6 — Retire `pfb_log_reset()` / ADR-30's mechanism

- Prompt: `06_Retire_Adr30.txt`
- Delete `pfb_log_reset()`, `pfb_log_rotate_period()`, `pfb_log_should_reset()`, the marker
  parse/serialize helpers, and the `log_rotate.last` marker-file handling. Remove the
  `log_rotate_<type>`/`log_reset_keep_<type>` registry entries + sniff paths. Remove the
  `pfb_log_reset()` call in `pfblockerng_tick()`. Delete `tests/php/LogRotateScheduleTest.php` +
  `LogRotateResetTest.php`. Grep-gate: no remaining reference to `log_rotate_`/`log_reset_keep_`/
  `pfb_log_reset`/`log_rotate.last` outside `.ADRs/` (historical mentions are fine).
- Tests: full suite green with the deletions; the grep-gate command + its (empty) output pasted in
  the handoff.

### Phase 7 — Log Settings UI

- Prompt: `07_Ui.txt`
- `pfblockerng_general.php`: remove the `log_rotate_<type>`/`log_reset_keep_<type>` `Form_Select`
  controls; add a `log_max_days_<type>` numeric `Form_Input` next to each `log_max_<type>` field,
  with help text. Load/save via `$pconfig`/`$_POST`, reading through `PfbConfig`.
- Tests: Tier-A `ui_render` (page loads, no PHP error, the new fields present, the removed ones
  gone).

### Phase 8 — Smoke + validation + docs

- Prompt: `08_Smoke_And_Validation.txt`
- Live-VM smoke (ADR-04): seed a log with lines whose timestamps straddle a `log_max_days_<type>`
  cutoff (mix of expired/current), run the cron tick, assert only the expired prefix is dropped,
  inode + ownership preserved, `log_max_days_<type>='0'` leaves size-only behaviour unchanged, and the
  retired ADR-30 config keys/UI controls are gone. Update any user-facing help text/docs referencing
  the old scheduled-reset feature. Flip Status → Accepted on green.

## 7. Definition of done

- All eight phases landed; `vendor/bin/phpunit` + `phpcs` + `phpstan` + `python -m pytest` +
  `ui_render` green; the §2.3 contract pinned; the §2.5/§2.6 coverage matrix fully ticked.
- Live-VM smoke (CE + Plus fan-out) green for the age-cutoff trim, inode/ownership preservation, and
  `nolimit`-independence cases.
- **Manual smoke checklist (owner: maintainer — out-of-CI, real multi-day-old data):**
  1. Set `log_max_days_ip_blocklog=7` on a box with more than 7 days of real block history; confirm
     only lines older than 7 days are dropped at the next tick, inode (`ls -i`) unchanged, a remote
     syslog shipper does not re-ship.
  2. Confirm a box that never touches `log_max_days_<type>` sees byte-identical trim behaviour to
     before this ADR (line-count only).
  3. Confirm an upgrade from a build with `log_rotate_ip_blocklog=daily` set no longer resets that
     log on any calendar boundary (the config key is now inert).

**Reject criteria.** Abandon/redesign if: (a) the age-cutoff scan cannot be reconciled with the
inode-preserving trim (it should — same `tail`/`cat` shape, one extra filter pass); or (b) the
BSD-branch year-inference proves unreliable enough in practice (e.g., a box with a badly-skewed clock)
that it produces materially wrong retention decisions — in that case, fall back to keeping the
year-less format for the `'BSD'` branch only and treat every `'BSD'`-sourced line as needing the
line-count cap (not the age cap) until a better source of truth exists.
