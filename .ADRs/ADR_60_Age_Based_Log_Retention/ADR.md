# ADR-60: Uniform log timestamps and continuous age-based log retention

- **Status:** **Accepted, amended** (2026-07-08; Phases 1-9 implemented 2026-07-08; §8
  post-merge amendments 2026-07-09) — the new
  `tests/smoke/test_log_age_retention.py` cases (host-path `ip_blocklog` age cutoff with inode
  preserved, chrooted `dnslog` age cutoff with inode + `unbound` ownership preserved, and the
  `log_max_days_<type>='0'` no-op control) pass on the CE + Plus live-VM fan-out (run
  28964455515); the deferred Phase 5/8 Tier-A `ui_render` proofs (Reports/Alerts day-bucket +
  hourly-chart rendering, the redesigned Log Settings page) also pass on the CE + Plus fan-out
  (run 28964459756). A disposable pre-Phase-6 dispatch (run 28964420263, `adr-60-redproof-temp`,
  deleted after use) confirmed the new smoke cases genuinely fail without this ADR's code
  (`assert content_after == kept` failed — the age cap did not exist yet). Phase 10 (the wider
  §1.8 ISO-8601 sweep) is a separate, non-gating follow-on.
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
  - `src/usr/local/www/pfblockerng/www/index.php` — the DNSBL sinkhole block page (`:45`, `:51`,
    `:52`): its `dnsbl.log` correlation grep key is coupled to `make_timestamp()`'s output shape —
    BREAKS the moment that format changes unless fixed in lockstep (§1.8).
  - `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` — the Reports/Alerts day-bucket stat
    grouping (`:1837`) and hourly chart-label builder (`:1782`, `:1850`) — both `cut`/`awk` on a
    fixed space-token count that the old (3-token) log format satisfies and the new (2-token) ISO
    format does not. BREAKS the moment the log format changes unless fixed in lockstep (§1.8).
  - Wider ISO-8601 sweep (§1.8, Phase 10 — lower priority, optional-but-requested normalization):
    `pfblockerng.inc` — `dnsbl_alias_update()` (~`:5370`/`:5404`, DNSBL group "last updated"),
    `pfBlockerNG_clearsqlite()` (~`:14133`/`:14137`, "last clear" timestamps), the `/tmp` debug
    snapshot filename (~`:16534`); `pfblockerng.php` (~`:843`, MaxMind version `gmdate`);
    `pfblockerng_update.php` (~`:291`-`:292`, schedule ledger display); `pfb_unbound.py`
    (~`:893`/`:898`, unwritable-log rename filename); `widget.php`'s `pfb_iso_timestamp()` helper
    (~`:702`-`:711`, a year-guessing reformatter that becomes unnecessary once its source is ISO).
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

### 1.8 Beyond the 10 log types — a full codebase sweep for non-ISO dates

Once the "external consumer might parse our old format" excuse is gone for the 10 log files, it's
gone everywhere else too. A full `date(`/`gmdate(`/`strftime(` sweep of `src/` (verified: no
`DateTime::format()`/`new DateTime()` usage exists outside these calls) found two categories.

**HIGH PRIORITY — in-repo consumers of the 10 log types' format, would BREAK the moment Phases 2-4
land if not fixed alongside them (not optional, folded into Phases 4-5 below):**

- **`www/index.php:45,51,52`** — the DNSBL block page shown to end users builds a grep key via
  `date('M j H:i', ...)`/`date('M j', ...)` to correlate a blocked request against `dnsbl.log` and
  pull the Type/Group/Evaluated/Feed detail for display. This key is byte-coupled to
  `make_timestamp()`'s exact output shape (`"Jan 5 14:30:45"`). The moment `make_timestamp()` goes
  ISO, the grep **never matches** — the block page silently falls back to `-` placeholders, no error,
  100% loss of the "why was I blocked" detail.
- **`pfblockerng.inc:13725`** (`pfb_log_event()`) — a **second writer** to the exact same
  `dnsbl.log` file `pfb_unbound.py` writes (Unbound-native-mode DNSBL logging, vs Python-mode),
  still using `date('M j H:i:s', time())`. Missed by a naive reading of "Python logs = only
  `pfb_unbound.py`" — this PHP call site writes the identical file and MUST change in the same
  phase, or `dnsbl.log` ends up mixed-format (worse than today's uniformly-wrong state).
- **`pfblockerng_alerts.php:1837`** — the Reports per-day stat buckets (`ipdate`/`dnsbldate`/
  `replydate` columns, feeding IP-block/permit/match AND dnsbl AND dns-reply stats alike) do
  `cut -d ',' -f{col} | cut -d ' ' -f1-2 | uniq -c`, relying on the OLD format's 3 space-separated
  tokens (`"Jan 5 14:30:45"` → `-f1-2` = `"Jan 5"`, the day bucket). ISO (`"2026-07-08 14:30:45"`)
  has only 2 space tokens, so `-f1-2` returns the whole field unchanged — every line becomes its own
  unique bucket down to the second; the daily stat table/chart breaks completely.
- **`pfblockerng_alerts.php:1782,1850`** — the hourly chart-label builder assumes the same 3-token
  shape (`awk -F ' ' '{print $2 " " $3 "(" $4 ")",$1}'` — month/day/hour). ISO's 2-token date+time
  means `$4` (hour) is empty; chart labels render as `"2026-07-08 (),N"`. **Not** broken by this
  change: `dnsbldatehr`/`dnsbldatehrmin` (`cut -d ':' -f1`/`-f1,2`, same file `:1841`/`:1844`) —
  ISO's date part uses only dashes, so splitting on `:` still correctly isolates the hour — verified,
  not assumed; these need a regression test proving they stay correct, not a code change.

**Lower priority — genuinely optional "everywhere" broadening the user asked for, since the same
"but what if something consumes it" excuse no longer holds anywhere in this codebase (Phase 10):**

| Site | Format today | Has year? | What it's for |
| --- | --- | --- | --- |
| `pfblockerng.inc:5370`/`:5404` (`dnsbl_alias_update()`) | `'M j H:i:s'` | No | DNSBL group "last updated" stat (SQLite `dnsbl.timestamp`); the widget's `pfb_iso_timestamp()` helper (below) already has to GUESS the year from this — a real latent wrong-year bug for a group updated in December and viewed in January |
| `pfblockerng.inc:14133`/`:14137` (`pfBlockerNG_clearsqlite()`) | `'M j H:i:s'` | No | "Last clear" timestamp, shown RAW (no reformatter) in the dashboard widget tooltip — same latent wrong-year exposure, with no safety net at all |
| `pfblockerng.inc:16534` | `'M_j'` | No | `/tmp` debug snapshot filename on a DNSBL feed `unbound-checkconf` failure — zero external consumer, trivial to convert |
| `pfblockerng.php:843` (`gmdate`) | `'D, j M Y H:i:s T'` | Yes | MaxMind version file, displayed on the dashboard widget — already unambiguous, purely cosmetic normalization |
| `pfblockerng_update.php:291`/`:292` | `'Y-m-d H:i'` | Yes | Update page "Last/Next" schedule display — already ISO-shaped, just missing seconds vs the `H:i:s` used elsewhere |
| `pfb_unbound.py:893`/`:898` | `strftime("_%Y%m%-d%H%M%S.log")` | Yes | Unwritable-log rename filename (ownership-repair path) — `%-d` is variable-width, so the filename isn't fixed-width/sortable; low-frequency, zero-risk fix (`%Y%m%d%H%M%S`) |
| `widget.php:390` (`pfb_iso_timestamp()`, `pfblockerng.inc:702`-`:711`) | reformatter, not a writer | n/a | Best-effort `strtotime()`-based reformatter for the (no-year) `dnsbl_alias_update()` value above — becomes dead weight once the source is already ISO; candidate for simplification/removal |

**Explicitly out of scope, never touch:** `www/index.php:101`'s hardcoded
`"Sat, 26 Jul 2014 05:00:00 GMT"` `Expires:` HTTP response header — RFC 7231/2822 format is
protocol-mandated for an actual HTTP header; this is not a candidate for ISO conversion under any
reading of "everywhere." No non-ISO date rendering was found in `src/usr/local/www/`'s JavaScript
(the only date-related JS is cache-busting `new Date().getTime()`, unrelated).

## 2. Decision

### 2.1 Per-area decision table

| Area | Today | ADR-60 |
| --- | --- | --- |
| Timestamp format | 4 different shapes across 10 types, 3 of which are frequently absent, none carrying an unambiguous year except `dnsbl_parse_err`'s ambiguous 2-digit one | **One format, one position, all 10 types**: `Y-m-d H:i:s` (ISO-8601, unambiguous, sorts lexically — already `pfb_logger()`'s existing `$elog`/errlog convention, already pinned by `PfbLoggerIsoTimestampTest.php`), as a fixed **line-start prefix** for the free-text logs and CSV **field 0** for the CSV-shaped logs. Always present, never opt-in. |
| `log`/`extraslog` timestamp | opt-in `NOW` token + same-second dedup that can blank it | Always stamped; `$pfb['pnow']` dedup deleted; any leftover literal `NOW`/`" [ NOW ]"` token in a caller's message string is defensively scrubbed **once, inside `pfb_logger()`** (not per call site — ~30+ call sites keep their existing text unchanged and simply gain a real, unconditional prefix) |
| `errlog` | opt-in via `pfb_logger()`, zero timestamp via the `pfb_open_sqlite()` bypass | Both paths go through the same helper; always stamped |
| `ip_block/permit/matchlog`, IP rows of `unilog` | 'BSD' branch: no year available; 'syslog' branch: year available but discarded | 'syslog' branch: use `strtotime($f[1])`'s already-correct year verbatim — a free fidelity win, zero ambiguity. 'BSD' branch: year-infer (assume current year; roll back one if the resulting date is in the future relative to now — the standard BSD-syslog fix) since pf's raw output never carries one. Both branches emit `date('Y-m-d H:i:s', $ts)`. |
| `dnsbl_parse_err` | `m/j/y H:i:s`, ambiguous | `Y-m-d H:i:s` |
| `dnslog`/`dnsreplylog`, python rows of `unilog` | `make_timestamp()`, no year | `make_timestamp()` gains the year: `"%Y-%m-%d %H:%M:%S"`; `pfb_log_event()`'s twin PHP writer to the same `dnsbl.log` file (`:13725`) converted in lockstep |
| `www/index.php`'s block-page correlation key | `date('M j H:i'/'M j', ...)` grepping `dnsbl.log` | Rebuilt against the new ISO shape (Phase 5) |
| `pfblockerng_alerts.php`'s day-bucket/chart stats | `cut`/`awk` assuming a 3-space-token log line | Rebuilt for the 2-space-token ISO shape (Phase 5); the `:`-split hour buckets are verified unaffected |
| Continuous retention | line-count only (`log_max_<type>`) | **adds** `log_max_days_<type>` (numeric string, default `'0'` = off) — both caps apply independently every tick; whichever is more restrictive wins |
| Calendar-boundary reset (ADR-30) | `log_rotate_<type>` / `log_reset_keep_<type>` / `pfb_log_reset()` / marker file | **removed** — superseded by the continuous age cap above |
| Wider ISO sweep (§1.8, optional) | `dnsbl_alias_update()`/`pfBlockerNG_clearsqlite()` (no year, 2 latent wrong-year bugs), a debug filename, a cosmetic `gmdate`, a seconds-less display, a variable-width Python rename filename | All converted to ISO-8601 (or the closest fixed-width equivalent for filenames); `pfb_iso_timestamp()`'s year-guessing simplified once its source is already ISO |

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
| Log type × writer | `log`, `errlog` (2 writers: `pfb_logger` + `pfb_open_sqlite` bypass), `extraslog`, `ip_blocklog`, `ip_permitlog`, `ip_matchlog`, `dnsbl_parse_err`, `dnslog` (2 writers: Python `make_timestamp()` + PHP `pfb_log_event()` — both write the SAME file), `dnsreplylog`, `unilog` (mixed-format passthrough) | Phases 2-4 |
| `pfb_daemon_filterlog()` input format | `'BSD'` branch, `'syslog'` (RFC-5424) branch | Phase 3 |
| In-repo consumers of the new format | `www/index.php`'s block-page correlation grep; `pfblockerng_alerts.php`'s day-bucket stats (ip/dnsbl/reply) and hourly chart labels; the `:`-split hour buckets confirmed UNAFFECTED (regression test, not a code change) | Phase 5 |
| `log_max_<type>` × `log_max_days_<type>` | off×off, off×set, `nolimit`×off, `nolimit`×set, set×off, set×set (tighter cap wins each direction) | Phase 6 |
| Unparseable-line handling | legacy pre-rework line (no/old-format timestamp) present in a file when age-cutoff first runs | Phase 6 (hostile-input row) |
| Config removal | every one of the 10 `log_rotate_<type>` + 10 `log_reset_keep_<type>` registry entries and sniff paths | Phase 7 |
| Wider ISO sweep (§1.8) | every site in the §1.8 lower-priority table | Phase 10 |

### 2.6 Hostile-input rows for the new age-cutoff parser (Phase 6)

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
- The §1.8 sweep caught two genuine in-repo consumers (`www/index.php`'s block-page correlation key,
  `pfblockerng_alerts.php`'s stat/chart builders) that a naive "just change the two writer functions"
  implementation would have silently broken — found and fixed in the same rollout instead of as a
  post-merge incident.

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
5. `www/index.php`'s DNSBL block page and `pfblockerng_alerts.php`'s Reports/Alerts stat tables and
   charts keep working against the new log format — verified, not merely un-broken by omission.
6. A `www/` change carries Tier-A `ui_render` coverage.
7. All gates green; the §2.3 contract pinned by tests; red→green proof for every behaviour-changing
   phase.
8. Every §1.8 lower-priority site converts to ISO-8601 (or the closest fixed-width equivalent for a
   filename), with `pfb_iso_timestamp()`'s year-guessing simplified once its source is ISO.

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

### Phase 4 — Uniform timestamp for the Python-side logs (and its PHP-side twin writer)

- Prompt: `04_Dns_Logs_Python_And_Php.txt`
- `make_timestamp()`: `"%b %-d %H:%M:%S"` → `"%Y-%m-%d %H:%M:%S"`. **Also** convert `pfb_log_event()`
  (`pfblockerng.inc:13725`) — the PHP-side writer to the SAME `dnsbl.log` file, used in
  Unbound-native-mode DNSBL logging — from `date('M j H:i:s', time())` to the same ISO helper,
  in this same phase (missing this leaves `dnsbl.log` mixed-format between modes, per §1.8). Verify
  `unilog`'s passthrough of `dnslog`/`dnsreplylog` rows inherits the new format with no separate
  change beyond that (it's a straight field copy).
- Tests: `python -m pytest` + `vendor/bin/phpunit` red-before/green-after against Phase 1's oracle for
  `dnslog`/`dnsreplylog` (both writers); the `TypeError`-twice fallback path still returns `""`
  (unchanged, still a real edge case, now just documented); a PHP-side `UnifiedFormatTest.php` case
  confirming a python-sourced `unilog` row shows the new year-bearing format.

### Phase 5 — Fix the in-repo consumers of the new log format

- Prompt: `05_Fix_Format_Consumers.txt`
- Two real, in-repo consumers are byte-coupled to the OLD 3-space-token log shape and BREAK the
  moment Phases 2-4 land (§1.8) — this phase fixes them so the system is internally consistent again
  before the age-cutoff feature (Phase 6) lands:
  - `www/index.php`'s DNSBL block page (`:45`, `:51`, `:52`): rebuild its `dnsbl.log` correlation
    grep key against the new ISO shape.
  - `pfblockerng_alerts.php`'s day-bucket stats (`:1837`) and hourly chart-label builder (`:1782`,
    `:1850`): rebuild for the 2-space-token ISO shape. Confirm (don't just assume) the `:`-split
    `dnsbldatehr`/`dnsbldatehrmin` buckets (`:1841`, `:1844`) are unaffected — add a regression test
    proving it, since this is exactly the kind of "looks unrelated, quietly isn't" claim CLAUDE.md
    says to verify.
- Tests: red-before/green-after for the block page (a synthetic ISO-format `dnsbl.log` line, assert
  the correlation now matches and the real detail — not `-` placeholders — renders); red-before/
  green-after for the Reports day-bucket grouping and the chart label shape; a regression test
  proving the hour-only buckets are unaffected. Tier-A `ui_render` for the block page and the Reports
  page.

### Phase 6 — `log_max_days_<type>`: the age-cutoff cap

- Prompt: `06_Age_Cutoff.txt`
- Register `log_max_days_<type>` (10 keys, default `'0'`, mirroring `log_max_<type>`'s loop shape) in
  `pfb_cfg_registry()` + the sniff `$registeredPaths`. Restructure `pfb_log_mgmt()` so `nolimit` on
  `log_max_<type>` no longer short-circuits the function — the age cap evaluates independently. Add
  the age-cutoff pass: over the `tail -n N` candidate, drop the leading run of lines older than
  `now - log_max_days_<type>` days (parse the now-uniform `Y-m-d H:i:s` prefix/field); unparseable
  lines are treated as expired.
- Tests: every §2.5/§2.6 coverage-matrix and hostile-input row; red-before (today's `pfb_log_mgmt()`
  has no age cap at all — the new test fails against pre-Phase-6 code) / green-after; inode +
  ownership preserved (both plain and chrooted python-log paths); a failed `tail`/`cat` still never
  blanks the log.

### Phase 7 — Retire `pfb_log_reset()` / ADR-30's mechanism

- Prompt: `07_Retire_Adr30.txt`
- Delete `pfb_log_reset()`, `pfb_log_rotate_period()`, `pfb_log_should_reset()`, the marker
  parse/serialize helpers, and the `log_rotate.last` marker-file handling. Remove the
  `log_rotate_<type>`/`log_reset_keep_<type>` registry entries + sniff paths. Remove the
  `pfb_log_reset()` call in `pfblockerng_tick()`. Delete `tests/php/LogRotateScheduleTest.php` +
  `LogRotateResetTest.php`. Grep-gate: no remaining reference to `log_rotate_`/`log_reset_keep_`/
  `pfb_log_reset`/`log_rotate.last` outside `.ADRs/` (historical mentions are fine).
- Tests: full suite green with the deletions; the grep-gate command + its (empty) output pasted in
  the handoff.

### Phase 8 — Log Settings UI

- Prompt: `08_Ui.txt`
- `pfblockerng_general.php`: remove the `log_rotate_<type>`/`log_reset_keep_<type>` `Form_Select`
  controls; add a `log_max_days_<type>` numeric `Form_Input` next to each `log_max_<type>` field,
  with help text. Load/save via `$pconfig`/`$_POST`, reading through `PfbConfig`.
- Tests: Tier-A `ui_render` (page loads, no PHP error, the new fields present, the removed ones
  gone).

### Phase 9 — Smoke + validation + docs

- Prompt: `09_Smoke_And_Validation.txt`
- Live-VM smoke (ADR-04): seed a log with lines whose timestamps straddle a `log_max_days_<type>`
  cutoff (mix of expired/current), run the cron tick, assert only the expired prefix is dropped,
  inode + ownership preserved, `log_max_days_<type>='0'` leaves size-only behaviour unchanged, the
  retired ADR-30 config keys/UI controls are gone, the DNSBL block page still shows real detail (not
  `-` placeholders), and the Reports/Alerts stat tables/charts still group correctly. Update any
  user-facing help text/docs referencing the old scheduled-reset feature. Flip Status → Accepted on
  green.

### Phase 10 — Wider ISO-8601 sweep (§1.8 lower-priority sites)

- Prompt: `10_Wider_Iso_Sweep.txt`
- Convert every §1.8 lower-priority site to ISO-8601 (or the closest fixed-width equivalent for a
  filename): `dnsbl_alias_update()` (`:5370`/`:5404`), `pfBlockerNG_clearsqlite()`
  (`:14133`/`:14137`), the `/tmp` debug filename (`:16534`), `pfblockerng.php`'s MaxMind `gmdate`
  (`:843`), `pfblockerng_update.php`'s schedule display (`:291`/`:292`), and `pfb_unbound.py`'s
  rename filename (`:893`/`:898`). Simplify/remove `pfb_iso_timestamp()`'s (`pfblockerng.inc:702`-
  `:711`) year-guessing logic now that its source (`dnsbl_alias_update()`) is already ISO. Do NOT
  touch `www/index.php:101`'s hardcoded HTTP `Expires:` header — protocol-mandated, explicitly
  out of scope (§1.8).
- Tests: for `dnsbl_alias_update()`/`pfBlockerNG_clearsqlite()` — a red-before/green-after proving
  the December-updated/January-viewed wrong-year bug is actually fixed (construct a fixture that
  straddles a year boundary); for the rest, straightforward before/after format assertions; a test
  proving `pfb_iso_timestamp()`'s simplified form still round-trips correctly (or that its removal
  doesn't break the widget, if you remove it entirely — your call, justify in the handoff).

## 7. Definition of done

**Phases 1-9 gate Status → Accepted** (the core ask: uniform timestamps, the age-cutoff cap, ADR-30's
retirement, and the in-repo consumers that would otherwise break). Phase 10 (§1.8's lower-priority
sweep) is a follow-on that lands afterward and does not block Accepted — it's requested normalization
of sites outside the 10 log types, not part of the retention feature's correctness contract.

- Phases 1-9 landed; `vendor/bin/phpunit` + `phpcs` + `phpstan` + `python -m pytest` + `ui_render`
  green; the §2.3 contract pinned; the §2.5/§2.6 coverage matrix fully ticked (Phase 10's row
  excepted — it ticks when Phase 10 lands).
- Live-VM smoke (CE + Plus fan-out) green for the age-cutoff trim, inode/ownership preservation,
  and `nolimit`-independence (`tests/smoke/test_log_age_retention.py`, run 28964455515); Tier-A
  `ui_render` (CE + Plus) green for the Reports/Alerts stat tables/charts and the redesigned Log
  Settings page (run 28964459756). The DNSBL block page's fix is proven off-box
  (`tests/php/LogFormatConsumersTest.php`'s real red/green execution of the correlation
  grep/regex-guard pipeline) but has **no automated live-VM proof** — `www/index.php` is served
  by a separate DNSBL-VIP-sinkhole listener outside the webConfigurator Tier-A harness, and no
  Tier-B (`ui_e2e`) case exists yet to reach it (tracked: issue #1013). Item 4 of the manual
  checklist below is this ADR's real, currently out-of-CI confirmation for that page.
- **Manual smoke checklist (owner: maintainer — out-of-CI, real multi-day-old data):**
  1. Set `log_max_days_ip_blocklog=7` on a box with more than 7 days of real block history; confirm
     only lines older than 7 days are dropped at the next tick, inode (`ls -i`) unchanged, a remote
     syslog shipper does not re-ship.
  2. Confirm a box that never touches `log_max_days_<type>` sees byte-identical trim behaviour to
     before this ADR (line-count only).
  3. Confirm an upgrade from a build with `log_rotate_ip_blocklog=daily` set no longer resets that
     log on any calendar boundary (the config key is now inert).
  4. Trigger a real DNSBL block, confirm the block page shows real Type/Group/Evaluated/Feed detail
     (not `-` placeholders).
  5. Confirm the Reports/Alerts daily stat table and hourly chart still group correctly on real data.

**Reject criteria (Phases 1-9).** Abandon/redesign if: (a) the age-cutoff scan cannot be reconciled
with the inode-preserving trim (it should — same `tail`/`cat` shape, one extra filter pass); or (b)
the BSD-branch year-inference proves unreliable enough in practice (e.g., a box with a badly-skewed
clock) that it produces materially wrong retention decisions — in that case, fall back to keeping the
year-less format for the `'BSD'` branch only and treat every `'BSD'`-sourced line as needing the
line-count cap (not the age cap) until a better source of truth exists.

**Phase 10 (follow-on, does not gate Accepted):** all §1.8 lower-priority sites converted; the two
genuine latent wrong-year bugs (`dnsbl_alias_update()`, `pfBlockerNG_clearsqlite()`) proven fixed with
a year-boundary test; `pfb_iso_timestamp()` simplified or removed with the widget still correct;
`www/index.php:101`'s HTTP header untouched (verified, not just "didn't get to it").

## 8. Post-merge amendments (2026-07-09 — the 48h review, issues #1047-#1057)

Reality overturned four pieces of this ADR after merge (PR #1005). The sections above are
left as written for the historical record; **this section is the authoritative correction.**

1. **The §2.1/§2.4/Phase-2 defensive scrub NO LONGER EXISTS — and was a spec defect.**
   Scrubbing the bare substring `NOW` corrupts legitimate message content (`SNOWSHOE` →
   `SSHOE`) — found by the PR #1005 review (#1008) and removed in 958e679f, which deleted
   the call-site tokens instead. §2.4's "call-site cleanup is cosmetic, deferred" was
   premised on the scrub existing; once the scrub was removed that deferral became
   load-bearing, and the incomplete call-site enumeration (one file instead of the tree)
   shipped #1047 (9 leftover `[ NOW ]` tokens in `pfblockerng.php`, fixed with a
   zero-hit tree-grep tripwire test). Spec lesson: the ADR wrote hostile-input rows for
   the age-cutoff parser (§2.6) but none for the scrub — its other new string transformer.
2. **§2.1's "fixed line-start prefix" missed the message-shape axis.** The §2.5 matrix
   enumerated log type × writer but not full-line vs sub-line fragment writes
   (`pfb_logger('.')`, 23 sites tree-wide), so fragments were stamped mid-line (#1054).
   Corrected: `pfb_logger()` stamps only at the start of a physical line (per-target
   beginning-of-line tracking); the §2.3-4 contract's unit is the LINE, not the write.
3. **§3's "the age-cutoff pass is cheap" was false for a row of this ADR's own matrix.**
   For `nolimit` × age-cap (§2.2 independence) there is no small `tail` candidate — the
   shipped implementation copied the whole unbounded log every idle tick (#1052).
   Corrected: a first-line age probe skips the pass when nothing is expired.
4. **§2.6's legacy-line hostile row was applied to the trim only.** The same "realistic
   upgrade scenario" (mixed legacy + ISO lines) was never propagated to the Phase-5
   consumers, so the Reports/Alerts bucketing mis-buckets legacy lines until the logs
   roll (#1057). Corrected: the bucketing pipelines skip non-ISO lines (older by
   construction than every ISO line).

Related, same window: the array-path short-write gap the stream sibling already guarded
(#1053) and the Log Settings absent-POST-key warning (#1056).

**2026-07-13 — issue #1109: a hysteresis margin on both trim caps.**

1. **`pfb_log_trim_margin_pct` — a single global percent (0-1000, default `'0'`), applying
   uniformly to both caps.** High-water **trigger**, low-water **cut**: the margin only
   delays *when* a trim fires (the file is left alone until its line count or oldest-line
   age exceeds `cap × (1 + margin/100)`); once it fires, the trim still cuts back to the
   **exact** cap, exactly as before. `margin=0` reproduces today's trigger point verbatim.
   Deliberately **not** per-log-type and **not** per-cap-unit: one field, both caps.
2. **Why a percentage, not an absolute count.** One global knob has to widen both a *line*
   count (Max lines) and a *days* count (Max days) with the same value; a percentage is the
   only unit expressible against either. An absolute offset (`+N lines` / `+N days`) would
   need two separate fields, reintroducing the per-cap-unit split item 1 rejects.
3. **The `margin=0` nuance — a byte-identical CONTENT change in I/O behaviour, not output.**
   §2.2's original line high-water was implicit at "any excess" per tick; `pfb_log_trim_needed()`
   now checks line count strictly `>` the cap (matching the age arm's existing strict `>`), so
   a file already sitting exactly at its cap is no longer rewritten every idle tick. The
   trimmed log's CONTENT is unchanged byte-for-byte in either case; only a redundant no-op
   full-file rewrite (and its mtime bump) is elided. Nothing in this codebase keys on a log
   file's mtime — ADR-42's content hashing covers feed sidecars, not logs.
4. **`pfb_log_age_nolimit_pass_needed()` renamed to `pfb_log_age_trim_needed()`.** #1052's
   probe (2026-07-09 item 3 above) was framed `nolimit`-only; the margin makes it the general age-trim
   decision for every type, `nolimit` or capped. **`pfb_log_trim_needed()` is now the single
   guard called from both `pfb_log_mgmt()` branches**, replacing the two duplicated #1052
   skip lines with one call each; `margin=0` on the age arm is exactly #1052's original case.
5. **Read cost is bounded and asymmetric with the write it replaces.** The line high-water
   probe reads the whole file once per tick to decide; that is a read, not a write. Flash/SSD
   wear is write-dominated, so a per-tick full-file read traded for an elided per-tick
   full-file write is the intended trade, not an oversight. **`pfb_log_line_count()` counts a
   line the way `tail(1)` does** — an unterminated trailing chunk is a line, not a fragment —
   because the count gates a `tail`-based rewrite and the two must agree. Counting bare `\n`
   bytes undercounts a log left mid-line (the state `pfb_logger('.', 1)`'s progress fragments
   leave, and what `pfb_logger_target_starts_at_bol()` exists to detect), which reads as "at
   cap" when the log is really over it and silently skips a trim the write path would perform.
6. **Rejected alternatives (do not re-litigate).** In-place head eviction (`memmove` +
   `ftruncate` on the line cap) was rejected: it opens a torn-write window §1.5 doesn't cover
   today and is a materially different write path from the existing tail-and-replace trim.
   A calendar-boundary or marker-file scheme (e.g. "only trim once per UTC day") was rejected
   because it reintroduces exactly the mtime/marker-file fragility §1.1 and §2.1 deleted this
   ADR to get away from, plus ADR-30's clock-skew sawtooth (§1.2).
