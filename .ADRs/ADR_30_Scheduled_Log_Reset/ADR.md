# ADR-30: Scheduled (calendar-boundary) reset of pfBlockerNG report logs

- **Status:** **Proposed** (2026-06-19)
- **Date:** 2026-06-19
- **Branch:** `adr/30-scheduled-log-reset` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` — pure period/decider helpers; `PfbConfig` registry entry for the new field
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — `pfb_log_mgmt()` neighbourhood; new `pfb_log_reset()`; the in-chroot/ownership log handling it reuses
  - `src/usr/local/www/pfblockerng/pfblockerng.php` — the cron tick that already calls `pfb_log_mgmt()` (`:771`)
  - `src/usr/local/www/pfblockerng/pfblockerng_general.php` — the **Log Settings** UI section (`:354`)
  - `tests/php/` — unit tests for the deciders + the registry round-trip/rollback
  - `tests/smoke/` — live-VM behaviour (boundary reset, inode preserved, off no-op)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). Logs are written by both PHP (IP-side) and the chrooted Unbound Python module (DNS-side); the reset is performed by PHP only, mirroring the existing `pfb_log_mgmt()` truncation path.
- **Test surface:** `vendor/bin/phpunit` + `vendor/bin/phpcs` + `vendor/bin/phpstan` (PR gate); `python -m pytest` (tooling); `tests/smoke` (ADR-04 live VM); `ui_render` (Tier A PR gate)

Originates from **issue #341** (Redmine #14669): *"Allow the option to set logrotate (daily/weekly/monthly) … because the logs do not roll over on a schedule the reporting data contains weeks of stale data."* The user consumes pfBlockerNG report statistics and needs the report logs to reflect only the current period.

---

## 1. Context (today)

### 1.1 How logs are managed now (measured, not assumed)

- Log management is **size-based only**. `pfb_log_mgmt()` (`pfblockerng.inc:1750`) iterates the 10
  pfBlockerNG log types — `log, errlog, extraslog, ip_blocklog, ip_permitlog, ip_matchlog, dnslog,
  dnsbl_parse_err, dnsreplylog, unilog` — and trims each to a per-log **max-lines** cap
  (`log_max_<type>`, default **20000**; `'nolimit'` opts out). It **truncates in place to preserve
  the inode** (`tail -n N > tmp; cat tmp > log`), deliberately — `mv` would change the inode and a
  remote syslog shipper keyed on `(inode, offset)` would re-send the whole file (#264/#280). The DNS
  python logs (`dnslog, dnsreplylog, unilog`) are handled through the Unbound **chroot**
  (`/var/unbound`) and re-`chown`ed to `unbound` after truncation.
- It runs **once per cron tick** — `pfblockerng.php:771` calls `pfb_log_mgmt()` at the end of the
  feed-update cron pass (the same place ADR-19's `pfb_software_update_check()` runs) — and again on
  a settings-save path (`pfblockerng.inc:9596`).
- **There is no time/calendar dimension.** No daily/weekly/monthly boundary, no rolled/archived
  copies, no schedule knob. Report statistics (Reports/Alerts tabs parse these same files) therefore
  accumulate until the line cap is hit, never rolling over on a calendar boundary — exactly the
  reporter's complaint.
- The **Log Settings (max lines)** UI section (`pfblockerng_general.php:354`) exposes the per-log
  `log_max_*` selects; values load/save through `$pfb['gconfig']` (the General settings blob).
- Config access for new scalar fields is **mediated by `PfbConfig`** (ADR-29) — a registered key is
  read via `PfbConfig::read($key)` and written via `PfbConfig::write($key, $v)`; the
  `RequireConfigGateway` sniff enforces it.

### 1.2 Load-bearing constraints

- **Inode + ownership preservation is a hard contract** (#264/#280): any reset must truncate in place
  (`: > file` / `cp /dev/null file`), never `mv`/recreate, and must keep `unbound` ownership for the
  chrooted python logs. The chroot path translation in `pfb_log_mgmt()` is the reference.
- **`config.xml` stored values are hard-frozen** (ADR-28 §2.2): the new field must add a *new* key
  with a sane default-on-absent; it must not alter any existing stored value, and it must round-trip
  losslessly through `PfbConfig` (ADR-29 rollback contract).
- **Opt-in, zero default impact.** Existing installs must behave **identically** until the operator
  turns the feature on — the field defaults to *off*.
- **Cron cadence is operator-defined** (`pfb_min`/cron hour). The schedule check must therefore be
  **boundary-gated and idempotent** — driven by "has the calendar period changed since the last
  reset?", not by assuming any particular tick frequency — so it fires exactly once per period
  regardless of how often the cron runs, and never on a settings-save.
- **No live Unbound/pfSense in CI** except the ADR-04 smoke VM; the off-box PHPUnit suite loads the
  real `.inc` via shims/doubles.

### 1.3 Premise check (this is NOT an ADR-01-style bet)

No performance premise — a once-per-tick string compare and an occasional `truncate` are
unmeasurably cheap. The justification is **functional**: give operators calendar-fresh report data.
The risk to weigh is **scope** (a config field + UI + cron wiring + a new public behaviour) and
**the inode/ownership contract** — both contained by the phasing (§6), the pinned contract tests
(§2.3), and the explicit reject path (§7).

## 2. Decision

Add an **opt-in scheduled reset**, **per log type — mirroring the existing per-log line cap**: a new
`log_rotate_<type>` setting (`off` | `daily` | `weekly` | `monthly`, default `off`) for **every log
that already has a `log_max_<type>` limit**. On each cron tick, each log whose schedule is set is
**truncated to empty when its calendar period has rolled over** since its last reset — preserving
inode + ownership exactly like today's line-cap trim, and leaving the line-cap trim itself unchanged.
Each log is independent: just as today each log has its own line limit, each gets its own (or no)
schedule. "Rotation" here means **reset (truncate to empty)**, not archived copies and not pfSense
`newsyslog` — chosen deliberately (see §2.4) because the reported need is *fresh statistics for the
current period*.

### 2.1 Per-area decision table

| Area | Decision |
| --- | --- |
| **Config fields (per-log)** | One registered key **`log_rotate_<type>`** *per log type that already has a `log_max_<type>` line limit* — mirroring that structure exactly: `log_rotate_log, log_rotate_errlog, log_rotate_extraslog, log_rotate_ip_blocklog, log_rotate_ip_permitlog, log_rotate_ip_matchlog, log_rotate_dnslog, log_rotate_dnsbl_parse_err, log_rotate_dnsreplylog, log_rotate_unilog` (10). Each: stored vocabulary `{'off','daily','weekly','monthly'}`, default `'off'`, plain-string (identity) adapter in `PfbConfig` — round-trips losslessly. A per-log schedule, just like the per-log line cap. |
| **Schedule decider** | Pure `pfb_log_rotate_period(string $schedule, int $ts): string` → a period key (`'YYYY-MM-DD'` daily, ISO `'YYYY-Www'` weekly, `'YYYY-MM'` monthly, `''` when off). Pure `pfb_log_should_reset(string $schedule, string $last_key, int $now_ts): bool` → `off ⇒ FALSE`, else `period(now) !== $last_key`. No I/O — the unit-test seam; called **once per log** with that log's own schedule + marker entry. |
| **State marker (per-log)** | Last-reset period key **per log type** in a small state file **`/var/db/pfblockerng/log_rotate.last`** (NOT `config.xml` — avoids per-period config churn and the freeze concern), one `<type>=<period-key>` entry per line. A missing/garbled entry ⇒ that log treated as "never reset" ⇒ first eligible tick resets it once and writes its entry. Parse/serialize via pure, unit-tested helpers. |
| **Reset action** | New `pfb_log_reset()`: iterate **the same log set `pfb_log_mgmt()` manages**; for each log read its own `log_rotate_<type>` + its marker entry, and when `pfb_log_should_reset()` is true **truncate that log to empty in place** (inode-preserving), reusing `pfb_log_mgmt()`'s chroot-path + `chown unbound` handling for the python logs, then update that log's marker entry. Each log independent. |
| **Which logs** | **All log types that have a `log_max_<type>` limit** — the full `pfb_log_mgmt()` set (`log, errlog, extraslog, ip_blocklog, ip_permitlog, ip_matchlog, dnslog, dnsbl_parse_err, dnsreplylog, unilog`), each gated by its **own** `log_rotate_<type>`. Default off ⇒ a log is reset only when its schedule is set. |
| **Cron wiring** | Call `pfb_log_reset()` from the cron tick **right after** `pfb_log_mgmt()` (`pfblockerng.php:771`). Per-log boundary-gated ⇒ a no-op for every log except those whose period just rolled over. Not called on the settings-save path. |
| **UI** | A schedule `Form_Select` (`Off/Daily/Weekly/Monthly`, name `log_rotate_<type>`) added **next to each per-log max-lines select** in the **Log Settings** section (`pfblockerng_general.php:354`), loaded/saved via `$pfb['gconfig']` like its line-limit sibling but read through `PfbConfig`. Brief help text. |
| **Line-cap trim** | **Unchanged.** The reset is purely additive; between resets each log's existing `log_max_<type>` cap still bounds growth. |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before wiring)

1. **Default off ⇒ zero behaviour change.** With every `log_rotate_<type>` absent/`'off'`, no log is
   ever truncated by the new path; `pfb_log_mgmt()` behaves byte-for-byte as today.
2. **Inode + ownership preserved on reset** (#264/#280): a reset log keeps its inode and its
   `unbound`/owner — never recreated.
3. **Idempotent, once-per-period, per log:** within a single calendar period a given log resets at
   most once, regardless of cron frequency; a second tick in the same period is a no-op for it.
4. **Per-log independence:** resetting one log on its boundary never affects another; each log
   follows only its own `log_rotate_<type>` and its own marker entry.
5. **`config.xml` untouched for existing keys; every new key round-trips** through `PfbConfig`
   (`write(read(v)) == v` for every vocabulary value; absent ⇒ `'off'`).

### 2.3 Explicitly kept / out of scope

- **Archived/rolled copies** (`.0/.1`, keep-N) and **pfSense `newsyslog`** integration — rejected
  (§2.4); revisit only if operators ask for retained history.
- The **line-cap** mechanism and its values — untouched (the schedule sits alongside it).
- **Python/shell** — no change; the reset is PHP-only (mirrors `pfb_log_mgmt()`).

### 2.4 Alternatives considered (and why rejected)

- **Rotate + keep N archives (newsyslog-style):** preserves history but adds archive files, disk
  budgeting, and a second inode/ownership story for the chrooted python logs — and the stats parser
  reads only the live file, so archives don't serve the stated need. Heavier for no benefit *to this
  request*.
- **Hook into pfSense `newsyslog`:** least custom code in theory, but pfBlockerNG logs are not
  syslog-managed and the Reports/Alerts tabs parse the files directly; handing rotation to
  `newsyslog` risks inode churn (the #264/#280 regression) and a config surface outside the package.

## 3. Consequences

**Positive**

- Report statistics reflect the chosen period; the #341 staleness complaint is resolved.
- Opt-in + default-off ⇒ no surprise for existing installs.
- The size-cap safety net stays; the two mechanisms compose.
- The decider is a pure, fully-unit-tested function; the risky I/O reuses a proven path.

**Negative / risks**

- A wider config + UI surface: one `log_rotate_<type>` per log (10) and a schedule select per Log
  Settings row — more to register, render, and support. Contained by the per-log pattern already in
  place for `log_max_<type>` (the same shape, registered/tested/rendered the same way).
- A reset **discards** that log's current-window data at the boundary (by design — "reset", not
  "archive"); an operator wanting history must export before the boundary. Called out in the help
  text.
- Wall-clock/timezone dependence: the period key uses the box's local time; a TZ change mid-period
  can shift a boundary once. Acceptable (matches operator expectation of "local daily/weekly").

## 4. Requirements (acceptance)

- A per-log schedule (`log_rotate_<type>`) selectable as Off/Daily/Weekly/Monthly next to each log's
  max-lines control in **Firewall → pfBlockerNG → General → Log Settings**, default Off, persisted
  across upgrade.
- With a log's schedule set, that log is emptied **once** when its period rolls over, inode +
  ownership intact, on the next cron tick after the boundary.
- With Off, no new truncation occurs for that log.
- Each log follows only its own schedule (per-log independence).
- All gates green; the contract (§2.2) pinned by tests.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()/exit()` in library code.
- Each new registered field (one per log type) goes through **`PfbConfig`** (ADR-29): a registry
  entry with its `since`, the sniff `$registeredPaths`, plus `CfgGatewayTest` and `RollbackContractTest`.
- Inode-preserving truncation only; reuse the chroot/ownership handling — no `mv`/recreate.
- Test-coverage mandate: every decider branch (each schedule × boundary-crossed/not, off, absent
  marker), before-and-after, no coverage theater.
- ADR implementation uses the full worktree + rebase-only-PR flow (it touches `src/`+`tests/`).

## 6. Action plan

> Each phase is one commit, leaves `python -m pytest` + `vendor/bin/phpunit` green, and is
> behaviour-preserving until the wiring phase flips the (default-off) feature on. Early phases are
> the preparatory, test-first, dormant-code groundwork; the risky cron wiring lands only after the
> decider and the config field are pinned.

### Phase 1 — Pure schedule deciders + tests

- Prompt: `01_Deciders.txt`
- Add `pfb_log_rotate_period()` + `pfb_log_should_reset()` (pure, no I/O) to `pfblockerng_extra.inc`.
- PHPUnit `tests/php/LogRotateScheduleTest.php`: every schedule (`daily/weekly/monthly`) with the
  period key on both sides of a boundary; `off ⇒ FALSE`; absent/empty `$last_key ⇒ TRUE`; ISO-week
  edge (year boundary). Behaviour-preserving — functions are dormant (uncalled) this phase.

### Phase 2 — Register the per-log `log_rotate_<type>` config fields

- Prompt: `02_Config_Field.txt`
- Add one `log_rotate_<type>` per log type (10, mirroring the `log_max_<type>` set) to
  `pfb_cfg_registry()` (section = General settings, default `'off'`, identity adapter, `since` = the
  release introducing them); add each full path to the sniff `$registeredPaths`; extend
  `CfgGatewayTest` (round-trip + default-absent) and `RollbackContractTest` (vocabulary) and the
  inventory test. Dormant — no reader/writer yet.

### Phase 3 — `pfb_log_reset()` + cron wiring

- Prompt: `03_Reset_And_Cron.txt`
- Add `pfb_log_reset()` (for each log in the `pfb_log_mgmt()` set: read its `log_rotate_<type>` via
  `PfbConfig::read`, read its marker entry, call the Phase-1 decider, and on a rolled boundary
  truncate that log in place inode-preservingly reusing the `pfb_log_mgmt()` chroot/ownership
  handling, then update its marker entry). Wire it after `pfb_log_mgmt()` at
  `pfblockerng.php:771`. Extract the marker parse/serialize into testable seams
  where practical; unit-test the selection + marker round-trip. Keep PFBL-01 + `RequireConfigGateway`
  sniffs green. **This phase flips the feature on (still default-off).**

### Phase 4 — Log Settings UI control

- Prompt: `04_Ui.txt`
- Add a `log_rotate_<type>` `Form_Select` next to each per-log max-lines control in the Log Settings
  section, with help text; load/save via `$pfb['gconfig']`, reading through `PfbConfig`. UI render
  proof (no PHP error; controls present).

### Phase 5 — Smoke + validation + docs

- Prompt: `05_Smoke_And_Validation.txt`
- Live-VM smoke (ADR-04): set a schedule on some logs + a stale marker entry (or a stale period), run
  the cron entry, assert those logs are emptied AND inode preserved AND a log left Off is untouched
  AND its marker entry updated; assert a same-period re-run is a no-op. Add the §7 manual checklist;
  update any user-facing doc/help. Flip Status → Accepted on green.

## 7. Definition of done

- All five phases landed; `vendor/bin/phpunit` + `phpcs` + `phpstan` + `python -m pytest` +
  `ui_render` green; the §2.2 contract pinned.
- Live-VM smoke (CE + Plus fan-out) green for the boundary-reset + inode-preserved + off-no-op +
  per-log-independence cases.
- **Manual smoke checklist (owner: maintainer — out-of-CI, real calendar rollover):**
  1. Set `log_rotate_ip_blocklog=daily` (leave others Off); confirm that log empties at the first
     cron tick after local midnight and **not** before; the Off logs are untouched; the inode (via
     `ls -i`) unchanged and a remote syslog shipper does **not** re-ship.
  2. Repeat with `weekly` (ISO week boundary) and `monthly` on different logs to confirm per-log
     independence.
  3. Toggle the log back to Off; confirm no further resets.

**Reject criteria.** Abandon/redesign if: (a) an inode-preserving reset cannot be reconciled with the
chroot/ownership handling (it should — `: > file` truncates in place); or (b) the feature cannot be
made genuinely opt-in/zero-default-impact. (The log-set question is **settled**: a per-log schedule
over the full `pfb_log_mgmt()` set, mirroring the per-log line cap — issue #341 maintainer decision.)
