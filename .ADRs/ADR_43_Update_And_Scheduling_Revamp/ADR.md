# ADR-43: Unify the reload-trigger API, consolidate cron onto one due-ledger tick, and revamp the Update page

- **Status:** **Implemented (pending live-VM fan-out)** (2026-06-25) — all 7 phases landed on
  `adr/43-update-and-scheduling-revamp`; off-appliance suites green. Flips to **Accepted** on the
  green CE+Plus live-VM fan-out of the ADR-43 smoke/UI cases (see RESULTS/07).
- **Date:** 2026-06-25
- **Branch:** `adr/43-update-and-scheduling-revamp` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming"). / **Component(s):** the trigger/scheduling layer
  and its operator surface — `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (the cron-install
  region of `sync_package_pfblockerng`, ~`:15125`–`:15290`; the trigger map `pfb_trigger()`,
  `:3170`; the reload entrypoint `sync_package_pfblockerng($cron)`, `:10916`),
  `src/usr/local/www/pfblockerng/pfblockerng.php` (the CLI verb dispatch behind the cron jobs **and**
  the GUI Update tab), with the HA-sync caller and the smoke harness `PFB_CLI` migrated onto the new
  API.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the trigger API, the due-ledger, the cron
  generator, and the GUI; POSIX `sh` only if a tick helper needs it (not expected). No Python.
- **Test suite:** `tests/php/` (PHPUnit — the off-appliance pure helpers: the trigger map, the
  due-ledger date math, the cron generator), `tests/smoke/` (live-VM ADR-04 — actual cron firing,
  catch-up, apply-on-change, the ADR-12 hook trigger context), `tests/smoke/ui/` (ADR-14 Tier A
  **and** Tier B — the revamped Update page).

> **HARD PREREQUISITE — this ADR is gated on ADR-40 and ADR-42 being _implemented_, not merely
> Proposed.** ADR-43 is the scheduling/trigger/operator layer **above** detection (ADR-42) and apply
> (ADR-40); it **consumes** both and deliberately does not re-decide them. Two of its decisions only
> hold once they land: "force vs reuse" has crisp meaning only against ADR-42's real change-detector
> (§2.B), and dropping a standalone apply-schedule in favour of **apply-on-change** is only safe once
> ADR-40 + ADR-10 make apply cheap (§2.D). If 40 or 42 is **rejected or materially re-scoped**, §2.B
> and §2.D must be revisited before implementation (see §7 reject/revisit criteria). Do **not** start
> `/adr-phase 43 1` until 40 and 42 are on `devel`.

## 1. Context

### 1.1 Today

**Scheduling is cron(8), driven by many independent jobs.** pfSense has **no PHP task scheduler** —
packages schedule work by registering crontab entries via `install_cron_job()` (→
`installedpackages/cron` → regenerated `/etc/crontab`). `sync_package_pfblockerng()` installs a
_family_ of jobs (all in `pfblockerng.inc:15125`–`:15290`), each with its own cadence:

| Job (`pfblockerng.php <verb>`) | Cadence today | How it is scheduled | Note |
| --- | --- | --- | --- |
| `cron` (feed update) | hourly → once-a-day | `pfb_interval` (1/2/3/4/6/8/12/24h) → `pfb_cron_base_hour()` spreads hours; `pfb_min` | the main pass |
| `dcc` (MaxMind / TOP1M / ASN) | **daily**, **random hour** (`rand(0,23)`), min 0 | fixed daily | jitter spreads upstream load |
| `bl` (DNSBL "blacklist" feeds) | **daily or weekly**, **random hour**, min 0 | `blacklist_freq` (`Weekly` → wday 7) | jitter spreads load |
| `ss_refresh` (SafeSearch CNAME) | **every 15 min** (`*/15`) | fixed | DNS **re-resolution**, not a feed pull (issue #149) |
| `clearip` / `cleardnsbl` (counter reset) | daily/weekly 00:00 | widget knob | cosmetic — **out of scope** (ADR-30 territory) |

**The reload entrypoint is one overloaded verb-string.** Every trigger funnels into
`sync_package_pfblockerng($cron)` (`inc:10916`). The `$cron` string is doing **three** unrelated
jobs at once — trigger identity, reload scope, and force-vs-reuse — with none of them named:

- **`cron`** → the scheduled pass; respects feed fingerprints (an unchanged feed is reuse-cached, not
  reparsed → "no change" reported). The GUI **Update** button **also** calls
  `sync_package_pfblockerng('cron')` — _indistinguishable_ from the scheduled cron inside the pass
  (`inc:3174`–`:3182`).
- **`updateip` / `updatednsbl`** → **force**-reload one side (always reparse, bypass the reuse gate).
- **Force buttons / `force_ip_refetch()`** → set side-channel flags that further mutate reuse.

`pfb_trigger()` (`inc:3170`–`:3195`) already exists to _map_ `$cron` → a stable `PFB_TRIGGER`
(`cron`/`update`/`force`) for the ADR-12 hook env — proof the overload is real and already needs
untangling. The name never reveals **scope** (ip/dnsbl/both) or **force** (reparse vs reuse); both
are implicit and discovered only by reading the body.

**The GUI Update page** (`www/pfblockerng/pfblockerng.php`, Update tab) exposes Force / Update /
Cron / Reload controls + the update-log pane on top of these verb strings; the controls don't make
clear what each actually does (force-reparse vs reuse, which side), and the log presentation is
dated.

**Change detection & apply are being reworked out from under this layer.** ADR-42 replaces the
mtime+md5 detector with content hashing + conditional GET ("did it change?"); ADR-40 makes the IP
pf-table apply membership-gated and delta-based ("apply cheaply"). ADR-43 does **not** touch either
— it owns _when the system looks_ and _how an operator/cron asks it to_.

### 1.2 The problem

1. **Two schedules that must be mentally reconciled.** A feed carries its own frequency
   (`freq`/`updatefreq`) while the pfBlockerNG cron fires on a _separate_ global cadence
   (`pfb_interval`); a feed is only actually checked when the global cron happens to run. Operators
   must align two knobs to reason about "when does feed X refresh", and the relationship is
   non-obvious. The same split repeats per job family (`dcc`/`bl` have their own cadences again).
2. **No catch-up after downtime.** Detection is gated on cron _firing_ at an hour bucket plus a
   `pfb_dailystart` hour. If the box is off during the window, the window is simply **missed** — the
   feed waits a full cycle. There is no record of "feed X was due at T and never ran", so a missed
   refresh cannot be recovered on the next boot/tick.
3. **The trigger verb is an un-named 3-way overload.** `$cron` conflates trigger identity, scope, and
   force/reuse. New callers guess; `pfb_trigger()` exists only to _recover_ the trigger the string
   threw away. Adding a fourth concern (e.g. a per-side force) means another implicit string
   convention.
4. **A fleet of near-duplicate cron blocks.** Four `install_cron_job` families (`cron`/`dcc`/`bl`/
   `ss_refresh`) with copy-pasted scheduling logic, two of them re-rolling `rand(0,23)` jitter
   inline, plus the existence/teardown bookkeeping (`pfblockerng_cron_exists`) for each. Adding a new
   periodic concern means a fifth copy.
5. **An Update page bolted onto the overload.** Its controls inherit the verbs' ambiguity, so the UI
   cannot present a clean "what will this do" to the operator.

### 1.3 Load-bearing facts (verified this session, not assumed)

- **No PHP scheduler exists; scheduling is cron via `install_cron_job()`** (`inc:15147` et al.). A
  long-running PHP daemon is **rejected** — it is not how pfSense packages run, and it would have to
  be HA-synced and supervised. The realistic shape is **one frequent cron tick that only triggers**;
  all "is X due?" logic moves into our PHP, decided from persisted state.
- **Sentinels already exist.** Per-feed `.orig` (byte-identical source mirror → change baseline),
  `.update`/`.last` markers already live under `$pfb['dbdir']` (`= {$g['vardb_path']}/pfblockerng`,
  `inc:42`). The due-ledger is an **evolution** of these (last-run → next-due), not a new mechanism.
- **`$pfb['dbdir']` is on the MFS RAM disk on the issue-#468 reboot path** → it is **wiped on
  reboot** unless persisted/restored (issue #468 added a separate change-gated DNSBL cache restored
  via `earlyshellcmd`). A due-ledger placed there naïvely is **lost on reboot** → every job reads
  "never run" → **all-due-at-once stampede** on the first post-boot tick, defeating today's
  random-hour jitter. The ledger design must make **ledger-absent ⇒ due-now-but-jittered**, and
  should ride #468's persist/restore set so a clean reboot keeps the schedule.
- **`pfb_trigger()` already maps `$cron` → `{cron,update,force}`** (`inc:3170`) — the canonical place
  the new API's `trigger` axis is derived; the GUI-Update-vs-scheduled-cron ambiguity is documented
  there (`:3174`).
- **The cron verbs are also internal contracts.** The ADR-04 smoke harness drives feeds via
  `PFB_CLI` verb strings (`helpers.reload('update'/'updateip'/...)`), and HA-sync replays a sync on
  the secondary. Any verb change must migrate these in lockstep — they are not free to break.
- **`dcc`/`bl` jitter is deliberate** (`rand(0,23)`) to avoid stampeding MaxMind / feed servers; the
  consolidation must **preserve a per-job jittered next-due**, not collapse everything onto one
  minute.
- **pf/Unbound/real cron are not real in CI.** The pure trigger map, due-ledger math, and cron
  generator are PHPUnit-pinned off-appliance; actual cron firing, catch-up, apply-on-change, and the
  Update page are only fully exercised on the ADR-04 live VM + ADR-14 UI tiers.

### 1.4 Relationship to ADR-40, ADR-42, ADR-10/12, ADR-30

- **ADR-42 (hash detection + conditional GET)** owns _did the feed change?_ ADR-43 **consumes** its
  detector as the "is there new content?" input to a due job; it does not re-implement detection.
- **ADR-40 (content-addressed apply)** owns _given a change, apply it cheaply._ ADR-43 **consumes**
  cheap apply to justify **apply-on-change** (§2.D); it does not touch the pf-table gate.
- **ADR-10 (zero-downtime DNSBL swap)** is the DNSBL-side cheap apply; same role as ADR-40 for the
  apply-on-change decision.
- **ADR-12 (update hooks)** reads `PFB_TRIGGER` (from `pfb_trigger()`); the new API must keep
  emitting an equivalent, stable trigger value so the hook contract is unchanged.
- **ADR-30 (scheduled log/counter reset)** owns `clearip`/`cleardnsbl`; **out of scope** here.

## 2. Decision

Split the overloaded `$cron` string into an **explicit trigger request**, move all "is X due?"
logic into PHP behind a **persisted due-ledger**, replace the cron-job fleet with **one frequent
trigger-tick**, switch to **apply-on-change** (consuming ADR-40/10) with an optional quiet-hours
window, and revamp the Update page onto the clean API.

| Area | Decision |
| --- | --- |
| **A — Trigger API** | A single explicit request object/params — **`scope` ∈ {ip, dnsbl, both}**, **`force` ∈ {bool}** (force = reparse, bypass reuse; default reuse/respect-detector), **`trigger` ∈ {cron, manual, force}** (identity for the ADR-12 hook env). `sync_package_pfblockerng()` is refactored to take this request; `pfb_trigger()`'s mapping is folded in. One entry, three named axes, no implicit string conventions. |
| **B — Verbs → adapters (deprecate-then-remove)** | The old verbs (`cron`/`update`/`updateip`/`updatednsbl` + the Force-button paths) become **thin adapters** that translate to the new request **and log a one-line deprecation warning**. The mapping is exact and pinned (e.g. `cron`→{both, force=false, trigger=cron}; `update`→{both, force=false, trigger=manual}; `updateip`→{ip, force=true, trigger=force}; `updatednsbl`→{dnsbl, force=true, trigger=force}). Internal callers (**HA-sync**, the smoke **`PFB_CLI`**) are migrated to the new API **in this ADR**; external scripts get a deprecation window, removal slated for a future release with a migration guide. "force vs reuse" is defined against **ADR-42's detector** (prerequisite). |
| **C — Due-ledger** | A persisted **per-job/per-feed next-due ledger** under `$pfb['dbdir']`, evolving the existing `.update`/`.last` markers. Each entry: last-run, next-due, and a **stable seeded jitter offset** (so `dcc`/`bl` keep a spread hour deterministically, not re-`rand`'d each pass). **Ledger-absent ⇒ due-now-but-jittered** (no boot stampede, §1.3); the ledger **rides issue #468's persist/restore** so a clean reboot keeps the schedule. **Offline catch-up falls out for free**: a `next-due` in the past ⇒ the job is due on the next tick, regardless of missed windows. |
| **D — One trigger-tick + apply-on-change** | Replace the `cron`/`dcc`/`bl` job family with **one frequent cron job** (a tick, ≈`*/15`) that **only** reads the ledger and dispatches the jobs that are due — no scheduling logic in crontab. `ss_refresh` (DNS re-resolution) rides **every** tick (its work is cheap and per-tick by nature). Because ADR-40 + ADR-10 make apply cheap (prerequisite), a due job that detects a change **applies immediately** (apply-on-change); the separate "when to apply" schedule collapses to an **optional quiet-hours / maintenance window** knob (defer apply to the window; default: apply immediately). |
| **E — Cron generator** | The four near-duplicate `install_cron_job` blocks collapse to **one** generator that emits the single tick (+ leaves `clearip`/`cleardnsbl` and any non-pfB jobs untouched). Idempotent install/teardown via the existing `pfblockerng_cron_exists` discipline. |
| **F — Update page revamp** | Rebuild the Update tab on the new API: explicit **scope** (ip/dnsbl/both) + **force** toggles (replacing the opaque Force/Update/Cron/Reload buttons), a **per-feed/job "next run" view** read from the ledger, a **"run now"** that calls the new request, and a cleaned-up update-log pane. Focused functional cleanup, **not** a visual redesign. |
| **G — Back-compat (config)** | Existing config (`pfb_interval`/`pfb_min`/`pfb_dailystart`, per-feed `freq`/`updatefreq`) is **read at the ADR-28/29 boundary** and **reinterpreted as ledger seed cadence** (a feed's `freq` becomes its next-due interval; the global interval seeds the default). No `config.xml` schema migration; the tick frequency is a new knob with a safe default. Any new registered field goes through `PfbConfig` (ADR-29). |

**Amended 2026-07-12 (issue #1204).** Rows D/E still hold — one cron entry, no scheduling logic in
crontab — but the entry now calls the cron-only wrapper verb **`pfblockerng.php cron-tick`**, which
runs the tick unless `/var/db/pfblockerng/.pfb_cron_disable` exists (then it logs
`[ Disabled by … ]` and dispatches nothing; the Update page reports the suppression). The direct
`pfblockerng.php tick` verb and the tick's own semantics are unchanged. The cron generator's
removal signatures are needle-tightened because `install_cron_job()` matches by **substring**.

### Semantics that MUST be preserved (the contract — pin with tests before changing)

1. **Every old verb maps to exactly one documented request and still works.** `cron`/`update`/
   `updateip`/`updatednsbl` + Force paths produce the same effective scope+force behaviour as today
   (red→green pins each mapping), plus a deprecation log line — no silent behaviour drift.
2. **The ADR-12 hook trigger value is unchanged.** `PFB_TRIGGER` still resolves to the same
   `{cron,update,force}` value for the equivalent trigger (the hook env contract holds).
3. **Effective per-job cadence is preserved.** Feeds refresh at their configured frequency; `dcc`
   stays daily, `bl` stays daily/weekly, `ss_refresh` stays per-≈15-min — now expressed as ledger
   next-due, not crontab rows. Pinned by cadence tests.
4. **Jitter is preserved and stable.** `dcc`/`bl` keep a spread (non-zero, deterministic per install)
   start offset; the tick never stampedes all jobs onto one minute.
5. **No boot stampede.** A wiped/absent ledger (RAM-disk reboot) ⇒ jobs become due-now-**jittered**,
   never all-at-once; a persisted ledger survives a clean reboot (#468 set).
6. **Catch-up, not double-run.** A missed window runs **once** on the next tick (next-due in the
   past ⇒ due), and a job already run in this period is **not** re-run.
7. **Reuse vs force fidelity.** `force=false` respects ADR-42's detector (unchanged ⇒ no reparse);
   `force=true` always reparses — the #517-style "reuse-cache no-change pass" path still exists.
8. **HA-sync + smoke harness stay green on the new API** (migrated in-ADR), and the deprecated verbs
   they used to call still resolve (defence in depth during the deprecation window).
9. **Apply-on-change is correct.** A detected change is applied promptly (or deferred to the
   quiet-hours window when set); no detected change ⇒ no apply. No regression vs the explicit-apply
   path it replaces.
10. **Idempotent cron install.** Re-running `sync_package_pfblockerng` converges the crontab to the
    single tick with no churn (existing `pfblockerng_cron_exists` contract).

### Explicitly kept / out of scope

- **Change detection (ADR-42) and pf-table apply (ADR-40/10)** — consumed, never re-decided here.
- **`clearip`/`cleardnsbl` counter-reset jobs** — cosmetic, ADR-30 territory; left as separate jobs.
- **`config.xml` schema/versioned migration** — none; legacy knobs absorbed at the read boundary
  (ADR-28/29), reinterpreted as ledger seeds.
- **A visual redesign of the Update page** — only a functional cleanup onto the new API; no
  restyle/relayout beyond what the new controls require.
- **Removing the deprecated verbs** — they are deprecated + warned here; **removal is a future
  release** (the migration guide states the timeline).
- **A long-running scheduler daemon** — rejected (§1.3).

## 3. Consequences

**Positive**

- **One mental model:** a feed/job has a frequency → a next-due → the tick runs it when due. No more
  reconciling a feed schedule against a separate cron cadence.
- **Free offline catch-up:** a missed refresh is recovered on the next boot/tick (a real gap in
  today's hour-bucket gating).
- **A named, extensible trigger contract:** scope/force/trigger are explicit; a new concern is a new
  axis, not a new implicit string. `pfb_trigger()`'s reverse-engineering disappears.
- **Less code, one place to schedule:** four near-duplicate cron blocks collapse to one generator +
  one tick; new periodic work is a ledger entry, not a fifth copy.
- **A clearer Update page:** the operator sees what each control does and when each feed next runs.
- **Apply-on-change:** changes take effect promptly (given ADR-40/10), with an optional quiet-hours
  window for operators who want batching.

**Negative / risks**

- **Hard dependency on two unbuilt ADRs.** 43 cannot be implemented until 40 + 42 land; if either is
  rejected/re-scoped, §2.B/§2.D must be revisited (§7). **Mitigation:** the prerequisite is stated up
  front; Phase 1–2 prep (extraction + ledger lib) is behaviour-preserving and independently valuable
  even if a later arm is narrowed (the ADR-01 lesson).
- **The trigger verb is a live wire** (HA-sync, smoke `PFB_CLI`, the GUI, external scripts).
  **Mitigation:** Phase 1 pins every current verb→behaviour mapping as an oracle **before** any
  refactor; adapters keep the old strings working; internal callers migrate in lockstep; external
  scripts get a deprecation window.
- **Ledger loss → stampede or starvation.** A mishandled RAM-disk wipe could stampede upstreams or
  (if mis-seeded) never run a job. **Mitigation:** the absent-⇒-due-now-jittered rule + #468 persist,
  pinned by a "wiped ledger" test and a live reboot smoke (`-m reboot`).
- **Tick frequency is a new tradeoff.** Too frequent = wakeups; too coarse = latency on catch-up.
  **Mitigation:** a conservative default (≈15 min, matching the tightest existing job `ss_refresh`),
  documented; it only triggers — the heavy work still runs at each job's own cadence.
- **Not a perf premise (unlike ADR-01).** The win is clarity/maintainability/catch-up, not speed —
  so the kill-gate is **correctness/back-compat** (the verb-mapping oracle + cadence/jitter/catch-up
  pins), not a benchmark.

## 4. Requirements (acceptance)

- **Prerequisite met:** ADR-40 and ADR-42 are implemented on `devel` (else this ADR does not start).
- Each deprecated verb (`cron`/`update`/`updateip`/`updatednsbl` + Force paths) maps to its
  documented `{scope,force,trigger}` request, produces today's effective behaviour, and logs one
  deprecation line (red→green per verb).
- `PFB_TRIGGER` (ADR-12) resolves unchanged for each equivalent trigger.
- The cron fleet is one tick; feeds/`dcc`/`bl`/`ss_refresh` keep their effective cadence and (for
  `dcc`/`bl`) a stable non-zero jitter — pinned by cadence/jitter tests.
- A wiped ledger ⇒ jobs due-now-jittered (no stampede); a missed window ⇒ exactly one catch-up run;
  a clean reboot keeps the schedule (ledger in the #468 set).
- `force=false` respects ADR-42's detector (no reparse on unchanged); `force=true` always reparses.
- A detected change is applied promptly (or deferred to the quiet-hours window when configured); no
  change ⇒ no apply.
- HA-sync and the smoke `PFB_CLI` run on the new API; the revamped Update page passes ADR-14 **Tier
  A + Tier B**.
- `python -m pytest`, `ruff`, `php -l`, PHPUnit, PHPStan, PHPCS, ShellCheck, markdownlint all green;
  live-VM fan-out (CE + Plus) green for cron firing, catch-up, apply-on-change, and the hook trigger.

## 5. Constraints (from CLAUDE.md)

- **PHP:** tabs, PHP 8.3; uppercase `TRUE`/`FALSE` (PHPCS sniff); no `die()`/`exit()` in library
  code; **registered config via `PfbConfig` (ADR-29)** for any new field (the tick-frequency / apply
  knob — register it; enum/bool at the boundary per ADR-28); PFBL-01 `RequirePfbFilter` stays green
  for any new `exec`/path build (the cron generator, the ledger file writes); pfSense funcs via
  `stubs/` + `tests/php/pfsense_doubles.php`. **No `write_config()` inside `PfbConfig`.**
- **Determinism:** the ledger's "now"/jitter must be **injectable** (pass a clock + a seed) so
  PHPUnit pins the date math without wall-clock/`rand()` flakiness.
- **Front-end:** the Update page is `www/` → **ADR-14 Tier A required**, **Tier B required** (the
  change is multi-step + visually structural: run-now → observe state → next-run view).
- **Test coverage (five non-negotiables):** behaviour-changing phases pin **fail-before/pass-after**;
  prep phases pin today's behaviour as **oracles**; every branch (each verb, each scope, force
  on/off, due/not-due, ledger present/absent, change/no-change, window/no-window) gets its own
  assertion; no phase without tests; intent-named, never coverage theater.
- **No live cron/pf/Unbound in CI** → actual firing, catch-up, reboot-persistence, apply-on-change,
  and the UI are live-VM (ADR-04) / ADR-14 tiers / maintainer smoke; PHPUnit pins the pure helpers.
- **ADR text + phase prompts land directly on the branch** (docs carve-out, no PR); every
  `src/`/`tests/` phase uses the full worktree + rebase-only-PR flow.

## 6. Action plan

Front-loaded with behaviour-preserving prep — pin every verb→behaviour mapping and build the
due-ledger as a pure, tested library — **before** any refactor of the live trigger path or the cron
fleet. Phases 3–5 are the behaviour changes (trigger API, cron consolidation, apply-on-change);
Phase 6 is the GUI; Phase 7 is migration/docs/live proof.

### Phase 1 — Oracle-pin the verb→behaviour map; extract the trigger request (prep, behaviour-preserving)

- **Prompt:** `01_Pin_Verbs_And_Extract_Request.txt`
- Extract a pure **`pfb_trigger_request($verb)`** mapping the current verb strings (and Force paths)
  to a `{scope, force, trigger}` struct, and have `sync_package_pfblockerng()` / `pfb_trigger()`
  consume it so the observable behaviour is **identical** this phase (no deprecation log yet, no new
  entry path). Make the struct loadable off-appliance.
- **Tests (oracle, stay green + new unit):** PHPUnit pins each verb → its `{scope,force,trigger}` and
  the resulting `PFB_TRIGGER`, matching today exactly; a table-driven case per verb + Force path.

### Phase 2 — The due-ledger library (prep, behaviour-preserving — pure, not yet wired)

- **Prompt:** `02_Due_Ledger_Library.txt`
- Build a pure PHP **due-ledger** module: read/write per-job/per-feed `{last_run, next_due, jitter}`
  under `$pfb['dbdir']`; an **injectable clock + seed**; the rules **absent-entry ⇒ due-now-jittered**
  and **next_due-in-past ⇒ due**. **Wire nothing into scheduling yet.** Evolve (not replace) the
  existing `.update`/`.last` markers.
- **Tests (oracle + new unit):** due/not-due across a clock; absent ledger ⇒ due-now with a non-zero
  jitter; missed window ⇒ exactly one due; stable jitter for a fixed seed; round-trip read/write.

### Phase 3 — The explicit trigger API + deprecated verb adapters (behaviour-changing)

- **Prompt:** `03_Trigger_Api_And_Adapters.txt`
- Refactor `sync_package_pfblockerng()` to take the `{scope,force,trigger}` request (Phase 1) as the
  primary entry; turn the old verbs into **thin adapters** that build the request, **log one
  deprecation line**, and call it. Migrate **HA-sync** + the smoke **`PFB_CLI`** onto the new API.
  `force` is defined against **ADR-42's detector**.
- **Tests (red→green):** each verb still produces today's effective behaviour **and** emits the
  deprecation log (failed before — no log/!named API); `force=false` respects the detector,
  `force=true` reparses (#517-style pass preserved); `PFB_TRIGGER` unchanged; HA-sync/`PFB_CLI` green.

### Phase 4 — One trigger-tick + the cron generator (behaviour-changing)

- **Prompt:** `04_Single_Tick_Cron.txt`
- Replace the `cron`/`dcc`/`bl` `install_cron_job` family with **one** generator emitting a single
  ≈`*/15` tick that reads the ledger and dispatches due jobs (preserving per-job cadence + seeded
  jitter); `ss_refresh` rides every tick; `clearip`/`cleardnsbl` untouched. Add the ledger to issue
  #468's persist/restore set. Register the tick-frequency knob via `PfbConfig` (ADR-29).
- **Tests (red→green + live):** cadence preserved (feeds/`dcc` daily/`bl` weekly) expressed as ledger
  next-due; wiped-ledger ⇒ no stampede; catch-up after a simulated gap; idempotent cron install (no
  churn); live-VM: the tick fires and runs a due feed, a reboot (`-m reboot`) keeps the schedule.

### Phase 5 — Apply-on-change + optional quiet-hours window (behaviour-changing, consumes ADR-40/10)

- **Prompt:** `05_Apply_On_Change.txt`
- A due job that detects a change (ADR-42) **applies immediately** via ADR-40 (IP) / ADR-10 (DNSBL);
  add an optional **quiet-hours/maintenance window** knob (`PfbConfig`) that **defers apply** to the
  window; default = apply immediately. Remove the now-redundant explicit apply-schedule reconciliation.
- **Tests (red→green):** change inside window / no window ⇒ applied now; change outside a set window ⇒
  deferred then applied at the window; no change ⇒ no apply; live-VM: a feed change applies on the
  tick without a manual Force.

### Phase 6 — Update page revamp on the new API (behaviour-changing, `www/` — Tier A + Tier B)

- **Prompt:** `06_Update_Page_Revamp.txt`
- Rebuild the Update tab: explicit scope+force controls → the new request; a per-feed/job **next-run**
  view from the ledger; a **run-now**; a cleaned update-log pane. Functional cleanup only.
- **Tests:** ADR-14 **Tier A** (render/marker/no-`php_error.log`); **Tier B** (run-now → observe the
  effective config/state change → next-run view reflects the run — a multi-step browser flow).

### Phase 7 — Migration guide, docs, deprecation notices + live-VM DoD

- **Prompt:** `07_Migration_Docs_DoD.txt`
- Write the **verb→new-API migration guide** (mapping table + removal timeline), the deprecation
  notices, and the new scheduling model in `docs/misc/architecture-notes.md` + the CLAUDE.md
  feed-update/scheduling mechanics. Finalise the live-VM fan-out (CE + Plus) and the DoD.

## 7. Definition of done

- **Prerequisite:** ADR-40 + ADR-42 implemented on `devel`.
- All §4 requirements met; the verb-mapping, cadence, jitter, catch-up, reuse/force, and
  apply-on-change cases green on the live-VM fan-out (CE + Plus); the Update page green on ADR-14
  Tier A + Tier B.
- The trigger path is the explicit `{scope,force,trigger}` request; old verbs are deprecated,
  warning-logging adapters; HA-sync + the smoke `PFB_CLI` run on the new API.
- The cron fleet is one tick + ledger; cadence/jitter preserved; the ledger persists across a clean
  reboot and degrades to due-now-jittered when wiped (no stampede).
- Apply-on-change is live (consuming ADR-40/10); the quiet-hours window defers correctly; the
  explicit apply-schedule reconciliation is gone.
- Docs + migration guide published; deprecation timeline stated. All linters/suites green.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- On a real box, power off across a feed's due window, boot, and confirm the feed **catches up** on
  the next tick (not a full cycle later), with **no stampede** of `dcc`/`bl` against upstreams.
- Confirm an upgrade from a build using the old verbs: scheduled cron + a GUI Update still work, log
  the deprecation, and produce identical effective behaviour; HA-sync to a secondary still reloads.
- Confirm apply-on-change on a real feed change (no manual Force) and that a configured quiet-hours
  window defers apply to the window.

**REJECT / re-scope criteria (what would kill or narrow this ADR):**

- **ADR-40 or ADR-42 is rejected or materially re-scoped.** Then §2.D (apply-on-change) and/or §2.B
  ("force vs reuse" against a real detector) lose their footing → either re-introduce an explicit
  apply-schedule (40 gone) or define force without the hash detector (42 gone), or **defer 43** until
  the dependency settles. The prep phases (1–2: verb oracle + ledger lib) stand alone regardless.
- **The verb→behaviour mapping is not a clean function** (Phase 1 shows scope/force are
  context-dependent per call site beyond {ip,dnsbl,both}×{force} — e.g. reputation/HA make scope
  ambiguous). Then the unified API is unsafe → keep the verbs, ship only the cron-tick consolidation +
  Update-page cleanup; the trigger-API unification is dropped.
- **The cron consolidation cannot preserve cadence + jitter + avoid the boot stampede** without
  regression (Phase 4 pins fail). Then keep the separate `dcc`/`bl` jobs (their jitter is in crontab)
  and apply the tick only to the feed `cron` + `ss_refresh`; the rest of the ADR stands.
