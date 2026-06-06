# pfBlockerNG — Test-Coverage Improvement Plan

Author: Claude (analysis pass, 2026-06-06). Target repo: `/Users/andre/git/pfBlockerNG`, branch `devel`.

This plan adds **meaningful** coverage — tests that would *fail on a regression*, cover **every
branch**, and assert **before-state** in transition tests (per CLAUDE.md "Test coverage
(mandatory)"). No coverage theater.

---

## 1. Current state (measured)

| Surface | Harness | Status |
| ------- | ------- | ------ |
| `pfb_unbound.py` (5412 ln) | pytest (`tests/`) | Pure helpers ~80–90%; `operate()` ~40%; `init_standard()`/workers 0% (live-VM-only by design). ~67% overall (#38). |
| `pfblockerng.inc` (12453 ln) | PHPUnit (`tests/php/`, real `.inc` off-appliance) | **26 / 89 top-level fns tested (~29%)**. 204 tests green. Many PURE fns untested. |
| `pfblockerng.sh` (1161 ln) | shellspec (`tests/shell/`) | tempfile, `iptoasn`, `reputation_max/dmax`, AWS region scripts covered. `pfb_aggregate`, `duplicate`, `cidr_aggregate`, `whoisconvert`, `asn_table`, `processet/xlsx` **0%**. |
| `www/*.php` (≈ 13 pages, ~6000 ln) | live-VM `ui_render`/`ui_e2e`/`ui_browser` smoke only | **No off-appliance unit coverage.** Extractable log/CSV/feed helpers unpinned. |

**Headline gaps (highest risk × testability × current zero-coverage):**

1. PHP config-migration & feed-routing logic (`convert_feeds_json`, `pfb_determine_list_detail`) — silent-corruption risk on upgrade, zero tests.
2. PHP pure parse/arithmetic helpers (`ip_explode`, `pfb_parse_line/query`, `pfb_cron_base_hour`, `pfblockerng_cron_exists`) — bug-prone slicing/math, zero tests.
3. Shell `pfb_aggregate` (ADR-11) — complex mtime/set-change gating, only smoke-VM coverage.
4. Python `operate()` branches reachable with a richer fake qstate/reply (CNAME-chase, SERVFAIL, event dispatch) — currently the live-VM smoke carries them, but several are unit-reachable.

---

## 2. Harness facts an implementing agent MUST know

- **PHPUnit** (`tests/php/`) loads the **real** `pfblockerng.inc` off-appliance via
  `tests/php/bootstrap.php` (empty include shims in `tests/php/shims/` + behavioural doubles in
  `tests/php/pfsense_doubles.php`). To test a fn that reaches a new pfSense symbol, add a
  faithful `function_exists()`-guarded double to `pfsense_doubles.php` (NOT the empty PHPStan
  stubs in `stubs/pfsense/`). Existing doubles: `is_ipaddrv4/v6`, `is_ipaddr`, `is_hostname`,
  `write_rcfile`, `safe_mkdir`, `resolve_host_addresses`, `is_ipaddr_configured`, … (see file).
  `config_get_path` is **not** doubled yet — add it if your target needs it. Run:
  `composer install` once, then `vendor/bin/phpunit`.
- **shellspec** (`tests/shell/`, `--shell sh`): `spec_helper.sh` puts `tests/shell/bin/` ahead of
  PATH so bare-name add-on binaries (`iprange`, …) hit deterministic shims; fixtures in
  `tests/shell/fixtures/`. Gated in pre-commit + CI (`test.yml`). Run: `shellspec`.
- **pytest** (`tests/`): `conftest.py` copies Unbound injected globals onto `builtins` and
  resets the `pfb` dict + DBs per test; `stubs/python/unboundmodule.py` provides a recording
  `DNSMessage` (`DNSMessage.instances`) + permissive `_Struct` qstate/env. `make_qstate()` in
  `tests/test_pfb_unbound.py` builds a `SimpleNamespace` qstate. Run: `python -m pytest`
  (repo root; use `.venv/bin/python -m pytest` locally).
- **DO NOT** try to unit-test genuinely live-VM logic off-appliance: `init_standard()`,
  `pfb_async_worker()`, `pfb_db_worker()`, real `unbound-control`/`pfctl`/SQLite-on-disk paths,
  and the `www/*.php` request lifecycle belong to the ADR-04 smoke suite. Coverage there is
  added as **smoke** tests, not unit tests.

---

## 3. Shared preamble (paste into EVERY task prompt below)

> You are working in the pfBlockerNG repo. **First read `CLAUDE.md` end-to-end and obey it.**
> Non-negotiables for this task:
>
> - **Activate `/caveman` at start.** Begin every reply with the work-context marker
>   (this is a PR-bound code change → use `👀`/`⏳` with the PR number once it exists).
> - **Work in a dedicated git worktree** off the latest `origin/devel`
>   (`git fetch origin && git worktree add -b <branch> <path> origin/devel`). Branch name:
>   `issue/<n>-<slug>` if an issue exists, else a descriptive `test/<slug>`. Never the primary
>   checkout. Reuse the venv by absolute path (`.venv/bin/python`); do **not** `ln -sfn` the venv
>   (self-loop footgun).
> - **Tests must VALIDATE, not just execute** (CLAUDE.md "Test coverage (mandatory)"): assert an
>   outcome that would *fail on a regression*; cover **every branch** (each side of every
>   bool/switch/input-class); in any transition test assert the **before-state** first so green
>   proves the change *caused* the effect. Complex behaviour → BDD `Scenario`/`Given–When–Then`
>   next to the test; trivial helpers stay trivial. Name/comments state the **intent**.
> - **Do not modify production `src/` code** unless the task explicitly says so. If a target
>   turns out to be genuinely untestable off-appliance, STOP and report why rather than forcing a
>   brittle test or refactoring shipped code.
> - **Run the linters + the relevant suite green** before pushing (ruff/phpunit/shellspec/
>   markdownlint as applicable; the pre-commit hook gates them — ensure hooks active via
>   `sh scripts/setup-hooks.sh`).
> - **Clean the diff** to only what the change requires (CLAUDE.md "Clean the diff"). Rebase onto
>   the latest `origin/devel` before every push (`--force-with-lease` if rewritten).
> - **Land via `/pr-merge-flow N`** (review feedback → green CI → rebase-merge). One task = one PR.
> - When done, report: branch, PR number, the source fn(s) pinned, the branch checklist you
>   covered, and anything you deliberately deferred (with reason).

---

## 4. Tasks (ranked; PHP tasks parallelizable, rebase-before-push handles the shared doubles file)

### TASK 1 — PHP: pin `convert_feeds_json()` (config migration, high corruption risk)

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add a PHPUnit test class `tests/php/ConvertFeedsJsonTest.php` pinning
> `convert_feeds_json()` (`src/usr/local/pkg/pfblockerng/pfblockerng.inc:7784`). It migrates the
> feeds-info JSON into the in-memory `$pfb['feeds_list']` + returned `$feed_info` structure and is
> currently **untested** — a regression silently corrupts every feed on upgrade.
>
> **Harness:** It reads `config_get_path('installedpackages/pfblockerngglobal', [])` and
> `file_get_contents($pfb['feeds'])`. Point `$pfb['feeds']` at a fixture JSON you create under
> `tests/php/fixtures/`; add a `config_get_path` double to `tests/php/pfsense_doubles.php` (guarded
> by `function_exists`) that returns a test-controlled array. Study `tests/php/bootstrap.php` and an
> existing data-driven test (e.g. `AggregateMemberListTest.php`) for the setup pattern.
>
> **Branch checklist (cover EACH, with before/after where it's a transition):**
>
> 1. Invalid/empty JSON or non-array → returns `array('blank' => '')`.
> 2. A `$type` whose `$info[0] == '*'` (or non-array) → skipped entirely.
> 3. A feed with `status == 'discontinued'` → removed AND `$feed_count[$type]` decremented (assert
>    the count *with* the discontinued entry present vs *after* removal).
> 4. A feed with an `alternate` array → `$feed_count[$type]` incremented per alternate.
> 5. **Merge path** (`$aconfig['feed_<aliasname>']` set): feeds merge under the alt name; the
>    `info`/`description` `substr_replace` rewrites the aliasname; `feeds_list[type][alias]` maps
>    to the alt name. Assert the merged `feeds` array and the rewritten text.
> 6. **Non-merge path** (no aconfig entry): `feeds_list[type][alias] == alias`, `feed_info[type][alias] == data`.
> 7. Final `$feed_info['count']` aggregation equals the per-type tallies.
>
> Use a BDD scenario block (this is non-trivial migration logic). Acceptance: every branch above
> has a distinct, failing-on-regression assertion; suite green.

---

### TASK 2 — PHP: pin `pfb_determine_list_detail()` (feed config router, silent-data-loss risk)

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add `tests/php/DetermineListDetailTest.php` pinning `pfb_determine_list_detail($list,
> $header, $confconfig, $key)` (`pfblockerng.inc:1967`, ~130 ln). It routes each feed to a
> parse/format strategy; a wrong branch silently mis-parses a whole feed.
>
> **First**, READ the function fully and enumerate its real branches (the signature args + the
> `$confconfig`/`$list` shape drive it). Map every distinct return/route it can produce. If it
> calls pfSense symbols, double them in `pfsense_doubles.php`. If — after reading — a large part is
> impure I/O that can't be reached off-appliance, pin the **pure routing decisions** that ARE
> reachable and explicitly report which sub-branches you deferred to smoke and why (don't force it).
>
> **Branch checklist:** one assertion per documented input class / route the fn selects (header
> type, list format, key presence/absence, empty vs populated config). Each must assert the
> *selected route/return*, not merely that it ran. BDD scenario block. Acceptance: every reachable
> branch pinned with a regression-failing assertion; deferred branches listed with reason; green.

---

### TASK 3 — PHP: pin the pure parse/arithmetic helper cluster

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add focused PHPUnit tests (one class per fn, or a small grouped class) for these PURE,
> bug-prone, currently-untested helpers in `pfblockerng.inc`:
>
> - `ip_explode($ip)` (:5002) — builds `[ip, oct0,oct1,oct2,oct3, "a.b.c.0/24", "a.b.c."]`. Pin the
>   exact array for a normal IPv4; AND the degenerate inputs it can receive (fewer than 4 octets,
>   trailing dot, empty) — assert what it actually returns so the contract is locked.
> - `pfb_parse_query($line)` (:7099) — `explode('.txt:')` + basename of `$rx[0]`. Pin a normal
>   `/path/alias.txt:payload` line, a line with no `.txt:`, and a line with no `/`.
> - `pfb_parse_line($line)` (:7107) — extracts the alias name from a `:local`/`.txt` log line. Pin
>   with `:local` present, with `.txt` present, with neither, and the basename slice.
> - `pfb_cron_base_hour($freq)` (:2313) — frequency→hours arithmetic. Pin EACH case
>   (`Disabled`/1/2/3/4/6/8/12/24 and the string forms `01hour`…`12hours`) AND the `default`
>   (returns `[]`, sets `$pfb['interval']=1`). Verify the generated hour list length/spacing for a
>   representative `$pfb['hour']` start. This is the highest-value one — the loop math is easy to
>   break.
> - `pfblockerng_cron_exists($cmd,$min,$hour,$mday,$wday)` (:2283) — crontab-match predicate. Pin
>   match vs no-match by feeding a doubled cron config; assert both sides.
>
> Trivial helpers get plain intent-named assertions; `pfb_cron_base_hour` (non-trivial) gets a BDD
> spec. Set `$pfb` globals as the fns require (see how existing tests prime `$pfb`). Acceptance:
> every branch/case above asserted; green.

---

### TASK 4 — PHP: pin local-network collection + file-reader helpers

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add PHPUnit coverage for these currently-untested helpers (read config/files; need
> doubles or tmp fixtures):
>
> - `pfb_local_ip($subnet, $pfb_localsub)` (:6376) — local-subnet membership. Pure-ish: pin
>   in-subnet TRUE vs out-of-subnet FALSE (both sides), IPv4 and IPv6 cases.
> - `pfb_collect_localip()` (:6390) and `pfb_collect_localhosts()` (:6476) — gather local IPs/hosts
>   from config. Drive via doubled config; assert the collected set for a representative config AND
>   the empty-config case.
> - `pfb_dnsbl_whitelist_lines()` (:3243) — reads a whitelist file → domains array. Write a tmp
>   fixture file; assert parsed lines, comment/blank-line skipping, and the missing-file case.
> - `find_reported_header($ip, $pfbfolder, $geoip=FALSE)` (:5020) — search IP in report files. Use a
>   tmp folder fixture; assert found vs not-found AND the `$geoip` TRUE/FALSE branch.
>
> Add doubles/fixtures as needed (`config_get_path`, interface helpers). Each fn: assert BOTH the
> positive and the empty/negative branch (CLAUDE.md branch rule). Acceptance: green; both sides of
> every branch pinned.

---

### TASK 5 — Shell: pin `pfb_aggregate` (ADR-11 union builder) off-appliance

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add `tests/shell/pfblockerng_aggregate_spec.sh` (shellspec) pinning the `pfb_aggregate`
> action of `src/usr/local/pkg/pfblockerng/pfblockerng.sh` (~:331). Today only the live-VM smoke
> (`test_smoke_aggregate.py`) covers it; the mtime/set-change gating logic deserves a fast unit pin.
>
> **Harness:** Follow the existing specs (`pfblockerng_reputation_max_spec.sh`) and `spec_helper.sh`.
> `iprange` is already shimmed via `tests/shell/bin/` on PATH — reuse/extend that shim so output is
> deterministic. Build member-file fixtures in a tmp dir; invoke the script's `aggregate` action (or
> the function directly if sourceable) against them.
>
> **Branch checklist (assert before/after for the gates):**
>
> 1. **Cold build:** no existing aggregate → produces the deduped, iprange'd union; consumer `.lst`
>    is created and **never empty** (placeholder when the union is empty).
> 2. **Member set unchanged + not stale:** re-run does NOT rebuild (assert the output mtime/content
>    is untouched — capture before, re-run, compare).
> 3. **Member set changed:** adding/removing a member triggers a rebuild with the new union.
> 4. **Stale (a member newer than the aggregate):** triggers rebuild.
> 5. **iprange failure** (shim returns non-zero): handled without producing a corrupt/empty wired
>    output (assert the documented fallback).
>
> BDD scenario block (state-transition logic). Wire the new spec into the shellspec run (it's
> auto-discovered by `.shellspec` glob — verify it runs). Acceptance: every gate's both sides
> asserted; `shellspec` green.

---

### TASK 6 — Shell: pin `duplicate` (dedup/CIDR-collapse) + `cidr_aggregate`

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Add a shellspec spec pinning `duplicate` (~:426) and `cidr_aggregate` (~:281) in
> `pfblockerng.sh` — pure-ish pipelines (sort/iprange/collapse) currently untested off-appliance.
>
> **Branch checklist:** for `duplicate` — exact duplicates removed; CIDR-collapsible adjacent
> ranges merged; non-overlapping ranges preserved; empty input → empty (or placeholder) output. For
> `cidr_aggregate` — single-file aggregation via the iprange shim; assert the collapsed result vs
> the raw input (before/after). Reuse the iprange shim; deterministic fixtures. Trivial-ish, so
> concise intent-named assertions are fine (no full BDD needed unless a path is stateful).
> Acceptance: both fns, both sides of each branch, `shellspec` green.

---

### TASK 7 — Python: extend `operate()` branch coverage with richer fakes (reachable branches only)

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Raise real branch coverage of `operate()` in
> `src/usr/local/pkg/pfblockerng/pfb_unbound.py` for branches reachable off-appliance, WITHOUT
> touching production code and WITHOUT reattempting the genuinely live-VM-only paths
> (`init_standard`, `pfb_async_worker`, `pfb_db_worker`, real SQLite/unbound-control).
>
> **First**, measure: run the suite under coverage to get `operate()`'s missing lines/branches
> (`python -m pytest --cov=src/usr/local/pkg/pfblockerng/pfb_unbound --cov-branch
> --cov-report=term-missing` — install `pytest-cov` in the worktree venv if absent). Map each
> missing branch to its trigger. Then enhance `make_qstate()` / the `DNSMessage` fake in
> `stubs/python/unboundmodule.py` (e.g. a populated `reply`/`reply_info` with rrsets, a security
> flag, `query_flags`) ONLY as far as needed to drive these candidate branches:
>
> - CNAME-chase path in `operate()` (reply rrset iteration).
> - SERVFAIL / `MODULE_ERROR` error handling on a malformed qstate.
> - Event dispatch: `MODULE_EVENT_PASS` and `MODULE_EVENT_MODDONE` vs `_NEW`.
> - Any `no_cache_store` / decision-cache interaction not already pinned.
>
> For EACH branch added: assert the observable effect (the `DNSMessage.instances[-1]` reply shape,
> rcode, ext_state transition) — not merely that the line ran. Where you find a branch that
> *cannot* be honestly faked, leave it and record it as smoke-deferred in your report (do NOT widen
> the fake into something that no longer resembles Unbound's real contract). BDD scenario blocks
> for the multi-step paths. Acceptance: net new `operate()` branches covered with regression-
> failing assertions; report before/after coverage numbers for `operate()`; `python -m pytest` green.

---

### TASK 8 — Governance (do LAST / optional): coverage visibility + ratchet

> [PASTE SHARED PREAMBLE]
>
> **Goal:** Make coverage regressions visible without flaky hard floors.
>
> - **PHP:** add an informational PHPUnit coverage report in CI (`test.yml`) using pcov/xdebug,
>   mirroring the existing informational Python `pytest-cov` step (#140) — no hard floor initially,
>   just a printed number + (optionally) an artifact, so the 29%→ climb is tracked.
> - **Shell:** the shellspec `--kcov` step already runs in CI (`test.yml:214`); surface its
>   percentage in the job summary.
> - Optionally propose (in the PR description, not enforced yet) a **ratchet** that fails CI if
>   PHP/Python line coverage drops below the last-merged value, once Tasks 1–7 have raised the
>   baseline.
>
> This touches CI YAML only (+ maybe `composer.json` dev-dep for pcov). No `src/` changes.
> Acceptance: CI prints PHP + shell coverage numbers; green. Land via `/pr-merge-flow`.

---

## 5. Sequencing & notes

- **Parallelism:** Tasks 1–4 (PHP) can run concurrently in separate worktrees but all may append to
  `tests/php/pfsense_doubles.php` → each must rebase onto latest `origin/devel` before push; the
  second to land resolves the trivial double-add conflict. Tasks 5–6 (shell) and 7 (python) are
  independent. Task 8 last, after the baseline has moved.
- **One PR per task.** Each lands via `/pr-merge-flow N` (the repo default).
- **Stretch / backlog (not scoped here, flag for a future ADR):** off-appliance unit harness for
  `www/*.php` pure helpers (alerts log/CSV parsing in the 5524-line `pfblockerng_alerts.php` is the
  biggest unpinned pure surface); shell `whoisconvert`/`asn_table`/`processet`/`processxlsx`;
  Python `init_standard`/workers — these belong to the ADR-04 smoke tier, add smoke cases there.
- **Definition of "meaningful":** every task above pins behaviour with assertions that fail on a
  real regression and cover both sides of each branch. Reject any test that executes code without a
  failable, intent-bearing assertion (CLAUDE.md).
