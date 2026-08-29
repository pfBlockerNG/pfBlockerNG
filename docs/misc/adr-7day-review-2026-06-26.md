# Adversarial review — ADRs landed on `devel` 2026-06-19 → 2026-06-26

Unit-level review only (smoke / live-VM reviewed separately, per request). 13 ADRs, each
reviewed against its design intent, its unit-test discrimination, and for oversights/new bugs;
every critical/high finding was independently skeptic-verified against the live code. Baseline:
both suites green (PHPUnit 1532 tests / 14878 assertions; pytest 1884 passed) — so "tests pass"
is no evidence here; the question was whether those green tests would *catch* a regression.

Severity = skeptic-corrected. "Ships" = a defect a user can hit on `devel` today.

## Confirmed shipping user bugs (fix candidates)

| # | ID | Sev | ADR | One line |
| - | -- | --- | --- | -------- |
| 1 | ADR36-1 | **Critical** | 36 + 37 | DNS-Redirect **and** DoT/DoQ-block settings never persist — save handler clobbers them |
| 2 | ADR30-1 | **High** | 30 (broken by 43) | Scheduled log reset + log size-cap trim are dead on a live box |
| 3 | ADR43-1 | **High** | 43 | Per-list feed Update-Frequency ignored — every feed now polls hourly (provider-ban risk) |
| 4 | ADR31-1 | **High** | 31 | Permit feed silently un-blocks a domain the operator manually blocked (band inversion) |
| 5 | ADR42-1 | Medium | 42 | Conditional-GET 304 fast-path is dead (validator key mismatch) — full re-download every cron |
| 6 | ADR43-2 | Medium | 43 | Default "Force Reparse" (scope=both, force=true) is a no-op — force only wired for ip/dnsbl scope |

### 1. ADR36-1 — DNS-Redirect & DoT/DoQ-block settings silently never persist *(CRITICAL, directly confirmed)*

`src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php:871-882`. The six ADR-36/37 fields are
written as leaves via `PfbConfig::write()` (871-880), then line 882
`PfbConfig::writeSection('installedpackages/pfblockerngdnsblsettings/config/0', $pfb['dconfig'])`
replaces the **whole** section with the page-load snapshot `$pfb['dconfig']`, which never
received those keys. `write_config()` (883) then flushes the snapshot, wiping the six leaf
writes. Net: enabling DNS Redirect, choosing interfaces, the exception alias, the Block/Reject
action, and Floating mode all silently revert on save — both features are unreachable from their
own settings page, in both directions (enable→off, disable→on). The two `safesearch_doh*` writes
survive only because they target a different section (`pfblockerngsafesearch`).

Why it slipped: `CfgGatewayTest`/`CfgAdaptersTest` round-trip each adapter in isolation; nothing
exercises the page's read→leaf-write→section-write ordering. The page is not loaded off-appliance.

Fix (minimal): move the eight `PfbConfig::write()` calls **after** the `writeSection()` so the
leaf writes land last and survive the section replace. (`safesearch_doh*` are order-independent.)

### 2. ADR30-1 — Scheduled log reset + size-cap trim dead on-box *(HIGH, directly confirmed; ADR-43 regression)*

`pfb_log_reset()` and the `pfb_log_mgmt()` line-cap trim are scheduled only from
`pflblockerng_sync_cron()` (`pfblockerng.php:800/806`), reachable only via the `cron` CLI verb.
ADR-43 (`pfblockerng.inc:16034 install_cron_job('pfblockerng.php cron', FALSE)`) removed that
scheduled job and installs only `pfblockerng.php tick`. `pflblockerng_tick()` (php:829-909)
execs `pfb_trigger`/`dcc`/`bl` + `ss_refresh` and never calls either log function;
`sync_package_pfblockerng()` never calls them. So `log_rotate_*=daily` never empties on schedule,
and report logs grow past `log_max_*` until a manual GUI view / settings-save (MFS `/var` disk
pressure). Root cause: collapsing the cron fleet onto the tick dropped what
`pflblockerng_sync_cron()` did *besides* triggering a sync.

### 3. ADR43-1 — Per-list Update-Frequency silently bypassed *(HIGH, directly confirmed)*

The per-feed frequency gate (`switch($list['cron'])` → EveryDay/Weekly/NNhour) lives only in
`pflblockerng_sync_cron()` (`pfblockerng.php:705-757`), reachable only via the orphaned `cron`
verb. The tick execs `pfb_trigger scope=both force=false trigger=cron` →
`sync_package_pfblockerng()`, which has **no** `$list['cron']` gate and downloads/conditional-GETs
every enabled feed on every due tick at the global `pfb_interval` (default hourly). A feed a user
set to **Weekly** (e.g. to respect a provider's rate limit) is now hit ~168×/week — providers
like Spamhaus ban frequent pollers. Violates ADR-43's own acceptance criterion #3 ("feeds refresh
at their configured frequency"). Same root cause as #2.

### 4. ADR31-1 — Permit feed un-blocks an operator's manual block *(HIGH, confirmed by code trace + execution)*

`pfb_unbound.py:4635-4666`. The permit-mode build inserts band-2 (`PRIO_FEED_ALLOW`) whiteDB
entries but never sets `important_rules=True`. When no loaded feed carries an ABP `@@`/`$important`/
regex (a common plain-hosts config: hosts-format block feed + a `Custom_List` manual block + a
DNSWL permit feed), `important_rules` stays False, so `evaluate_domain` takes the **fast path**
(`:5658 if not cfg.get("important_rules", False)`), where `whitelist_check_domain` is
band-agnostic: any whiteDB match overrides any block. A band-2 permit allow therefore overrides
the operator's band-5 `Custom_List`/user block — a security fail-open. Before ADR-31 the only
band-2 allows came from ABP `@@` rules, which always set `important_rules=True` (forcing the
band-aware numeric path where band 5 > band 2); ADR-31 added band-2 allows without that flag.
Reproduced live through the suite's conftest. Gated behind: the opt-in permit feature **and** a
domain overlap **and** no important-rule loaded. Matches §2.2.3 reject criterion (b).

### 5. ADR42-1 — Conditional-GET 304 fast-path is dead *(MEDIUM, confirmed)*

Validator read/write key mismatch. The detector writes validators to `{header}.orig.etag` /
`.lastmod` (`pfblockerng.php:557/578/589`, base `{header}.orig`), but the probe is called with
`file_dwn="{header}.md5"`, so `pfb_download` reads `pfb_validator_read("{header}.md5.orig...")`
(`pfblockerng.inc:8005`). Read key ≠ write key → stored ETag/Last-Modified never loaded →
`If-None-Match`/`CURLOPT_TIMECONDITION` never set → server can never return 304. Every unchanged
remote feed re-downloads its full body every cron. **No correctness impact** (it fail-safes to
download+hash, so no blocklist defect) — but ADR-42's headline Phase-3 optimization is entirely
non-functional, and it compounds #3 (hourly polling × full re-download).

### 6. ADR43-2 — Default "Force Reparse" is a no-op *(MEDIUM, confirmed)*

`pfblockerng.inc:12016-12032`. `$pfb_req['force']` is consumed only in the `scope==='ip' &&
force` and `scope==='dnsbl' && force` branches. The Update page (and the wizard reload) default
Run-Now to `scope='both'` + `pfb_run_force='on'` → dispatches `scope=both force=true
trigger=force`, which falls through the whole chain with no scope/reuse adjustment — identical to
`force=false`. The most prominent "Force" control produces a plain detector-respecting pass; an
unchanged feed is not reparsed even though the operator explicitly asked.

## Other confirmed correctness issues (medium — worth fixing, not "ships-critical")

- **ADR43-3** (`pfblockerng_extra.inc:2070-2077`) — ledger-absent returns due-now **immediately**,
  not due-now-**jittered** as contract #5 requires; first post-boot tick can stampede dcc/bl
  across a fleet when the #468 archive restore is missing.
- **ADR43-4** (`pfblockerng_extra.inc:2217-2222`) — jitter is added to **every** `next_due`, so
  "daily" dcc actually runs every ~24-47h (avg ~35h) and "weekly" bl every ~7-8 days; jitter
  should be a one-time start *offset* (contract #4), not a per-cycle period addend. Pinned-as-
  correct by `DueLedgerTest:654` / `TickCronTest:248` — the tests encode the wrong cadence.
- **ADR38-2** (`pfb_unbound.py:881-892`) — `pfb_setup_logging` still lists `unified` in its
  writable-or-rename loop; `unified.log` is now root-owned (Amendment 1), so the chrooted python
  renames the root daemon's log to a junk file on every Unbound restart.
- **ADR38-4** (`pfblockerng.inc:10608-10662`) — syslog emit sits outside the `dup_entry=='+'`
  gate, so pf-duplicate (`-`) filter.log lines are exported to syslog (with stale enrichment),
  while `unified.log`/Reports collapse them.
- **ADR36-3 / ADR37-2** — reconcile idempotency (`!==` strict array compare across an XML
  round-trip with `['any'=>'']` empty-element sentinels) is unguarded; if the parser reparses
  `<any></any>` as `[]` rather than `''`, every tick rewrites config and forces `filter_configure()`.
- **ADR36-4** (`pfblockerng.inc:14150-14160`) — the rule builder validates interfaces only with
  `pfb_filter(PFB_FILTER_WORD)`, not `pfb_build_if_list()` as §5 requires; a word-shaped
  non-existent interface builds a bogus rdr rule.

## Test-quality failures (dimension 2 — code may be correct, the guards are not)

These are coverage-theater / missing-discrimination findings: the headline property is "green"
but the assertion would not fail on a regression. Each violates the repo's own test mandate.

- **ADR40-3** — delta end-state == `-T replace` (the Phase-4 invariant) is **unpinned**: the mock
  pfctl logs entry *counts* only, so swapping `$add_set`/`$del_set` (catastrophic) passes 14/15
  tests. (`AliasDeltaApplyTest`.)
- **ADR40-2 / ADR40-4 / ADR40-5** — cross-list dedup detection, the off-by-one "guard", and the
  #468 empty-table force-replace are "tested" by re-implementing `array_diff` in the test and
  never calling the function under test. `AliasContentGateTest`'s cross-list tests would pass with
  the whole feature deleted; smoke docstrings point at test names that don't exist (ADR40-6).
- **ADR40-1** — the cross-list dedup propagation the ADR is *Accepted* for is not actually
  delivered (the content gate re-reads stale sibling `.txt` files; only reputation has a global
  regen pass). Not a new regression, but the Accepted claim is overstated and the dedup live legs
  were deferred, so it was never validated.
- **ADR42-2** — the regression test for the critical `$probe_meta=NULL` blocker asserts PHP
  tautologies (`NULL !== NULL`); reverting the production fix leaves it green.
- **ADR30-2** — no test drives the real `tick` entrypoint (smoke uses the dead `cron` verb, unit
  calls `pfb_log_reset()` directly), which is exactly why #2 shipped invisibly.
- **ADR31-2** — §2.2.3 "manual block beats permit" is tested only with an ABP `@@` allow (numeric
  path), never with a permit feed; the discriminating test fails on current code (= bug #4).
- **ADR35-1 / ADR35-2 / ADR37-1** — the managed-object ownership helpers (`pfb_is_managed_obj`
  etc.), the sole arbiter of what the deinstall sweep deletes from three pfSense-core sections,
  have **zero** off-box tests; the golden/lifecycle/sweep suites were deleted in the #476 inline
  rework and not replaced. A broadened predicate would delete user firewall objects and pass PR CI.
- **ADR36-2** — `DnsRedirectBuilderTest`/`DnsRedirectLifecycleTest` (rdr rule-shape + lifecycle)
  deleted, no off-box replacement; §7 DoD still ticks the deleted tests as green.
- **ADR43-5** — `pflblockerng_tick()` (the due-OR-pending dispatch, quiet-hours defer/apply,
  set_pending vs mark_ran) has no off-appliance test.
- **ADR29-1 / ADR29-2** — the `RequireConfigGateway` sniff's `$registeredPaths` and the
  inventory-completeness test are hand-maintained mirrors of the registry with no drift test, so
  a new registered key silently stops being enforced / inventoried (the false-negative the sniff
  exists to prevent).

## Low / latent (not triggered on supported configs today)

ADR38-1/ADR38-6 (key=value escaper doesn't escape `\` or tabs — but DNSBL qname is
unbound-presentation-escaped upstream, so not readily exploitable); ADR39-2 (`major.minor`
reduction doesn't strip a non-numeric suffix → would emit a 404 varver on a future version
string); ADR35-4 (unanchored `str_contains($descr,'pfB DNSBL')` could sweep a user rule that
merely names it); ADR31-3/ADR31-4 (ABP-format permit feed is a silent no-op; permit wildcard lost
on equal-band collision); ADR27-1/2/3 (retention/landing version-sort collapses the alpha/beta/rc
stage → non-deterministic prune / mislabeled "latest devel" once retention>1); ADR43-6
(`pfb_quiet_hours` name is inverted from its meaning — window is when apply *is* allowed).

## Cross-cutting pattern

The two highest-impact regressions (#2, #3) and several test gaps trace to the same shape: an ADR
phase that **reworked one mechanism dropped a responsibility a sibling owned**, and the inline
rework that came with it **deleted the off-box golden/lifecycle tests** that would have caught it
— leaving only dispatch-only smoke, which does not gate PRs. ADR-43's cron-fleet collapse is the
clearest case (it silently un-homed log-reset *and* per-list frequency), and the #476 inline-move
deleted the DnsRedirect/DoT/fwobj suites. Net: real user-facing regressions ship green.
