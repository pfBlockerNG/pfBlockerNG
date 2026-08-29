# ADR-53: Replace the IP-suppression host-explosion with CIDR set-subtraction (v4+v6 parity)

- **Status:** **Accepted** (2026-07-03) — implemented via PR #768 (merged 2026-07-03); CE+Plus live fan-out green (smoke 28678906679, UI 28678907701; §7 evidence in `RESULTS/09_Results.txt`).
- **Date:** 2026-07-03
- **Branch:** `adr/53-ip-suppression-set-subtraction` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming"). / **Component(s):**
  `src/usr/local/pkg/pfblockerng/pfblockerng.sh` (`suppress()`),
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (suppression file, killstates, alias-build
  wiring), `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` (config registry, new pure
  helpers), `src/usr/local/www/pfblockerng/pfblockerng_ip.php`,
  `src/usr/local/www/pfblockerng/pfblockerng_alerts.php`,
  `src/usr/local/www/widgets/widgets/pfblockerng.widget.php`.
- **Target runtime:** POSIX sh + PHP 8.3 (pfSense CE 2.8). No Python on the appliance.
- **Test suite:** `tests/shell/` (shellspec — `suppress()`), `tests/php/` (PHPUnit — validators,
  v6 diff engine, killstates helper, config round-trip), `tests/smoke/` +
  `tests/smoke/ui/` (ADR-04/ADR-14 — live carve assertions, Tier A/B).
- **Tracking issue:** #422 (design review posted 2026-07-03 — the findings below).

## 1. Context

### 1.1 The problem (issue #422)

The IP-side **Suppression** feature ("carve an address out of the block set") has three coupled
defects:

1. **No IPv6 suppression list.** Only `v4suppression` exists; the shell `suppress` pass runs only
   for `_v4` member files (`pfblockerng.inc:16700-16711`, `$vtype == '_v4'`); the UI textarea is
   IPv4-only.
2. **Masks restricted to `/32` or `/24`** (`pfblockerng_ip.php:159` — "Mask must be defined as
   /32 or /24 only").
3. **The hole-punch materialises hosts.** When a `/32` suppression sits inside a feed-listed
   `/24`, `suppress()` (`pfblockerng.sh:471-557`) explodes the `/24` into its 255 individual
   hosts minus the suppressed one (`seq 255`, line 524), then removes remaining whole tokens with
   `grepcidr -vf`.

Issue #422 proposed replacing the mechanism with a pf **pass rule + suppress table**. The design
review on that issue (2026-07-03) rejected that direction — see §1.4 — and this ADR records the
corrected design.

### 1.2 Today — load-bearing facts (all verified live this session)

Empirical results below were produced on a FreeBSD 16 box with the shipped binaries
(`/usr/local/bin/iprange`, `/usr/local/bin/grepcidr`).

- **The explosion is implementation, not physics.** Subtracting a `/b` hole from a containing
  `/a` block, emitted as **covering CIDRs**, costs exactly `b − a` entries — one per prefix-length
  step. Measured: `/24 − /32` = **8** entries, `/16 − /32` = **16**, `/8 − /32` = **24** (vs
  16 777 215 by host enumeration). The IPv6 equivalents: `/64 − /128` = **64** entries,
  `/48 − /128` = 80, absolute worst case `/0 − /128` = 128. For `k` holes in one block the bound
  is `k × (b − a)` — always trivial. The `2^n` framing in #422's original body was an artifact of
  enumerating hosts.
- **`grepcidr -vf` silently no-ops on containing entries** (both families, proven): with feed
  `198.51.100.0/16` and suppression `198.51.100.99/32`, the `/16` line survives intact — the
  suppressed host **stays blocked with no warning**. Same for v6 (`2001:db8:3::/48` vs a `/128`
  inside it). So today's mechanism is correct in exactly two shapes — a bare host token, or the
  *exact* `/24` containing the suppression — and silently ineffective for any other containing
  block. It fails safe (no over-suppression), but the user's exemption just doesn't happen.
- **`grepcidr` handles IPv6 whole-token removal correctly** (proven): a `/128` suppression removes
  a bare v6 host token; rc semantics match v4.
- **`iprange --except` performs true set subtraction** with optimal covering-CIDR output (the
  measurements above). `iprange` is **already a hard dependency** — `pathaggregate`
  (`pfblockerng.sh:48`), the same binary ADR-11 aggregation shells out to.
- **`iprange` is IPv4-only and mangles IPv6 input** (proven): `2001:db8:1::/64` is parsed as
  hostname `2001` ("Ignoring text after hostname"). IPv6 must **never** route through iprange.
- **`iprange` exit codes** (probed): `rc=0` for success **including a legitimately-empty result**
  (everything suppressed — no grepcidr-style `rc=1` quirk); `rc=1` for a missing/unloadable file;
  **`rc=0` even when a token is malformed** — worse, a non-IP token is treated as a **hostname and
  DNS-resolved** (no flag disables resolution; only `--dns-threads/-silent/-progress` exist). A
  stray hostname-shaped token would trigger mid-update DNS lookups and, if it resolved, silently
  subtract the resolved IPs. Inputs must be pre-filtered to strict IP/CIDR shape.
- **pfSense already ships the v6 covering-CIDR emitter.** `ip_range_to_subnet_array($ip1, $ip2)`
  (pfSense `util.inc`, stubbed at `stubs/pfsense/util.php:150`) converts an arbitrary range to the
  minimal covering-CIDR array **natively for IPv6** via fixed-width binary-string math (no GMP).
  Verify at the min-CE dated ref during Phase 5 per the CLAUDE.md upstream-resolution protocol.
- **Suppression applies to the deny folder only** — `Deny_Both|Inbound|Outbound` **and
  `Alias_Deny`** (`pfblockerng.inc:4111-4116`, `adv => TRUE`). Permit/Match/Native and **GeoIP are
  never suppressed** ("Only 'Deny' type Aliases can be suppressed!", `pfblockerng_ip.php:371-374`)
  — a maintainer constraint (BBcan177 on #422/#363) this ADR preserves.
- **`pfbsuppression.txt` is just the decoded user list** (`pfb_create_suppression_file()`,
  `pfblockerng.inc:4954-4963`). The suppress body runs per alias, gated on suppression enabled +
  `_v4` + feed-changed (`in_array($alias, $final_alias_old)`) — the ADR-40 change gates.
- **Dedup/masterfile bookkeeping is v4-only** (`pfblockerng.inc:15847`, `$vtype == '_v4'`): the
  new v6 path has **no** masterfile resync to replicate.
- **Consumers of the post-suppression member files** (why suppression is content-level on
  purpose): pf tables via the ADR-40 mirror/reload model, ADR-11 aggregate aliases, HAProxy `.lst`
  (ADR-12), the Alerts/Reports "is this IP blocked" view, the widget, and **killstates** — the
  state-kill pass excludes suppressed IPs via an exact-IP hashmap (with its own second
  materialisation: `subnetv4_expand` of `/24` entries, `pfblockerng.inc:10151-10163`) and then
  `pfctl -T test`s each state IP against every pfB table (`pfblockerng.inc:10347`).
- **DNSBLIP is an IP feed, not a DNS-side check.** IPs harvested from DNSBL feeds land in
  `DNSBLIP_v4.txt` and ride the ordinary IP-alias pipeline (`pfblockerng.inc:1503-1538`, `15163`).
  `pfb_unbound.py` performs no answer-IP matching. (#422's body mischaracterised this; no Python
  work exists in this ADR.)
- **The Alerts "+" button is a second, independent copy of the hole-punch**
  (`pfblockerng_alerts.php:753-860`): live `pfctl -T delete` + re-add of the 254 sibling hosts,
  refusing anything "blocked by a CIDR other than /24" (line 798). The dashboard widget shares the
  flow.
- **Config storage:** `v4suppression` is an **unregistered** base64 blob (raw
  `config_*_path` at `pfblockerng_alerts.php:254-255,847`); the DNSBL `suppression` blob **is**
  registered (plain entry, no adapters — `pfblockerng_extra.inc:897`) — the registered-blob
  precedent the new key follows.

### 1.3 Why content-level subtraction (the decision in one line)

Because every consumer above reads the member files, a **content-level** fix keeps them all
consistent **for free** — firewall, aggregates, HAProxy, DNSBLIP, reporting, killstates — while
the covering-CIDR math caps the cost at a few dozen entries per hole. No per-consumer suppress
logic, no pf rule surgery, no new tables.

### 1.4 Rejected alternatives

**Pass rule + suppress table (`pfB_Suppress_v4/_v6`) — #422's original proposal. Rejected:**

1. **Security regression.** A `pass quick` above the deny rules affirmatively *accepts* traffic
   and terminates evaluation — the suppressed IP bypasses every rule below, including the user's
   own block rules. "pfB shouldn't block this" becomes "the firewall must allow this". pf has no
   "skip only these block rules" construct.
2. **`Alias_Deny` is undefined.** The user writes those rules; pfBlockerNG cannot place a pass
   rule "above" rules it doesn't own or know.
3. **Killstates regression.** The deny table would still *contain* the suppressed range, so every
   update run would kill the suppressed host's states — cutting the connections of the exact host
   the user exempted.
4. **Fails its own consistency criterion.** HAProxy `.lst` files can't express exclusions; the
   sub-range hole would stay firewall-only.

**pf table `!` negation entries** (`{ 1.2.3.0/24, !1.2.3.4 }`, longest-prefix wins). Punches the
hole in-table with no rule surgery and `-T test` honours it — but every *text* consumer
(aggregates, HAProxy, ADR-40 mirrors, widget counts) would have to learn `!` lines. Same
consistency tax as the pass table. Rejected.

**Porting the explosion to v6** — carving a `/128` from a `/64` by host enumeration is 2^64
entries. Impossible; the reason #422 exists.

## 2. Decision

Keep suppression **content-level**; replace the mechanism with **CIDR set-subtraction** in both
families, lift the mask ceiling, and add `v6suppression`.

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| v4 engine | `suppress()` drops the `grep -F` + `seq 255` + awk explode entirely; one `${pathaggregate} <member> --except <suppfile>` call per (feed-changed) deny member file. Publish gated on `rc=0` (empty output is legitimate — everything suppressed); `rc!=0` keeps the previous list + logs, mirroring the #713 fail-safe pattern |
| iprange input hygiene | both files are pre-filtered to strict IPv4/CIDR token shape before iprange sees them (extend the existing `pfb_is_cidr_token` gate) — a malformed token must never reach iprange's hostname-DNS-resolution path (§1.2) |
| v6 engine | pure PHP set-diff — parse lines to fixed-width binary-string ranges (`ip6_to_bin`-style), subtract the suppress ranges, emit remainders via pfSense's `ip_range_to_subnet_array()`; atomic tmp+rename publish, fail-safe keep-previous on any error. **Never iprange** (§1.2). No masterfile bookkeeping (v4-only, §1.2) |
| v6 wiring | invoked from the alias-build loop (the `pfblockerng.inc:16700` region) for `_v6` member files under the same gates as v4 (suppression enabled + feed-changed), as a direct PHP call — no shell round-trip |
| Config | new `v6suppression` base64 blob beside `v4suppression` (`pfblockerngipsettings/config/0`), **registered** in `pfb_cfg_registry()` (plain, default `''`, like DNSBL `suppression`); `v4suppression` is **also registered** and its raw call sites migrated (prep phase); both added to the sniff's `$registeredPaths`. `pfb_create_suppression_file()` additionally writes `pfbsuppression_v6.txt` |
| UI masks | v4 accepts `/8`–`/32`; v6 accepts `/32`–`/128` (floors = input-sanity guards against fail-open typos; the engine handles any mask). Validation extracted to a pure, PHPUnit-tested helper used by the page |
| Alerts "+" / widget | full rework: locate the containing table entr(y/ies) by streaming the ADR-40 mirror (`/var/db/aliastables/<table>.txt`; fallback `pfctl -T show`), `pfctl -T delete` each + `-T add` the covering-CIDR difference, both families, any mask; drop the "blocked by a CIDR other than /24" refusal and the 254-host loop. Kernel/mirror drift self-heals at the next update (the fresh canonical set differs from the mirror → ADR-40 reloads) |
| killstates | the suppression exclusion becomes prefix-aware via a pure helper (the `ip_in_subnet` loop pattern already used for Permit customlists at `pfblockerng.inc:10296-10301`), covering v4 + v6 suppression entries; local/DNS-IP exact-match exclusions stay hash-based |
| Stats output | `suppress()` keeps the per-alias Pre/Suppress/Master stats table (`wc -l` before/after) |
| Scope of application | unchanged: deny folder only (`Deny_*` + `Alias_Deny`); GeoIP and Permit/Match never suppressed |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before swapping)

- **Set-equivalence:** the published member file's address set is exactly
  `feed set − suppress set`, both families. (The *line shape* may change — §2.3 fork 4.)
- **Fail-safe publish:** any engine error (missing binary, unloadable file, non-zero rc) keeps the
  previous list intact and logs — never a truncated/empty publish on error. An **empty result from
  a legitimate full suppression is a valid publish** (grepcidr's `rc=1` quirk has no iprange
  equivalent; do not reintroduce it).
- **Gating unchanged:** suppression runs only when enabled, only for deny-folder lists, only for
  feed-changed aliases (ADR-40 gates), GeoIP untouched.
- **Masterfile resync** (`dup=on`, v4) still mirrors the post-suppression list, exactly as today.
- **`pfbsuppression.txt` content rules unchanged** for v4 (decoded user list; absent when empty).
- **Alerts "+" keeps immediate effect** (live table punch + config write + suppression-file
  refresh), and its "already exists" dedup checks.
- **Killstates never kills a state whose foreign IP falls inside any suppression entry** (this is
  a *strengthening* for masks the old exact-IP map couldn't express — red→green, not oracle).
- **Existing `/32` + `/24` user entries keep working identically** (upgrade path: no config
  migration — the same tokens, a strictly more capable engine).

### 2.3 Design forks — resolved (user-confirmed 2026-07-03)

Per the house convention, each fork records the chosen option and its alternative. All four were
put to the user on 2026-07-03 and the recommended option was confirmed in each case.

1. **Mask floors — chosen: v4 `/8`–`/32`, v6 `/32`–`/128`.** Floors are pure input-sanity guards
   (a `/1` typo would fail-open half the internet); the engine itself is mask-agnostic.
   *Alternative:* no floor (maximum flexibility, no typo guard).
2. **Config gateway — chosen: register both `v4suppression` and `v6suppression`** and migrate the
   raw call sites (prep, behaviour-preserving, round-trip-pinned). *Alternative:* register only
   the new key (smaller diff; sibling keys diverge in access pattern forever).
3. **Alerts "+" — chosen: full rework (any mask + v6).** *Alternatives:* keep the `/24`-only live
   path (the button keeps refusing the exact cases this ADR unlocks) or config-only + reload hint
   (UX regression).
4. **v4 normalization — chosen: accept full-file `iprange --except` normalization.** When
   suppression is active for a file, adjacent entries may merge and notation normalizes
   (`x.x.x.69` vs CIDR), so widget/report line counts can shift; set-equivalence holds. It runs
   only when the suppress list is non-empty (same effective gate as today), and dedup/aggregation
   paths already normalize elsewhere. *Alternative:* surgical carve of intersecting entries only
   (stable counts; needs an intersect pre-pass + line splicing — more code and branches).

### 2.4 Explicitly kept / out of scope

- **GeoIP:** never suppressed, never CIDR-filtered (maintainer constraint on #422/#363). Untouched.
- **The per-list CIDR-*limit* tunable** ("clamp an over-broad feed entry") and its v6/GeoIP story —
  #363, separate concern.
- **DNSBL whitelist / DNSBL-side suppression** — different subsystem (`pfblockerngdnsblsettings`).
- **The automatic private/reserved v6 exclusion** — already works; not this mechanism.
- **HAProxy/aggregate consumer changes** — none needed; they inherit the corrected content.
- **pf rule or table changes** — none; explicitly rejected (§1.4).
- **`config.xml` schema/migration** — none; new key reads absent→`''` on old configs, unknown key
  is ignored on downgrade (ADR-28 rules).

## 3. Consequences

**Positive**

- Suppression becomes *correct* (containing entries are actually carved — today's silent no-op
  dies), *general* (any mask ≥ floor, both families), and *cheap* (≤ a few dozen entries per hole).
- Every consumer inherits the fix with zero consumer-side changes; killstates and Alerts "+" get
  strictly more capable.
- Less code: the explode machinery, the 254-host alerts loop, and the `/24`-only special cases all
  delete.
- The security-critical engines are pure and off-appliance-testable (shellspec + PHPUnit).

**Negative / risks**

- **iprange DNS-resolution hazard** (§1.2): a malformed token is silently DNS-resolved with
  `rc=0`. Mitigated by strict pre-filtering on both inputs (contract §2.2) — pinned by a spec that
  feeds a hostname-shaped token and asserts it never reaches iprange.
- **Visible count/shape shifts** when suppression is active (fork 4) — widget/report line counts
  may drop as entries merge. Documented; set-equivalence is the invariant.
- **PHP v6 diff performance** is unproven at scale. v6 feeds are small today, but the engine gets
  a measured bound (§7 reject criteria) before acceptance.
- **shellspec needs the real `iprange`** for the P3 red→green semantics (a grep-based stub cannot
  fake set subtraction): CI installs it; locally the spec skips when absent (house pattern — CI is
  the hard gate).
- **Live-punch scan cost:** the alerts "+" streams the mirror file (can be millions of lines) with
  `ip_in_subnet` per line — seconds-scale worst case for a one-click admin action. Acceptable;
  noted in help text if measurably slow.

## 4. Requirements (acceptance)

1. A host suppressed inside a **containing** feed entry (`/16` v4, `/64` v6) is absent from the
   loaded pf table while sibling addresses remain present — proven live (smoke), asserting the
   **before-state first** (host blocked pre-suppression).
2. `v6suppression` exists end-to-end (config + UI + engine + suppression file) with the same UX as
   v4.
3. v4 masks `/8`–`/32` and v6 masks `/32`–`/128` validate; out-of-range masks produce input errors.
4. No materialisation anywhere: the published files contain covering CIDRs, never host explosions;
   the alerts "+" punches any-mask holes live, both families.
5. Fail-safe publish proven for: missing binary, unloadable file, malformed token (never reaches
   iprange), legitimate full suppression (empty file published).
6. Killstates spares states of suppressed IPs at any mask, both families.
7. Config round-trip pinned for both registered keys; sniff `$registeredPaths` updated; raw call
   sites migrated.
8. Green CE+Plus smoke/UI fan-out (Tier A on touched pages; Tier B for the multi-step save flow
   and the alerts "+" e2e).

## 5. Constraints (from CLAUDE.md)

- **Shell:** POSIX sh only; quote expansions; `LC_ALL=C` on any `sort`/`comm` over machine data;
  add-on binaries via `path*` vars (`pathaggregate`, `pathgrepcidr`); guard missing binaries like
  `suppress()` does today (`pfblockerng.sh:472-476`).
- **PHP:** 8.3, tabs, uppercase `TRUE`/`FALSE`; no `die()`/`exit()` in library code; registered
  keys only via `PfbConfig` (the sniff enforces once registered); pure helpers take inputs as
  arguments so they test off-appliance; pfSense functions resolved/stubbed per the dated-ref
  protocol (`ip_range_to_subnet_array` verified at min-CE; faithful double in
  `pfsense_doubles.php`, pinned by vectors).
- **No Python on the appliance** (the v6 engine is PHP; `pfb_unbound.py` is untouched).
- **Tests:** the five non-negotiables — red→green for every behaviour change (the containing-entry
  carve, mask lift, killstates, alerts), oracles for behaviour-preserving prep, branch coverage
  (each family × each gate × fail-safe), BDD style for the multi-step smoke journeys, expected-vs-
  actual diagnostics on every custom matcher/poll.
- **Front-end:** Tier A required on every touched page; Tier B required for the v6 textarea
  save→persist flow and the alerts "+" e2e (multi-step by definition).
- **Flow:** worktree + rebase-only PR via `/pr-merge-flow`; plan-with-higher-model / implement-
  with-Sonnet 5; rebase onto `origin/devel` before every push/dispatch.

## 6. Action plan (phases)

Each phase is one commit on `adr/53-ip-suppression-set-subtraction`, leaves the full suite green,
and is independently revertible.

### Phase 1 — `suppress()` oracle (shellspec, behaviour-preserving)

Prompt: `01_Suppress_Oracle.txt`

- New `tests/shell/pfblockerng_suppress_spec.sh` pinning **today's** `suppress()`: bare-token
  removal; the exact-`/24` explode (255 hosts, `/24` line gone, dupfile dedup); the
  **containing-`/16` silent no-op** (the defect, pinned as today's oracle — flips in Phase 3);
  `rc>=2` keep-previous (#713); masterfile resync under `dup=on`; suppression-file-absent no-op.
- Follow the `pfblockerng_original_count_spec.sh` harness pattern (`BeforeAll 'pfb_source'`,
  stubbed `path*` binaries).
- Green before and after this phase (oracle; regression guarantee only).

### Phase 2 — Config-gateway prep: register `v4suppression` (behaviour-preserving)

Prompt: `02_Config_Gateway_Prep.txt`

- Register `v4suppression` in `pfb_cfg_registry()` (plain blob, default `''`, correct `since` per
  `docs/misc/config-gateway.md`); add its path to the sniff's `$registeredPaths`; migrate the raw
  `config_*_path` call sites (`pfblockerng_alerts.php:254-255,847` + any others the sniff then
  flags) to `PfbConfig`.
- Round-trip + default-on-absent pinned (`CfgAdaptersTest` conventions); PHPCS clean.

### Phase 3 — v4 engine swap: `iprange --except` (red→green)

Prompt: `03_V4_Engine_Swap.txt`

- Rewrite `suppress()`: strict token pre-filter on both inputs → single
  `${pathaggregate} <member> --except <supp>` → rc-gated atomic publish (`rc=0` publishes, empty
  included; else keep-previous + log). Delete the explode/dupfile machinery; keep stats +
  masterfile resync.
- Flip the Phase-1 containing-entry oracle to the carve assertion (16 covering CIDRs; suppressed
  host absent; siblings present) — **fails on pre-phase code, passes after**. Update the `/24`
  case to assert 8 covering CIDRs, not 255 hosts. Add the hostname-token spec (never reaches
  iprange; list kept). Real `iprange` in CI (skip-if-absent locally).

### Phase 4 — v4 UI mask lift (`/8`–`/32`)

Prompt: `04_V4_Mask_Lift.txt`

- Extract validation to a pure `pfb_validate_suppression_line($line, $family): ?string` helper
  (PHPUnit red→green: `/16` rejected today → accepted; `/7` rejected; garbage/comment handling);
  `pfblockerng_ip.php` uses it; update the `/32 or /24 only` help texts.
- Tier A on the IP settings page.

### Phase 5 — v6 set-diff engine (pure PHP, TDD)

Prompt: `05_V6_Diff_Engine.txt`

- Pure `pfb_cidr_subtract_v6(array $cidrs, array $holes): array` on binary-string ranges +
  `ip_range_to_subnet_array()` (verify at the min-CE dated ref; faithful double for PHPUnit,
  vector-pinned), and `pfb_suppress_file_v6($file, $suppfile): bool` (streaming, atomic,
  fail-safe).
- PHPUnit red→green: known vectors (`/64 − /128` = 64 entries; hole==entry; hole outside; adjacent
  holes; multi-hole; full suppression → legitimately empty) + set-equivalence property checks via
  an independent range representation (inet_pton hex compare, not the engine's own helpers).
  Informational perf measurement (100k-line input) recorded for the §7 bound.

### Phase 6 — v6 config + UI + update-flow wiring

Prompt: `06_V6_Config_UI_Wiring.txt`

- Register `v6suppression` (plain blob + sniff path + round-trip test); v6 textarea on
  `pfblockerng_ip.php` (validator family=v6, `/32`–`/128`); `pfb_create_suppression_file()` writes
  `pfbsuppression_v6.txt`; call `pfb_suppress_file_v6()` from the alias-build loop for `_v6` under
  the v4-equivalent gates; stats-log parity.
- Tier A (page renders with the new section) + Tier B (fill → save → re-GET → persisted).

### Phase 7 — killstates prefix-aware exclusion (red→green)

Prompt: `07_Killstates_Prefix.txt`

- Pure `pfb_ip_suppressed(string $ip, array $entries): bool` (both families); replace the
  suppression part of the exact-IP map + `subnetv4_expand` block (`pfblockerng.inc:10151-10163`)
  with it; include `v6suppression` entries for v6 states; local/DNS exact exclusions unchanged.
- PHPUnit red→green: a state IP inside a `/16` suppression entry is spared (old code kills it).

### Phase 8 — Alerts "+" / widget live punch (any mask + v6)

Prompt: `08_Alerts_Live_Punch.txt`

- Rework the `addsuppress` flow (`pfblockerng_alerts.php:753-860` + the widget's shared path):
  locate containing entries (mirror-file stream, `pfctl -T show` fallback), `-T delete` +
  `-T add` the covering-CIDR difference (`ip_range_to_subnet_array` both families), write the
  correct family list via `PfbConfig`, refresh suppression files; delete the 254-host loop and the
  `/24`-only refusal.
- Tier A (alerts page) + Tier B e2e (seed a blocked alert from a fixture feed → click "+" →
  config updated, table hole punched, sibling still blocked).

### Phase 9 — Live-VM smoke, docs, DoD

Prompt: `09_Smoke_Docs_DoD.txt`

- `tests/smoke/test_smoke_suppression.py`: fixture feeds list `198.18.0.0/16` (v4) and a
  `2001:db8::/64` (v6); assert **before-state** (host in table via `pfctl -T test`), add the
  suppression, force update, assert host absent + sibling present + mirror holds covering CIDRs.
  Fixtures README updated; inert ranges only (RFC 2544 / RFC 3849 — never RFC 1918, killstates
  excludes it).
- `docs/misc/architecture-notes.md`: "IP suppression set-subtraction (ADR-53)" section (mechanism,
  the covering-CIDR math, the iprange hazard, consumer inheritance).
- CE+Plus fan-out (impacted scope + the new module); record results in `RESULTS/`.

## 7. Definition of done

- Phases 1–9 landed via the standard PR flow; `python -m pytest`, `vendor/bin/phpunit`,
  `shellspec`, PHPCS/PHPStan/ruff all green.
- The acceptance requirements (§4) each map to a green automated test; the live-VM fan-out (CE +
  Plus) is green including `test_smoke_suppression.py` and the alerts "+" Tier B e2e.
- **Manual smoke checklist (owner: maintainer, documented out-of-CI confirmation, not a gate):**
  on a real box with a production feed set — suppress a host inside a broadly-listed range, confirm
  it passes while siblings stay blocked; confirm an existing `/32`+`/24` suppression list upgrades
  with identical behaviour; click "+" on a live alert blocked by a `/16`.
- Flips to **Accepted** on the green fan-out alone (CLAUDE.md "ADR acceptance").
- **Reject/revisit criteria:**
  - If the P3 spec work shows `iprange --except` cannot be gated fail-safe (e.g. an error mode
    that is indistinguishable from a legitimate empty result), stop and redesign the v4 engine
    (candidate fallback: PHP set-diff for v4 too, sharing the P5 engine).
  - If the P5 measurement shows the PHP v6 diff cannot process a **100k-line** member file in
    **< 5 s** on appliance-class hardware, the v6 wiring does not ship as-is — revisit (C helper
    via iprange-style tooling, or a pre-partitioned diff) before Phase 6.
  - If the live smoke shows consumer drift (aggregate/HAProxy/report reading a different set than
    pf), the content-level premise itself is violated — halt and re-audit before acceptance.

## Amendment 1 (2026-07-18, issues #1467/#1470/#1471, PR #1503) — live punch: live-only snapshot, streaming plan, fail-closed serialized apply

Three decisions in the "Alerts \"+\" / widget" row of §2.1 (and the §3 scan-cost note) are
superseded by the live-punch redesign landed in PR #1503:

1. **Snapshot source.** "Locate the containing table entr(y/ies) by streaming the ADR-40 mirror
   (`/var/db/aliastables/<table>.txt`; fallback `pfctl -T show`)" no longer holds: live
   `pfctl -t <table> -T show` is the SOLE snapshot source and the mirror is never read
   (`pfb_live_table_snapshot()`, `$aliasdir` parameter retained unused). A live punch never
   rewrites the mirror, so the mirror-first read made a SECOND punch inside the same containing
   entry plan against pre-first-punch state and silently revert the first carve (issue #1467).
   The original "kernel/mirror drift self-heals at the next update" note remains true but is no
   longer relied on for punch planning. A snapshot capture failure (temp-file creation, non-zero
   pfctl exit, unreadable capture) now throws instead of reading as an empty table, so "not
   currently blocked" is only ever reported from a successfully captured empty plan.
2. **Streaming.** The §3 note "streams the mirror file … with `ip_in_subnet` per line" is
   strengthened: the snapshot is a lazy `\Generator` (temp file cleaned in `finally`, including
   abandoned iteration) and `pfb_live_punch_plan()` consumes any `iterable`, retaining only the
   containing entries — the web-UI process no longer materializes the table membership
   (issue #1471; the pre-#1503 code buffered every line into an array).
3. **Apply.** The punch is applied by `pfb_live_punch_run()`/`pfb_live_punch_apply()`
   (issue #1470): covering-CIDR remainders are added FIRST and containing entries deleted LAST
   (every intermediate state blocks a superset of the target — a mid-sequence pfctl failure can
   never unblock the containing range), every exec's status is checked via
   `pfb_pfctl_op_failed()`, an add failure rolls back best-effort and reports, and the whole
   snapshot→plan→apply sequence is serialized under the issue-#1175 feed-pass lock so a
   concurrent ADR-40 replace cannot interleave (add phase → replace → delete phase would
   otherwise open the full containing CIDR until the next reload). The punch deliberately does
   NOT route through `pfb_pfctl_table_op()`: its ADR-61 sync-status ledger entry would let the
   retry sweep mirror-replace the table and revert other valid live punches. The temporary
   Unlock records nothing (and says so) when the host is not currently blocked, when a pass is
   mid-update, or when the punch fails; the Suppression "+" keeps its standing-exemption
   semantics (the customlist write proceeds; a live failure is surfaced and heals at the next
   reload).

Pinning tests: `tests/php/LiveTableSnapshotTest.php`, `tests/php/LivePunchPlanTest.php`,
`tests/php/AlertsLivePunchApplyTest.php`, `tests/php/LivePunchRunTest.php`; live Tier-B
`tests/smoke/ui/test_alerts.py` double-punch (v4+v6) and not-blocked-honesty e2e (executed red
on the pre-fix tree and green on the fix, plus the pre-existing carve/relock suite on the final
tip). Sibling unchecked-exec sites outside the punch path are tracked in issue #1505.
