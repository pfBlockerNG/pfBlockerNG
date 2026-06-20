# ADR-25: Per-client Group Policy for DNSBL blocking (incl. time scheduling)

- **Status:** **Proposed** (2026-06-14)
- **Date:** 2026-06-14
- **Folds in:** issue #384 (Redmine #11099) — "DNSBL blocking by schedule" (block during
  school hours). Scheduling is a per-group axis here, not a separate feature.
- **Branch:** `adr/25-group-policy-dnsbl` (off `devel`; slug per CLAUDE.md "Branch naming")
  / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (decision path +
  build), `pfblockerng.inc` (manifest + config + migration), `src/usr/local/www/pfblockerng/`
  (new policy-group UI), `config.xml` schema, `stubs/`, `tests/`.
- **Target runtime:** Python 3.11+ in Unbound `pythonmod`, **stdlib only** (no external
  deps in the chroot); PHP 8.3 (pfSense CE 2.8).
- **Test suite:** `tests/` (pytest — Python decision + build), `tests/php/` (PHPUnit —
  manifest/config/migration helpers), `tests/smoke/` (ADR-04 live VM + ADR-14 `ui_render`).

---

## 1. Context — Today

### 1.1 The DNSBL decision is global and client-agnostic

Every LAN client gets the **same** DNSBL verdict for a name. The query-time matcher
`evaluate_domain(q_name, q_name_original, tld, is_cname, cfg, containers)`
(`pfb_unbound.py` ~4608) returns a `DnsblDecision` from the queried name alone — the
**client source IP is never an input**. The verdict is memoised in the unified
**domain-keyed** decision cache `decisionDB[name] = DnsblDecision` (ADR-15), cleared on a
zero-downtime swap (ADR-10).

### 1.2 The client IP is, however, already in hand

`operate(id, event, qstate, qdata)` (~5001) extracts the client source IP **today** via
`get_q_ip(qstate)` (~1637 → `qstate.mesh_info.reply_list.query_reply.addr`) and uses it
**only for log attribution** (`pfb_addr`, ~5204). **No new Unbound API plumbing is needed
to make decisions client-aware** — the load-bearing premise of this ADR holds.

### 1.3 A primitive "Group Policy" already ships — one binary bypass list

pfBlockerNG already exposes a feature literally named *Group Policy* but it is a **single
global bypass list**:

- Config: `pfb_gp` (on/off) + `pfb_gp_bypass_list` (textarea of client IPs), under
  `dnsblconfig` (`pfblockerng.inc:1273-1274`).
- `pfblockerng.inc:4133-4148` writes an ini `[GP_Bypass_List]` section into the file the
  python module reads; `pfb_unbound.py:1042-1053` loads it into `gpListDB`; the decision
  path (`:5201-5210`) sets `bypass_dnsbl = True` when `gpListDB.get(q_ip) is not None`.
- Semantics: a listed IP **skips all DNSBL**; everyone else gets **full DNSBL, Block**.
  Matching is **exact-IP only** (`gpListDB.get(q_ip)`, a dict lookup — no CIDR).
- A runtime `python_control addbypass/removebypass [duration]` path mutates `gpListDB`
  in place (`:5125-5178`) — a transient per-IP bypass.

This is exactly **one group with one action (bypass)**. This ADR generalises it.

### 1.4 DNSBL feed/alias organisation (the unit a group will subscribe to)

DNSBL feeds are grouped under **aliases**: a settings row builds alias
`DNSBL_{aliasname}` (`pfblockerng.inc:9342`) whose `$list['row']` feeds each carry
`header` / `url` / `state` / `custom`. The per-feed manifest entry the python build
consumes is `{ 'feed', 'group' (=alias), 'log', 'format', 'provenance' }`
(`pfblockerng.inc:3744`, `:9429`). The per-feed `log` flag already encodes an
action/shape: `0`=block+log, `1`=VIP+log, `2`=null no-log, `3`=NXDOMAIN+log,
`4`=NXDOMAIN no-log (`:9384-9400`). The manifest is published atomically and applied by
the ADR-10 watcher via the `pfb_py_reload` sentinel.

### 1.5 Load-bearing constraints

- `pfb_unbound.py` is **stdlib-only** and **chrooted at `/var/unbound`** — every file it
  reads must be chroot-relative; no external Python deps.
- **No live Unbound in CI.** The decision/build logic is unit-tested off-appliance against
  golden oracles (ADR-06/07); end-to-end behaviour is the live-VM smoke (ADR-04). The
  smoke harness **probes on-box from `127.0.0.1`** — it has **no built-in multi-source-IP
  client simulation**, which this feature fundamentally needs (see §7).
- The decision cache is **domain-keyed**. Any client-dependent verdict that is cached
  domain-only is a **cross-client correctness bug**.

### 1.6 Scheduling is requested but unwired (issue #384 / Redmine #11099)

A standing feature request asks for **DNSBL blocking by schedule** — "enable/disable it
during school hours". pfSense already ships a native scheduler: the `<schedules>` config
section (Firewall > Schedules), referenced by firewall rules via a `sched` name and evaluated
by `filter_get_time_based_rule_status()`. None of it is wired into the DNSBL decision path —
the only time-driven element today is the hourly feed-update cron (`pfb_interval`), which
governs list *refresh*, not whether blocking is *active*. Per-client policy and time-of-day
gating are the same shape of problem (a group of clients gets a different verdict under a
condition), so this ADR folds scheduling in as a **per-group axis** rather than a parallel
feature — the maintainer's call on the issue.

---

## 2. Decision

Replace the single global bypass with **N named policy-groups**, Pi-Hole–style
(<https://docs.pi-hole.net/group_management/example/>; Pi-Hole's FTL is open source and was
read as prior art). A policy-group binds **client CIDRs** to **a subset of DNSBL aliases**
plus **per-group allow/deny domain rules**, **an action tier (Block / Warn)**, and an
**optional schedule** (a named pfSense firewall Schedule) that gates **when the group is in
force**. A client belonging to no group (by CIDR) falls to a **default group** = today's
behaviour (all aliases, Block) → **backward compatible**.

**Schedules reuse pfSense's native scheduler, not a new one.** A group carries a `sched`
reference to an existing `<schedules>` entry; we serialise that schedule's time ranges into
the manifest and evaluate "is it active now" in the chroot. No schedule ⇒ the group is
**always in force** (today's behaviour). This keeps one schedule concept for the admin
(reused across firewall rules and groups) at the cost of re-implementing the active-window
test in the stdlib-only Python module (§2.4, §3).

### 2.1 Resolution model (the architecture that keeps the domain-keyed cache valid)

The expensive matching work is **group-independent**; only the *action applied to a match*
is group-dependent. We exploit that with an **alias-membership bitmask**:

| Concern | Where | Shape |
|--------|-------|-------|
| Which aliases a domain is in | build (`pfb_unbound.py`) | `domain → int bitmask` over aliases (one bit per `DNSBL_*` alias). A domain in two aliases gets both bits. **Group-agnostic ⇒ stays in the domain-keyed `decisionDB`.** |
| Which groups a client belongs to | per-IP, cached | client source IP → set of policy-groups whose CIDR set contains it (`gpClientGroups`, **time-independent** — cached per IP, cleared only on an ADR-10 swap). |
| Whether a group is **in force now** | per-query | `schedule_active(group)`: *now* falls within a serialised time range of the group's referenced pfSense Schedule. **No `sched` ⇒ always in force.** Cheap (a handful of ranges); evaluated live so it tracks time boundaries. |
| Which aliases a client subscribes to | per-query | **union** of the masks of the client's **active** groups (belongs-to ∩ in-force-now). |
| Block test | per-query | `domain_mask & client_mask != 0` → O(1) int AND. |
| Allow / deny domain rules | per-query | per-group exact/suffix domain sets, unioned across the client's **active** groups. |
| Action tier (Block vs Warn) | per-query | strictest tier among the client's **active** groups whose subscription matched. |

**Membership vs enforcement (what makes scheduling expressible).** Belonging to a group is by
**CIDR** and is time-independent; *enforcement* is gated by the group's **schedule**. The
resolution starts from the client's groups, then narrows to the active ones:

- Client belongs to **zero** groups (by CIDR) → **default group** (all aliases, Block =
  today). Schedule plays no part here.
- Client belongs to ≥1 group but **none is in force now** → **PASS** (it is governed by
  groups, all currently off — *not* the global default). This is what lets "block only during
  school hours" mean *unrestricted otherwise*: put the clients in a scheduled blocking group;
  outside the window the group is inert and they resolve freely, instead of falling back to
  the all-Block default.
- Client has ≥1 **active** group → apply the merge precedence below over the active set.

**Merge precedence (deterministic, union semantics — over the client's ACTIVE groups):**

1. **Allow-domain** match in any active group → **PASS** (allow always wins — Pi-Hole rule).
2. else **Deny-domain** match in any active group → **BLOCK**.
3. else **subscribed-alias** match (`domain_mask & client_mask`) → action = **strictest
   tier** among matching active groups (**Block > Warn**); Warn = resolve normally **and log**.
4. else → **PASS**.

The legacy `pfb_gp`/`pfb_gp_bypass_list` bypass = a migrated group with an **empty alias
subscription, no deny rules, and no schedule** (always in force) → naturally PASS for its
members under the same engine.

### 2.2 The cache-bleed correctness problem — SPIKE-gated (Phase 1)

A client-dependent verdict has a subtler hazard than the cache **key**: Unbound's **C
message cache**. When a *pass/warn* client resolves a listed name, Unbound caches the
**real** answer; a subsequent *block* client served from that C-cache **never re-enters
`operate()`** and **silently escapes the block**. (ADR-15/#43 already had to set
`qstate.no_cache_store` on synthetic block replies for a related reason; this generalises
the hazard to *all* policy-relevant names.) This likely already affects the legacy bypass
feature, undocumented.

**Scheduling generalises the same bleed to a *time* axis.** A policy-relevant name resolved
while a group is **off-schedule** (verdict PASS) gets its real answer C-cached with a normal
TTL; when the schedule window opens, a query that should now **block** is served the stale
cached answer and escapes — the cross-client bleed, triggered by a clock boundary instead of
a second client. The chosen scheme must close **both**: scheme (a) does so for free, since a
name carrying any alias bit is policy-relevant and re-enters `operate()` every query
regardless of the hour (so no schedule-boundary cache flush is needed); a scheme that caches
policy-relevant answers (b/c) must prove it invalidates across a window edge. Phase 1
reproduces the **time-transition** variant alongside the cross-client one.

**This is the premise that must be proven before the feature is built.** Phase 1 is a
**research spike** (no shipped production code) that:

- **Reproduces** the cross-client C-cache bleed on a live VM (pass client warms cache →
  block client escapes), pinning it as the concrete problem.
- **Evaluates** candidate schemes and picks one on evidence:
  - **(a)** `no_cache_store` on every policy-relevant name when group policy is enabled
    (listed names re-evaluated per query; non-listed names cache normally). Simple, but
    costs C-caching for listed names.
  - **(b)** Per-group-mask keying of the synthetic answer / selective store so identical
    group-masks share cache. More complex; needs proof it composes with ADR-10/15.
  - **(c)** Unbound **`views` + `access-control-view`** mapping client CIDRs → views with
    per-view local data. Native, but per-view local-zones at blocklist scale (millions ×
    #groups) likely explode memory — the very reason pfBlockerNG moved off local-zones.
    Evaluate and most likely **reject with measured evidence**.
- **Benchmarks** the viable candidate(s): warn/pass-client latency on listed names and
  memory vs #groups, **with methodology and a kill-threshold**.

**Reject criterion:** if no scheme keeps per-client blocking correct without an
unacceptable latency/memory regression (threshold set in Phase 1), the ADR is **reduced**
(fall back to action-tier-only, no per-feed subsetting) or **REJECTED** — exactly the
ADR-01 outcome the process exists to surface. Phases 3–7 adopt the Phase-1 winner.

### 2.3 Semantics that MUST be preserved (the contract — pin with tests before swapping)

- **Group policy OFF (default): byte-identical behaviour.** `evaluate_domain` decisions
  unchanged (ADR-06/07 oracles green); manifest with no groups produces today's output;
  `decisionDB`/`gpListDB` behaviour unchanged.
- **Legacy bypass preserved.** Existing `pfb_gp`/`pfb_gp_bypass_list` configs keep working
  (migrated to a Bypass group) — a listed IP still skips all DNSBL; `python_control
  addbypass/removebypass [duration]` still works.
- **Default group = today.** A client matching **no group by CIDR** gets all aliases + Block.
- **No schedule ⇒ always in force.** A group without a `sched` reference behaves exactly as
  an unscheduled group would — its enforcement never depends on the clock. Removing/renaming
  the referenced pfSense Schedule degrades safely to "always in force" (fail-open to the
  group's own rules, never a crash). A client that belongs to groups but has **none active**
  resolves freely (PASS) — it does **not** silently fall to the all-Block default.
- **Block shapes unchanged** (NOERROR+VIP or NULL per per-feed `log`; never NXDOMAIN for a
  feed match). Warn does not invent a new shape — it **resolves + logs**.
- **ADR-10 swap + ADR-15 cache invariants hold:** a swap clears `decisionDB` AND the new
  per-client caches (`gpClientDB`); no torn decision across a CNAME chain.
- **PFBL-01 validation** on every new manifest write / CIDR / domain-rule input
  (`pfb_filter`/`sanitize_ipaddr`), enforced by the PHPCS sniff.

### 2.4 Explicitly kept / out of scope

- **Scheduling reuses pfSense Schedules — no custom scheduler.** A group references an
  existing `<schedules>` entry by name (one schedule per group; compose finer windows by
  splitting into multiple groups). We do **not** build a new time-window UI/store. The schedule
  *definition* lives in pfSense core config; we only serialise its resolved ranges into the
  manifest and evaluate them in the chroot. **Time-of-day correctness in the Unbound chroot is
  an implementation item** (Phase 4/5): `time.localtime()` resolves against the chroot's
  `/var/unbound/etc/localtime`, which may be absent → wrong window. The build must serialise
  ranges in a timezone-explicit form (or ensure zoneinfo is reachable in-chroot); proven by a
  Phase-7 schedule smoke. Inverted/"all except" windows are out of scope (express the inverse
  as the group's active window).
- **Per-feed (sub-alias) subscription** — the subscribable unit is the **DNSBL alias**
  (`DNSBL_*`), not the individual feed. Per-feed is a possible later ADR; the bitmask
  design does not preclude it.
- **Client identity beyond IP/CIDR** (MAC, hostname, interface, DHCP-derived) — Pi-Hole
  supports these; this ADR is **IP/CIDR only** (matches "client IP ranges").
- **Per-group SafeSearch / noAAAA / TLD / IDN axes** — group policy governs **DNSBL
  alias/allow/deny** only in this ADR; the other axes stay global.
- **A "warning/continue" sinkhole page** — Warn = resolve+log (chosen); a click-through
  block page is out of scope.
- **IP-side (firewall) per-group behaviour** — DNSBL only.

---

## 3. Consequences

### Positive

- True per-client DNSBL policy (Pi-Hole-style): different client ranges get different
  aliases blocked, warned (logged), or passed — the requested capability.
- **Scheduling (issue #384) for free on the same engine:** a group's enforcement is gated by
  a reused pfSense Schedule, so "block during school hours" is one group with a `sched` and no
  new subsystem. Time gating is a cheap per-query active-window test; the expensive domain
  match stays cached and group-/time-agnostic.
- The **bitmask + group-agnostic matcher** keeps `decisionDB` domain-keyed: the expensive
  match is computed once per name regardless of #groups; only a cheap per-IP mask + int
  AND is added. Memory scales with #aliases (a single int per domain), not #groups.
- Generalises and **subsumes** the legacy bypass with no behaviour loss; unmatched clients
  are unchanged.
- The Phase-1 spike makes the one genuine architectural risk (cache bleed) a **measured,
  falsifiable** decision instead of a latent bug.

### Negative / risks

- **The cache-bleed scheme may cost C-caching** for listed names (Phase-1 dependent) →
  added upstream resolution latency/load for pass/warn clients on listed names. Bounded by
  the kill-threshold; could reduce scope.
- **Bigger surface**: build, decision path, manifest, config + migration, a new UI page,
  and multi-source smoke. Phased to keep each commit green and behaviour-preserving early.
- **CI cannot fully validate** per-client behaviour (no multi-source-IP simulation today) →
  a real share of validation falls to a **maintainer manual smoke** (§7) plus a smoke
  harness extension for source-bound queries.
- **Union merge** can surprise an admin (a permissive group widens a restrictive one);
  mitigated by the allow>block>warn precedence being documented in the UI.
- **Schedule timezone in the chroot** is a correctness trap: a naive `time.localtime()` in
  `/var/unbound` can evaluate the window in UTC and block/unblock at the wrong hour. Bounded
  by serialising ranges TZ-explicitly + a Phase-7 schedule smoke that asserts the boundary,
  but it is a real surface the spike/Phase-4 must close (§2.4).

---

## 4. Requirements (acceptance)

- Admin can define ≥1 policy-group: name, enabled, client CIDR list, subscribed `DNSBL_*`
  aliases, action tier (Block/Warn), allow-domain + deny-domain lists, and an **optional
  schedule** (a pfSense firewall Schedule selected from the existing ones).
- A query's verdict follows §2.1 resolution + §2.3 precedence, by client source IP **and the
  current time** (a group enforces only while its schedule is active; no schedule ⇒ always).
- A scheduled blocking group blocks inside its window and the same clients resolve freely
  outside it (issue #384), without falling back to the all-Block default.
- Group policy OFF ⇒ byte-identical to today; legacy bypass auto-migrates and still works.
- Decision correctness holds across the C-cache (Phase-1 scheme, **incl. schedule-window
  transitions**), ADR-10 swaps, and CNAME chains.
- All gates green: `pytest`, `ruff`, `mypy tests/`, `php -l`, PHPStan, PHPUnit, PHPCS
  (PFBL-01), `ui_render`.

## 5. Constraints (from CLAUDE.md)

- Python: 4-space, stdlib-only, chroot-relative paths, typed new fns, no bare `except`,
  new injected Unbound symbols (if any) declared in `stubs/python/unboundmodule.py`.
- PHP: tabs, PHP 8.3, no `die()/exit()` in lib code, new pfSense fns stubbed in
  `stubs/pfsense/` + doubled in `tests/php/pfsense_doubles.php`; PFBL-01 sniff scope
  updated for any new in-scope input-handling function.
- Naming: follow `pfb_*` / `DNSBL_*` / `gp*` conventions already in the files.
- Each phase = one commit, `pytest` green; behaviour-preserving where marked.

---

## 6. Action plan

Early phases are the behaviour-preserving **preparatory de-risking** pass; the cache spike
(Phase 1) gates the rest.

### Phase 1 — SPIKE: cache-bleed reproduction + scheme selection (may REJECT)

- Prompt: `01_Spike_Cache_Strategy.txt`
- **Research only — no production code shipped** (throwaway harness allowed).
- Reproduce the cross-client C-cache bleed on a live VM; pin it. **Also reproduce the
  schedule time-transition variant** (off-schedule PASS warms the cache → window opens →
  block escapes) and confirm the chosen scheme closes it.
- Evaluate schemes (a)/(b)/(c) from §2.2; benchmark the viable one(s) — methodology +
  kill-threshold.
- **Output:** `RESULTS/01_Results.txt` recording the chosen scheme (or a reduce/reject
  recommendation) with numbers. Phases 3–7 adopt it.
- Tests: a benchmark harness + a documented reproduction; no unit suite change.

### Phase 2 — Prep: extract + pin current behaviour (behaviour-preserving)

- Prompt: `02_Extract_And_Oracle.txt`
- Extract the group-agnostic base match into a named function; add golden tests freezing
  current `evaluate_domain` decisions (oracle).
- Pin the legacy `gpListDB` bypass semantics (exact-IP bypass; `python_control`
  add/remove/duration) with tests asserting **off-state then on-state**.
- Add a pure **CIDR client→group-mask resolver** (interval/longest-prefix over CIDRs →
  unioned mask) + unit tests; **not wired** into the decision path yet.
- Tests: oracle + bypass + CIDR-resolver unit tests, all green.

### Phase 3 — Build: alias-membership bitmask (feature-flagged, off ⇒ identical)

- Prompt: `03_Build_Bitmask.txt`
- Extend the build so `data_db[domain]` (and the zone map) carry an **alias bitmask**;
  define the `DNSBL_*` alias → bit assignment. With group policy OFF the observable
  manifest/decision output is unchanged.
- Tests: a domain in 2 aliases → both bits; mask intersection; off-state parity.

### Phase 4 — Config + manifest + migration (PHP)

- Prompt: `04_Config_Manifest_Migration.txt`
- `config.xml` schema for policy-groups (name, enabled, CIDRs, subscribed aliases, tier,
  allow/deny domains, **optional `sched` schedule reference**) + the default group.
- Migrate legacy `pfb_gp`/`pfb_gp_bypass_list` → a Bypass group (idempotent; absent ⇒
  no-op).
- Extend the manifest: groups, alias→bit map, per-group subscribed bitmask, client-CIDR→
  group map, allow/deny lists, default-group policy, **and per-group serialised schedule time
  ranges** (read from the pfSense `<schedules>` section; TZ-explicit so the chroot evaluates
  the right wall-clock window). PFBL-01 validation on all inputs. A dangling/removed schedule
  ref serialises as "always in force" (fail-open).
- Tests (PHPUnit): schema decode, migration (before legacy → after group; absent → no-op),
  manifest shape before/after, bitmask map, **schedule serialisation (ranges + dangling-ref →
  always-on)**.

### Phase 5 — Python decision layer + Phase-1 cache scheme

- Prompt: `05_Decision_Layer.txt`
- Load manifest groups; build `gpClientGroups` (client IP → CIDR-matched groups, time-
  independent, cached); per query compute the **active** subset via `schedule_active(group)`
  over the serialised ranges (no `sched` ⇒ always active); implement §2.1 membership-vs-
  enforcement + §2.3 precedence over the active set; Warn = resolve+log; apply the Phase-1
  cache scheme. Clear the per-IP cache on ADR-10 swap.
- Tests: every branch — allow-wins, deny, subscribed-hit Block, subscribed-hit Warn,
  no-match PASS, default group, union across 2 groups, migrated legacy bypass; **schedule:
  in-window enforces vs out-of-window PASS (assert before+after across the boundary), no-sched
  always-on, belongs-but-all-inactive ⇒ PASS not default, dangling ref ⇒ always-on**;
  before/after transition tests; CNAME-chain + swap-invalidation cases.

### Phase 6 — Web UI (policy-group management)

- Prompt: `06_WebUI.txt`
- New `www/pfblockerng/` page(s) to list/add/edit policy-groups (name, CIDRs, alias
  multiselect, tier, allow/deny, **schedule dropdown of existing pfSense Schedules** + a
  "none = always on" entry, with a link to Firewall > Schedules to create one). Replace the
  legacy bypass textarea with the migrated group (or link to it). Help text matches neighbours
  and notes the active-window semantics briefly.
- Tests: ADR-14 Tier A `ui_render` (200, no PHP errors, page marker, no new
  `php_error.log`); PHPUnit for any extracted page decider.

### Phase 7 — Smoke (multi-source) + DoD + docs

- Prompt: `07_Smoke_DoD_Docs.txt`
- Extend the smoke harness for **source-bound** queries (e.g. `drill -I <src>` / a second
  interface / per-source binding) to prove per-group Block/Warn/PASS, default group, and
  legacy migration end-to-end on a live VM; where CI cannot, codify a maintainer manual
  smoke.
- **Schedule smoke:** a group with a short pfSense Schedule window — assert a listed name is
  blocked **inside** the window and resolves **outside** it for the same client (drive the
  clock or pick a boundary), proving the chroot evaluates the right wall-clock window (the §3
  TZ trap) and the time-transition cache scheme holds.
- Update `docs/misc/architecture-notes.md` (group-policy section), `README.md` if workflow
  changes, stubs if new pfSense fns; PFBL-01 sniff scope.
- Tests: smoke case(s) + green full suite.

---

## 7. Definition of done

### Automated (CI)

- [ ] `python -m pytest` green incl. all new Phase 2–5 unit/oracle/branch tests.
- [ ] `ruff check . && ruff format --check .` clean; `mypy tests/` clean.
- [ ] `php -l`, PHPStan, PHPUnit, PHPCS (PFBL-01) clean incl. new manifest/migration tests.
- [ ] ADR-14 `ui_render` green for the new policy-group page (marker present, no new
      `php_error.log` line).
- [ ] Off-state parity test: group policy disabled ⇒ ADR-06/07 oracles byte-identical.
- [ ] Schedule branch tests (Phase 5): in-window enforces vs out-of-window PASS
      (before+after across the boundary); no-`sched` always-on; belongs-but-all-inactive ⇒
      PASS (not the all-Block default); dangling schedule ref ⇒ always-on.

### Manual smoke (maintainer, on-box) — the multi-source part CI can't do

- [ ] Two client IPs in two groups with different alias subscriptions: a name in alias A
      (subscribed by group 1, not group 2) is **Blocked** for client 1 and **resolves** for
      client 2 — assert the **before** (both resolve with policy off) and **after**.
- [ ] Warn group: the listed name **resolves** for its clients **and** a DNSBL report/log
      line is written (would-be block recorded).
- [ ] Allow>Block precedence: a per-group allow-domain overrides a subscribed-alias block
      for that group's clients only.
- [ ] Union: a client in two groups gets the union of subscriptions + allow>block>warn.
- [ ] Default group: an unmatched client gets all-aliases Block (today's behaviour).
- [ ] Legacy migration: an upgrade from a config with `pfb_gp`/`pfb_gp_bypass_list` yields
      a Bypass group; those IPs still skip all DNSBL; `python_control addbypass` still works.
- [ ] **Schedule (issue #384)**: a scheduled blocking group blocks a listed name **inside**
      its window and the same client resolves it **outside** the window — assert the **before**
      (resolves off-window) and **after** (blocks on-window); the chroot evaluates the correct
      local wall-clock window.
- [ ] **Cache-bleed**: a pass/warn client warming a listed name does **not** let a block
      client escape, **and** an off-schedule resolution does not let an on-schedule query
      escape the block (the Phase-1 scheme holds live across both client and time axes).

### Reject criteria (decide at Phase 1, revisit at Phase 5)

- No cache scheme keeps per-client blocking correct without exceeding the Phase-1
  latency/memory kill-threshold ⇒ **reduce** to action-tier-only (no per-feed subsetting)
  or **REJECT** the ADR, recording the evidence in `RESULTS/` (ADR-01 precedent).
