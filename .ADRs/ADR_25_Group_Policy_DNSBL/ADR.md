# ADR-25: Per-client Group Policy for DNSBL blocking

- **Status:** **Proposed** (2026-06-14)
- **Date:** 2026-06-14
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

---

## 2. Decision

Replace the single global bypass with **N named policy-groups**, Pi-Hole–style
(<https://docs.pi-hole.net/group_management/example/>; Pi-Hole's FTL is open source and was
read as prior art). A policy-group binds **client CIDRs** to **a subset of DNSBL aliases**
plus **per-group allow/deny domain rules** and **an action tier (Block / Warn)**. A client
matching no group falls to a **default group** = today's behaviour (all aliases, Block) →
**backward compatible**.

### 2.1 Resolution model (the architecture that keeps the domain-keyed cache valid)

The expensive matching work is **group-independent**; only the *action applied to a match*
is group-dependent. We exploit that with an **alias-membership bitmask**:

| Concern | Where | Shape |
|--------|-------|-------|
| Which aliases a domain is in | build (`pfb_unbound.py`) | `domain → int bitmask` over aliases (one bit per `DNSBL_*` alias). A domain in two aliases gets both bits. **Group-agnostic ⇒ stays in the domain-keyed `decisionDB`.** |
| Which aliases a client subscribes to | per-query, from manifest | client source IP → **union** of the masks of every policy-group whose CIDR set contains it (cached per IP in a small `gpClientDB`). |
| Block test | per-query | `domain_mask & client_mask != 0` → O(1) int AND. |
| Allow / deny domain rules | per-query | per-group exact/suffix domain sets, unioned across the client's groups. |
| Action tier (Block vs Warn) | per-query | strictest tier among the client's groups whose subscription matched. |

**Merge precedence (deterministic, union semantics):**

1. **Allow-domain** match in any of the client's groups → **PASS** (allow always wins —
   Pi-Hole rule).
2. else **Deny-domain** match in any group → **BLOCK**.
3. else **subscribed-alias** match (`domain_mask & client_mask`) → action = **strictest
   tier** among matching groups (**Block > Warn**); Warn = resolve normally **and log**.
4. else → **PASS**.

The legacy `pfb_gp`/`pfb_gp_bypass_list` bypass = a migrated group with an **empty alias
subscription and no deny rules** → naturally PASS for its members under the same engine.

### 2.2 The cache-bleed correctness problem — SPIKE-gated (Phase 1)

A client-dependent verdict has a subtler hazard than the cache **key**: Unbound's **C
message cache**. When a *pass/warn* client resolves a listed name, Unbound caches the
**real** answer; a subsequent *block* client served from that C-cache **never re-enters
`operate()`** and **silently escapes the block**. (ADR-15/#43 already had to set
`qstate.no_cache_store` on synthetic block replies for a related reason; this generalises
the hazard to *all* policy-relevant names.) This likely already affects the legacy bypass
feature, undocumented.

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
- **Default group = today.** An unmatched client gets all aliases + Block.
- **Block shapes unchanged** (NOERROR+VIP or NULL per per-feed `log`; never NXDOMAIN for a
  feed match). Warn does not invent a new shape — it **resolves + logs**.
- **ADR-10 swap + ADR-15 cache invariants hold:** a swap clears `decisionDB` AND the new
  per-client caches (`gpClientDB`); no torn decision across a CNAME chain.
- **PFBL-01 validation** on every new manifest write / CIDR / domain-rule input
  (`pfb_filter`/`sanitize_ipaddr`), enforced by the PHPCS sniff.

### 2.4 Explicitly kept / out of scope

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

---

## 4. Requirements (acceptance)

- Admin can define ≥1 policy-group: name, enabled, client CIDR list, subscribed `DNSBL_*`
  aliases, action tier (Block/Warn), allow-domain + deny-domain lists.
- A query's verdict follows §2.1 resolution + §2.3 precedence, by client source IP.
- Group policy OFF ⇒ byte-identical to today; legacy bypass auto-migrates and still works.
- Decision correctness holds across the C-cache (Phase-1 scheme), ADR-10 swaps, and
  CNAME chains.
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
- Reproduce the cross-client C-cache bleed on a live VM; pin it.
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
  allow/deny domains) + the default group.
- Migrate legacy `pfb_gp`/`pfb_gp_bypass_list` → a Bypass group (idempotent; absent ⇒
  no-op).
- Extend the manifest: groups, alias→bit map, per-group subscribed bitmask, client-CIDR→
  group map, allow/deny lists, default-group policy. PFBL-01 validation on all inputs.
- Tests (PHPUnit): schema decode, migration (before legacy → after group; absent → no-op),
  manifest shape before/after, bitmask map.

### Phase 5 — Python decision layer + Phase-1 cache scheme

- Prompt: `05_Decision_Layer.txt`
- Load manifest groups; build `gpClientDB` (client IP → unioned mask + rule refs, cached);
  implement §2.1 resolution + §2.3 precedence; Warn = resolve+log; apply the Phase-1 cache
  scheme. Clear `gpClientDB` on ADR-10 swap.
- Tests: every branch — allow-wins, deny, subscribed-hit Block, subscribed-hit Warn,
  no-match PASS, default group, union across 2 groups, migrated legacy bypass; before/after
  transition tests; CNAME-chain + swap-invalidation cases.

### Phase 6 — Web UI (policy-group management)

- Prompt: `06_WebUI.txt`
- New `www/pfblockerng/` page(s) to list/add/edit policy-groups (name, CIDRs, alias
  multiselect, tier, allow/deny). Replace the legacy bypass textarea with the migrated
  group (or link to it). Help text matches neighbours.
- Tests: ADR-14 Tier A `ui_render` (200, no PHP errors, page marker, no new
  `php_error.log`); PHPUnit for any extracted page decider.

### Phase 7 — Smoke (multi-source) + DoD + docs

- Prompt: `07_Smoke_DoD_Docs.txt`
- Extend the smoke harness for **source-bound** queries (e.g. `drill -I <src>` / a second
  interface / per-source binding) to prove per-group Block/Warn/PASS, default group, and
  legacy migration end-to-end on a live VM; where CI cannot, codify a maintainer manual
  smoke.
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
- [ ] **Cache-bleed**: a pass/warn client warming a listed name does **not** let a block
      client escape (the Phase-1 scheme holds live).

### Reject criteria (decide at Phase 1, revisit at Phase 5)

- No cache scheme keeps per-client blocking correct without exceeding the Phase-1
  latency/memory kill-threshold ⇒ **reduce** to action-tier-only (no per-feed subsetting)
  or **REJECT** the ADR, recording the evidence in `RESULTS/` (ADR-01 precedent).
