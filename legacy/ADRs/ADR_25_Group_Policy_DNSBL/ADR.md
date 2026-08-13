# ADR-25: Per-client Group Policy for DNSBL blocking (incl. time scheduling)

- **Status:** **Proposed** (2026-06-14; **REVISED 2026-07-04** — re-scoped as the **DNSBL
  enforcement engine** of the ADR-54/55 trilogy. The data model moved out: Feeds/Feed Groups
  → ADR-54, Client Groups/policy bindings/UI → ADR-55. The resolution semantics changed from
  "membership narrows enforcement" to **default + exceptions** (§2.1); the cache strategy
  gained a preferred candidate — **divergence-gated `no_cache_store`** — and a last-resort
  fallback — a **module resolution cache** (§2.2). §0 maps the trilogy and the execution
  order. The Phase 1 spike is unchanged in substance and **starts immediately, in parallel
  with ADR-54**.)
- **Date:** 2026-06-14
- **Folds in / supersedes:** the per-client / per-network / per-source differentiated
  DNSBL-policy requests this ADR delivers as its core feature:
  - **#384** (Redmine #11099) — "DNSBL blocking by schedule" (block during school hours);
    scheduling is a per-group axis here, not a separate feature.
  - **#321** (Redmine #16578) — pfBlockerNG profiles per interface/VLAN (OPNsense-style
    Unbound Access Lists).
  - **#315** (Redmine #16830) — DNS-Resolver + pfBlockerNG policy per network.
  - **#377** (Redmine #12932) — per-user/GUI-managed DNSBL whitelist (ACLs).
  - **#386** (Redmine #10841) — per Source/VLAN/Network individual black & white lists.

  The implementing PR **closes all of them** (`Closes #384`, `Closes #321`, `Closes #315`,
  `Closes #377`, `Closes #386` in its body) so they resolve automatically on merge.
- **Branch:** `adr/25-group-policy-dnsbl` (off `devel`; slug per CLAUDE.md "Branch naming")
  / **Component(s):** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (decision path +
  build), `pfblockerng.inc` (manifest + config + migration), `src/usr/local/www/pfblockerng/`
  (new policy-group UI), `config.xml` schema, `stubs/`, `tests/`.
- **Target runtime:** Python 3.11+ in Unbound `pythonmod`, **stdlib only** (no external
  deps in the chroot); PHP 8.3 (pfSense CE 2.8).
- **Test suite:** `tests/` (pytest — Python decision + build), `tests/php/` (PHPUnit —
  manifest/config/migration helpers), `tests/smoke/` (ADR-04 live VM + ADR-14 `ui_render`).

---

## 0. Relationship & execution order (REVISED 2026-07-04 — read this first)

```text
ADR-25 Phase 1 (cache spike) ────────────────────────────┐  start IMMEDIATELY, parallel to
                                                          │  ADR-54/55; its verdict gates
                                                          ▼  ADR-25 Phases 2..7
ADR-54 P1→P2→P3→P4 ──→ ADR-55 P1→P2→P3→P4 ──→ ADR-25 P2..P7 ──→ ADR-56 ──→ ADR-57
(Feeds/Feed Groups      (Client Groups +      (this ADR:          (per-CG    (GeoIP
 M:N data model)         IP policy rules+UI)   DNSBL engine)       axes)      fold-in)
```

**What this ADR consumes (and no longer defines):**

- **FEED GROUP** (the subscribable unit, one bitmask bit each) — ADR-54
  (`installedpackages/pfblockerngfeedgroups`; DNSBL groups gained the `policy_only`
  default-action token there, stored-but-inert until this ADR enforces it).
- **CLIENT GROUP** (`pfB_CG_*`, addresses + alias refs + `allow_domains`/`deny_domains`) and
  **POLICY BINDINGS** (CG↔FG edges: `action_override` ∈ Block/Warn/Bypass for dnsbl-family
  FGs, `sched` ref) — ADR-55 (`installedpackages/pfblockerngclientgroups`). ADR-55 stores
  dnsbl bindings but keeps them **locked out of its UI and generator**; this ADR's Phase 6
  unlocks them.
- The ADR-55 Phase 4 **source-bound smoke fixture** (`client_source(ip)`) — reused by this
  ADR's Phase 7 for per-client DNSBL probes.

**What this ADR still owns:** the Phase-1 spike; the alias-membership **bitmask build**; the
**decision layer** (per-client verdicts, precedence, Warn); the **cache-correctness scheme**
(divergence-gated `no_cache_store`, §2.2); **schedule evaluation in the chroot** (serialised
ranges, TZ-explicit); the **manifest emission** of groups/masks/client-map/schedules; the
legacy `pfb_gp` bypass **handover and retirement**; the dnsbl-binding **UI unlock** in
ADR-55's pages.

### 0.1 Wayfinder conversion gate (2026-07-19)

This Proposed ADR predates the discovery that one Unbound mesh state can carry replies for
multiple requesters. When Wayfinder converts ADR-25 into a map and spec, it **must**:

1. Treat §1.2's scalar-client premise ("the client IP is already in hand" and no additional
   Unbound plumbing is needed) as falsified by
   [Choose client-IP precedence across Unbound reply-list nodes](https://github.com/pfBlockerNG/pfBlockerNG/issues/1536).
   Neither the reply-list head nor its first valid address is a canonical client for policy.
2. Resolve and incorporate
   [Research Unbound mesh partitioning by pfBlockerNG Group Policy](https://github.com/pfBlockerNG/pfBlockerNG/issues/1549)
   before inheriting §2.1, §2.2, or the Phase-1 cache strategy. That research must prove the
   supported pre-resolution seam for making effective Group Policy part of mesh-state
   equivalence on supported pfSense CE and Plus versions.
3. Preserve the owner direction that same-policy requesters may share Unbound mesh/cache
   work, while requesters with different effective policies must receive distinct query
   states before `operate()` installs a qstate-wide synthetic DNSBL response. A late
   `inplace_cb_reply*` rewrite is not an equivalent default: it cannot restore an allowed
   response when normal resolution never ran.
4. Re-specify
   [pfb_unbound.py: make requester identity policy-partition aware](https://github.com/pfBlockerNG/pfBlockerNG/issues/1406)
   only after #1549 names and verifies that mechanism. Do not mechanically translate this
   ADR's historical phase prompts into implementation tickets.

This gate records the dependency and invalidated premise; it deliberately does not select
the Unbound mechanism ahead of the research.

**Per-phase gating:** every phase is executed by a Sonnet 5 implementer and adversarially
gate-reviewed by the orchestrator at reasoning effort `xhigh` against the phase kill-gates
before the next phase starts (CLAUDE.md planner/implementer flow — mandatory).

## 1. Context — Today

### 1.1 The DNSBL decision is global and client-agnostic

Every LAN client gets the **same** DNSBL verdict for a name. The query-time matcher
`evaluate_domain(q_name, q_name_original, tld, is_cname, cfg, containers)`
(`pfb_unbound.py` ~5588) returns a `DnsblDecision` from the queried name alone — the
**client source IP is never an input**. The verdict is memoised in the unified
**domain-keyed** decision cache `decisionDB[name] = DnsblDecision` (ADR-15), cleared on a
zero-downtime swap (ADR-10).

### 1.2 The client IP is, however, already in hand

`operate(id, event, qstate, qdata)` (~6049) extracts the client source IP **today** via
`get_q_ip(qstate)` (~2055 → `qstate.mesh_info.reply_list.query_reply.addr`) and uses it
**only for log attribution** (`pfb_addr`, ~5204). **No new Unbound API plumbing is needed
to make decisions client-aware** — the load-bearing premise of this ADR holds.

### 1.3 A primitive "Group Policy" already ships — one binary bypass list

pfBlockerNG already exposes a feature literally named *Group Policy* but it is a **single
global bypass list**:

- Config: `pfb_gp` (on/off) + `pfb_gp_bypass_list` (textarea of client IPs), under
  `dnsblconfig` (`pfblockerng.inc:2107-2108`).
- `pfblockerng.inc:6980-6995` writes an ini `[GP_Bypass_List]` section into the file the
  python module reads; `pfb_unbound.py:1347-1357` loads it into `gpListDB`; the decision
  path (`:6175-6195`) sets `bypass_dnsbl = True` when `gpListDB.get(q_ip) is not None`.
- Semantics: a listed IP **skips all DNSBL**; everyone else gets **full DNSBL, Block**.
  Matching is **exact-IP only** (`gpListDB.get(q_ip)`, a dict lookup — no CIDR).
- A runtime `python_control addbypass/removebypass [duration]` path mutates `gpListDB`
  in place (`:3000-3090`) — a transient per-IP bypass.

This is exactly **one group with one action (bypass)**. This ADR generalises it.

### 1.4 DNSBL feed/alias organisation (the unit a group will subscribe to)

DNSBL feeds are grouped under **aliases**: a settings row builds alias
`DNSBL_{aliasname}` (`pfblockerng.inc:14322`) whose `$list['row']` feeds each carry
`header` / `url` / `state` / `custom`. The per-feed manifest entry the python build
consumes is `{ 'raw', 'feed', 'group' (=alias), 'format_hint', 'provenance', 'log_flag' }`
— plus `'mode' => 'permit'` for ADR-31 permit feeds — built in
`pfb_unbound_python_sources()` (`pfblockerng.inc` ~`:6568`). (Corrected 2026-07-03: the
original `{feed, group, log, format, provenance}` key names no longer exist — code written
against `log`/`format` does dead lookups.) The per-feed `log_flag` already encodes an
action/shape: `0`=block+log, `1`=VIP+log, `2`=null no-log, `3`=NXDOMAIN+log,
`4`=NXDOMAIN no-log (`:14370-14390`). The manifest is published atomically and applied by
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
by `filter_get_time_based_rule_status()`. None of it is wired into the DNSBL decision path.
(Updated 2026-07-03 for ADR-43, amended 2026-07-12 for issue #1204: package scheduling is now
**one cron tick** — `pfblockerng.php cron-tick` every 15 minutes reading the
due-ledger — and an
already-landed PHP time-window evaluator exists, `pfb_quiet_hours` +
`pfb_quiet_hours_in_window()` in `pfblockerng_extra.inc`, a precedent/possible reuse for this
ADR's schedule serialisation. Both still govern *refresh/apply timing*, not whether blocking
is *active*.) Per-client policy and time-of-day
gating are the same shape of problem (a group of clients gets a different verdict under a
condition), so this ADR folds scheduling in as a **per-group axis** rather than a parallel
feature — the maintainer's call on the issue.

---

## 2. Decision

**(REVISED 2026-07-04 — this section supersedes the original "N named policy-groups" model.)**
Enforce **per-client DNSBL policy as default + exceptions** over the ADR-54/55 entities:
every DNSBL **Feed Group** keeps a global default (its `logging` shape, or `policy_only` =
enforced for nobody), and ADR-55 **policy bindings** add per-**Client-Group** exceptions —
`Block` / `Warn` / `Bypass` overrides, each optionally gated by a **pfSense Schedule**.
Pi-Hole remains the prior art for per-client grouping
(<https://docs.pi-hole.net/group_management/example/>), but the semantics deliberately match
the IP side (ADR-55 §2.3): **bindings never remove the default — they carve exceptions**, and
a Feed Group that should apply only to some clients uses a `policy_only` default. This is one
mental model across pf rules and DNSBL.

**Schedules reuse pfSense's native scheduler, not a new one.** A **binding** carries a
`sched` reference to an existing `<schedules>` entry (ADR-55 §2.2); we serialise that
schedule's time ranges into the manifest and evaluate "is it active now" in the chroot. No
schedule ⇒ the binding is **always in force**; a dangling ref ⇒ always in force (fail-open,
same as ADR-55's rule for pf rules). One schedule concept for the admin, at the cost of
re-implementing the active-window test in the stdlib-only Python module (§2.4, §3).

### 2.1 Resolution model (the architecture that keeps the domain-keyed cache valid)

The expensive matching work is **group-independent**; only the *action applied to a match*
is client-dependent. We exploit that with a **group-membership bitmask**:

| Concern | Where | Shape |
|--------|-------|-------|
| Which Feed Groups a domain is in | build (`pfb_unbound.py`) | `domain → int bitmask` over dnsbl Feed Groups (one bit per `DNSBL_*` group). A domain in two groups gets both bits. **Client-agnostic ⇒ stays in the domain-keyed `decisionDB`.** |
| Which Client Groups a client belongs to | per-IP, cached | client source IP → set of CGs whose address/CIDR set contains it (`gpClientGroups`, **time-independent** — cached per IP, cleared on an ADR-10 swap). CG alias refs are resolved to literal IPs/CIDRs at manifest build; FQDN alias members are excluded (ADR-55 §2.1 caveat). |
| Which bindings are **in force now** | per-query | `schedule_active(binding)`: *now* falls within a serialised range of the binding's Schedule. **No `sched` ⇒ always in force.** Cheap (a handful of ranges); evaluated live so it tracks window edges. |
| Per-client override for a matched group | per-query | union over the client's CGs' **active** bindings that cover a matched Feed-Group bit → the **most permissive** override wins (`Bypass > Warn > Block`) — overrides are carve-outs, mirroring the IP side where the pass bucket precedes the block bucket. |
| Block test | per-query | `domain_mask & enforced_mask != 0` → O(1) int AND (enforced mask = bits of groups with a global default, ∪ bits enforced for this client via active Block bindings on `policy_only` groups). |
| Allow / deny domain rules | per-query | per-CG exact/suffix domain sets (`allow_domains` / `deny_domains`), unioned across the client's CGs. |

**Resolution ladder (deterministic — evaluated per query for the client's CG set):**

1. **Global user-allow** (ADR-31 band semantics, `whiteDB`) → **PASS** — unchanged, pinned.
2. **CG `allow_domains`** match → **PASS** (allow always wins — Pi-Hole rule).
3. **CG `deny_domains`** match → **BLOCK** (default block shape).
4. Domain's mask ∩ client-relevant groups: for each matched group, resolve the client's
   **active** bindings → most-permissive override (`Bypass` → PASS; `Warn` → resolve + log;
   `Block` → that group's block shape). A `policy_only` group with **no** active binding for
   this client contributes nothing.
5. No binding for a matched group with a **global default** → the group's default shape
   (today's behaviour — the zero-CG oracle).
6. No match → **PASS**.

**"School hours" (issue #384)** = a `policy_only` Feed Group + a `Block` binding with a
schedule: outside the window the binding is inert and the group enforces for nobody; inside
it, the CG's clients are blocked. No fall-to-default surprise — the default of a
`policy_only` group is "nobody".

The legacy `pfb_gp`/`pfb_gp_bypass_list` bypass = the ADR-55-migrated **`Legacy_Bypass`** CG
whose bindings carry `Bypass` for every dnsbl Feed Group → PASS for its members under the
same ladder (rung 4).

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
  - **(a′) — PREFERRED CANDIDATE (added 2026-07-04): divergence-gated `no_cache_store`.**
    Only names whose verdict can **diverge** — across clients or across time — skip the
    message cache; everything else caches fully. The build publishes a **divergent mask** =
    union of Feed-Group bits referenced by any binding with an override, any `policy_only`
    group, and any **scheduled** binding (time-axis divergence); a name is also divergent on
    a CG `allow_domains`/`deny_domains` hit (same suffix-match shape as `whiteDB`). Query
    time: `domain_mask & divergent_mask == 0` and no domain-rule hit ⇒ uniform verdict ⇒
    C-cache as today. **Zero Client Groups ⇒ divergent set empty ⇒ caching byte-identical.**
    Cost profile of excluded names: BLOCK answers are synthesized locally (already
    `no_cache_store`, ADR-15/#43 — no upstream); PASS/Warn answers re-resolve per query, but
    Unbound's **rrset cache** bounds most repeats to local assembly within TTLs. The spike
    measures exactly that pass-path latency. Caveat the spike must close: `no_cache_store`
    prevents *future* storage only — enabling a policy on an already-warm name (or a schedule
    edge) needs a one-shot flush of affected names; policy edits riding an ADR-10 swap get
    the clear for free, and the swap is the designed apply path.
  - **(a)** plain `no_cache_store` on every policy-relevant name — the degenerate form of
    (a′) with divergence = "any listed name"; keep as the simplicity baseline to measure
    against.
  - **(b) — LAST-RESORT FALLBACK (supersedes the original mask-keyed idea): a module-level
    RESOLUTION cache.** If (a′)'s measured pass-path cost breaches the kill-threshold,
    `pfb_unbound.py` keeps its own answer stash for divergent names: the answer Unbound
    resolved last time a client was allowed to resolve the name — captured from
    `qstate.return_msg` at MODDONE, keyed `(qname, qtype, qclass)`, expiry = the answer's
    min TTL, served with decremented TTL, dropped on expiry. **Verdict-independent** (plain
    DNS data; the per-client verdict applies on top at answer time) — which is why no
    per-mask keying is needed. Cleared on the ADR-10 swap like `decisionDB` (TTL alone
    bounds staleness, so a gentler keep-across-swaps policy is available later). Known
    complexity the spike must flag before this could ever land: DNSSEC (preserve
    RRSIGs/security status or refuse to stash validated answers), DO/CD flag variance in
    the key, re-running the per-client CNAME walk when serving from the stash. **Built only
    on measured evidence, never pre-emptively.**
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

- **Zero Client Groups (default): byte-identical behaviour.** `evaluate_domain` decisions
  unchanged (ADR-06/07 oracles green); a manifest with no CGs/bindings produces today's
  output; `decisionDB`/`gpListDB` behaviour unchanged; caching byte-identical (§2.2 (a′),
  empty divergent set).
- **Legacy bypass preserved.** Existing `pfb_gp`/`pfb_gp_bypass_list` configs keep working —
  through the untouched `gpListDB` path until this ADR's decision layer lands, then through
  the migrated `Legacy_Bypass` CG (ADR-55 §2.5) whose `Bypass` bindings reproduce it; a
  listed IP still skips all DNSBL; `python_control addbypass/removebypass [duration]` still
  works (rewired to a transient CG-equivalent entry, same observable behaviour). The legacy
  keys retire only in this ADR's Phase 6 handover.
- **A client matching no Client Group gets every Feed Group's default** — today's behaviour
  exactly (rung 5 of the §2.1 ladder).
- **No schedule ⇒ always in force.** A binding without a `sched` reference never depends on
  the clock. Removing/renaming the referenced pfSense Schedule degrades safely to "always in
  force" (fail-open, never a crash) — same rule ADR-55 applies to pf rules.
- **Block shapes unchanged** (NOERROR+VIP or NULL per per-feed `log`; never NXDOMAIN for a
  feed match). Warn does not invent a new shape — it **resolves + logs**.
- **ADR-10 swap + ADR-15 cache invariants hold:** a swap clears `decisionDB` AND the new
  per-client caches (`gpClientDB`); no torn decision across a CNAME chain.
- **PFBL-01 validation** on every new manifest write / CIDR / domain-rule input
  (`pfb_filter`/`sanitize_ipaddr`), enforced by the PHPCS sniff.

### 2.4 Explicitly kept / out of scope

- **Scheduling reuses pfSense Schedules — no custom scheduler.** A binding references an
  existing `<schedules>` entry by name (compose finer windows by splitting into multiple
  bindings/groups). We do **not** build a new time-window UI/store. The schedule *definition*
  lives in pfSense core config; we only serialise its resolved ranges into the manifest and
  evaluate them in the chroot. **Time-of-day correctness in the Unbound chroot is an
  implementation item** (Phase 4/5): `time.localtime()` resolves against the chroot's
  `/var/unbound/etc/localtime`, which may be absent → wrong window. The build must serialise
  ranges in a timezone-explicit form (or ensure zoneinfo is reachable in-chroot); proven by a
  Phase-7 schedule smoke. Inverted/"all except" windows are out of scope (express the inverse
  as the binding's active window).
- **Per-feed (sub-group) subscription** — the subscribable unit is the **Feed Group**
  (`DNSBL_*`), not the individual feed. ADR-54's M:N makes this a non-issue in practice: a
  user who wants finer granularity makes a smaller group and reuses the feeds.
- **Client identity beyond IP/CIDR + alias refs** (MAC, hostname, interface, DHCP-derived) —
  Pi-Hole supports these; this trilogy is **IP/CIDR (+ resolvable pfSense aliases)** only.
- **Per-CG SafeSearch / DoH / noAAAA / TLD / IDN axes** — governed by **ADR-56** (committed
  follow-up, gated on this ADR's spike verdict); until then those axes stay global.
- **A "warning/continue" sinkhole page** — Warn = resolve+log (chosen); a click-through
  block page is out of scope.
- **IP-side (firewall) per-group behaviour** — **ADR-55** (landed before this ADR's decision
  layer; not this ADR).
- **Data model & UI pages** — ADR-54 (feeds/groups) and ADR-55 (CGs/bindings/pages); this
  ADR only *unlocks* the dnsbl controls in ADR-55's pages (Phase 6).

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

**(REVISED 2026-07-04.)** Phase 1 starts immediately (parallel to ADR-54); Phases 2–7 run
**after ADR-55 completes** and adopt the Phase-1 verdict. Early phases are the
behaviour-preserving **preparatory de-risking** pass; the cache spike (Phase 1) gates the
rest. Every phase: Sonnet 5 implements, the orchestrator adversarially gate-reviews at
`xhigh` (§0).

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
- Add a pure **CIDR client→CG-set resolver** (interval/longest-prefix over the Client
  Groups' address sets → the client's CG set) + unit tests; **not wired** into the decision
  path yet.
- Tests: oracle + bypass + resolver unit tests, all green.

### Phase 3 — Build: group-membership bitmask (feature-flagged, off ⇒ identical)

- Prompt: `03_Build_Bitmask.txt`
- Extend the build so `data_db[domain]` (and the zone map) carry a **Feed-Group bitmask**;
  define the `DNSBL_*` group → bit assignment (one bit per dnsbl Feed Group — the ADR-54
  entity). With zero CGs the observable manifest/decision output is unchanged.
- Tests: a domain in 2 groups → both bits; mask intersection; off-state parity.

### Phase 4 — Manifest emission (PHP): CGs, bindings, divergent mask, schedules

- Prompt: `04_Config_Manifest_Migration.txt`
- **(Re-scoped 2026-07-04: the config schema + migration this phase originally owned moved
  to ADR-54/55 — the entities already exist. This phase EMITS them to the chroot.)**
- Extend the manifest: dnsbl group→bit map; the **divergent mask** (§2.2 (a′)); Client
  Groups (name → resolved literal IPs/CIDRs — alias refs resolved at build, FQDN members
  excluded with a one-line notice); per-CG `allow_domains`/`deny_domains`; bindings
  (CG, group-bit, override, **serialised schedule time ranges** — read from the pfSense
  `<schedules>` section, TZ-explicit so the chroot evaluates the right wall-clock window).
  PFBL-01 validation on all inputs. A dangling/removed schedule ref serialises as "always in
  force" (fail-open); a dangling Feed-Group ref is skipped with a notice.
- **ADR-29 gateway rules apply:** `pfb_gp`/`pfb_gp_bypass_list` are **registered PfbConfig
  fields** — read via `PfbConfig`, never direct `config_*_path`. The ADR-54/55 sections are
  structural foreign keys (section helpers).
- Tests (PHPUnit): manifest shape with zero CGs (byte-identical — oracle), with CGs/bindings
  (each field), divergent-mask composition (override/`policy_only`/scheduled inputs),
  schedule serialisation (ranges + dangling-ref → always-on), alias-ref resolution incl. the
  FQDN exclusion. **Red→green is mandatory** for every behaviour-adding test.

### Phase 5 — Python decision layer + Phase-1 cache scheme

- Prompt: `05_Decision_Layer.txt`
- Load manifest CGs/bindings; build `gpClientGroups` (client IP → CG set, time-independent,
  cached); per query resolve the **active** bindings via `schedule_active(binding)` over the
  serialised ranges (no `sched` ⇒ always active); implement the §2.1 resolution ladder
  (most-permissive override, `policy_only` semantics, rung-5 defaults); Warn = resolve+log;
  apply the Phase-1 cache scheme (divergence-gated `no_cache_store` unless the spike chose
  otherwise). Clear the per-IP cache on ADR-10 swap.
- Tests: every ladder rung — global-allow wins, CG allow, CG deny, Block/Warn/Bypass
  overrides (incl. most-permissive across 2 CGs), `policy_only` with and without an active
  binding, rung-5 default, no-match PASS, migrated legacy bypass; **schedule: in-window
  enforces vs out-of-window inert (assert before+after across the boundary), no-sched
  always-on, dangling ref ⇒ always-on**; divergence gating: uniform name cached / divergent
  name not (assert `no_cache_store`), zero-CG ⇒ nothing gated; CNAME-chain +
  swap-invalidation cases. **Red→green mandatory.** ADR-31 interplay pinned: band-2
  `whiteDB` pre-empts any binding (ladder rung 1).

### Phase 6 — UI unlock + legacy bypass handover

- Prompt: `06_WebUI.txt`
- **(Re-scoped 2026-07-04: the policy pages shipped with ADR-55 — this phase UNLOCKS their
  dnsbl half and retires the legacy bypass.)**
- In `pfblockerng_group_policy_edit.php`: the binding Feed-Group select now offers dnsbl
  groups; the override select gains `Block`/`Warn (log only)`/`Bypass` for them (validator
  updated); the CG `allow_domains`/`deny_domains` help text notes they are now enforced.
  `pfblockerng_category_edit.php`: the "Unbound (Policy-only)" option's help drops its
  "inert until ADR-25" note.
- **Legacy handover:** `python_control addbypass/removebypass` rewired to the CG-equivalent
  transient path (same observable behaviour); the `pfb_gp`/`pfb_gp_bypass_list` keys +
  `gpListDB` ini section + the DNSBL-page pointer text retired per the deprecation the keys'
  registry entries document. Migration final-state test: a legacy config upgraded through
  ADR-55 + this phase has exactly one enforcement path (the CG one).
- Ports lockstep re-check; help text matches neighbours.
- Tests: Tier A on touched pages; **Tier B `ui_e2e` REQUIRED**: dnsbl binding create → save
  → reload → persisted → enforced (paired with a smoke probe in Phase 7); PHPUnit for the
  validator vocabulary change; red→green on the handover (bypass works via CG path, legacy
  keys gone).

### Phase 7 — Smoke (multi-source) + DoD + docs

- Prompt: `07_Smoke_DoD_Docs.txt`
- Reuse ADR-55 Phase 4's **`client_source(ip)`** fixture for source-bound DNS probes
  (`drill -I <src>` / the second guest address) to prove per-CG Block/Warn/Bypass,
  `policy_only`, rung-5 defaults, and legacy migration end-to-end on a live VM; where CI
  cannot, codify a maintainer manual smoke.
- **Schedule smoke:** a group with a short pfSense Schedule window — assert a listed name is
  blocked **inside** the window and resolves **outside** it for the same client (drive the
  clock or pick a boundary), proving the chroot evaluates the right wall-clock window (the §3
  TZ trap) and the time-transition cache scheme holds.
- Update `docs/misc/architecture-notes.md` (group-policy section), `README.md` if workflow
  changes, stubs if new pfSense fns; PFBL-01 sniff scope.
- Tests: smoke case(s) + green full suite.

---

## 7. Definition of done

### On merge (issue closure)

- [ ] The landing PR body carries `Closes #384`, `Closes #321`, `Closes #315`, `Closes #377`,
      and `Closes #386` so every folded-in / superseded issue closes automatically when ADR-25
      lands (each was left a comment pointing here while the ADR was Proposed).

### Automated (CI)

- [ ] `python -m pytest` green incl. all new Phase 2–5 unit/oracle/branch tests.
- [ ] `ruff check . && ruff format --check .` clean; `mypy tests/` clean.
- [ ] `php -l`, PHPStan, PHPUnit, PHPCS (PFBL-01) clean incl. new manifest/migration tests.
- [ ] ADR-14 `ui_render` green for the touched ADR-55 pages (marker present, no new
      `php_error.log` line) **and Tier B `ui_e2e`** for the unlocked dnsbl-binding flow
      (create→save→reload→persisted→enforced — required for a multi-step flow per CLAUDE.md).
- [ ] **Live-VM smoke green on the CE + Plus fan-out** — the default ADR-acceptance
      validation (CLAUDE.md "ADR acceptance"); a single-leg run is not the gate.
- [ ] Zero-CG parity test: no Client Groups ⇒ ADR-06/07 oracles byte-identical AND caching
      behaviour byte-identical (empty divergent mask).
- [ ] Schedule branch tests (Phase 5): in-window enforces vs out-of-window inert
      (before+after across the boundary); no-`sched` always-on; dangling schedule ref ⇒
      always-on; `policy_only` + no active binding ⇒ PASS.
- [ ] Divergence-gating tests (Phase 5): uniform name C-cached; divergent name
      `no_cache_store`; the policy-apply path clears already-warm affected names (the ADR-10
      swap clear, §2.2 (a′) caveat).

### Out-of-CI validation (maintainer, on-box) — the multi-source part CI can't do

Per CLAUDE.md "ADR acceptance — automated tests, not a manual sign-off", the items below are
a **documented out-of-CI limitation, not an acceptance blocker**: acceptance is the automated
CE+Plus fan-out above. (If Phase 7 manages source-bound queries in the harness, promote these
to smoke cases and this section shrinks accordingly.)

- [ ] Two client IPs, two Client Groups: a name in a `policy_only` group with a Block
      binding for CG 1 only is **Blocked** for client 1 and **resolves** for client 2 —
      assert the **before** (both resolve with no bindings) and **after**.
- [ ] Warn binding: the listed name **resolves** for the CG's clients **and** a DNSBL
      report/log line is written (would-be block recorded).
- [ ] Allow>Block precedence: a CG allow-domain overrides a matched-group block for that
      CG's clients only.
- [ ] Most-permissive override: a client in two CGs (Bypass in one, Block in the other, same
      group) resolves freely; Warn+Block resolves+logs.
- [ ] Rung-5 default: an unmatched client gets every default-enforcing group's shape
      (today's behaviour).
- [ ] Legacy migration: an upgrade from a config with `pfb_gp`/`pfb_gp_bypass_list` yields
      the `Legacy_Bypass` CG; those IPs still skip all DNSBL; `python_control addbypass`
      still works.
- [ ] **Schedule (issue #384)**: a scheduled Block binding blocks a listed name **inside**
      its window and the same client resolves it **outside** the window — assert the **before**
      (resolves off-window) and **after** (blocks on-window); the chroot evaluates the correct
      local wall-clock window.
- [ ] **Cache-bleed**: a pass/warn client warming a listed name does **not** let a block
      client escape, **and** an off-schedule resolution does not let an on-schedule query
      escape the block (the Phase-1 scheme holds live across both client and time axes).

### Reject criteria (decide at Phase 1, revisit at Phase 5)

- No cache scheme keeps per-client blocking correct without exceeding the Phase-1
  latency/memory kill-threshold ⇒ **reduce** (e.g. Bypass-only overrides, no per-group
  subsetting — the shapes the surviving scheme supports) or **REJECT** this ADR's decision
  layer, recording the evidence in `RESULTS/` (ADR-01 precedent). ADR-54/55 stand on their
  own regardless — the IP side and the data model do not depend on this verdict.
