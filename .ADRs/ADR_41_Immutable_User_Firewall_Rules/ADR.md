# ADR-41: Immutable user firewall rules in the IP autorule reconciliation

- **Status:** **Implemented (pending live-VM smoke)** (2026-06-25) — Phases 1–3 landed: the
  emission is extracted + the reconciliation rewritten to the immutable-user splice (binary anchor),
  with the off-appliance contract (user-rule fidelity, pfB-set-identical, idempotence) pinned
  red→green in `AutoruleListOracleTest`. Phase 2's pf-precedence kill-gate returned **GO** (live
  first-match confirmed; `RESULTS/02`). Flips to **Accepted** once the §7 live-VM fan-out (CE + Plus)
  — the per-`pass_order` data-plane precedence sweep in `test_smoke_autorule_immutable.py` (currently
  skipped pending Phase-4 wiring) — is green.
- **Date:** 2026-06-25
- **Branch:** `adr/41-immutable-user-firewall-rules` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming"). / **Component(s):** the IP-side autorule
  reconciliation in `src/usr/local/pkg/pfblockerng/pfblockerng.inc` —
  `sync_package_pfblockerng()`, the "Assign Rules" region (~`:14551`–`:14880`): the rule
  bucketing (~`:14586`–`:14651`), the per-interface emission loops (~`:14729`–`:14820`), and the
  ORDER table (~`:14640`). The pfB-rule *generation* (`pfb_firewall_rule()` `:8162`; the
  `$pfb['permit_*']`/`$pfb['deny_*']` builders) is reused unchanged.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). `pfctl(8)` / `filter.inc` rule generation is real
  only on the live VM.
- **Test suite:** `tests/php/` (PHPUnit — the pure splice/emission logic, loaded off-appliance via
  `tests/php/bootstrap.php`) and `tests/smoke/` (live-VM ADR-04 — the factory-restore oracle sweep
  is the acceptance gate; pf rule generation + precedence are only real here).

## 1. Context

### 1.1 Today

`sync_package_pfblockerng()` reconciles pfBlockerNG's firewall rules into `config.xml`
`filter/rule` by **stripping every rule and rebuilding the whole list** each pass:

- It reads all `filter/rule` (`:14583`), then **removes every `pfB_*`-described rule** (`:14601`)
  except the DNS-redirect / DoT-block "bypass" rules (`:14594`–`:14596`, kept like user rules).
- It **buckets the surviving (user) rules** by interface, type, and floating into
  `$permit_rules` / `$other_rules` / `$fpermit_rules` / `$fmatch_rules` / `$fother_rules`
  (`:14611`–`:14651`), keyed on `pass_order` — e.g. a non-floating user `pass` rule on a
  pfBlockerNG-managed interface goes to `$permit_rules` for `order_1`..`order_4`, but to
  `$other_rules` for `order_0` (`:14634`–`:14638`).
- It **regenerates** the pfB rules (DNSBL ping/permit floating pair `:14692`; per-interface
  permit/match/deny via the inbound loop `:14729`–`:14778` and outbound loop `:14782`–`:14820`).
- It **re-emits user buckets interleaved with pfB rules** inside those per-interface loops and in
  a post-loop tail (`:14820`–`:14839`), in a sequence dictated by `pass_order` per the ORDER
  table (`:14640`):

  ```text
  ORDER 0 | pfB (p/m/b/r) | All other |
  ORDER 1 | pfSense (p/m) | pfB (p/m)  | pfB (b/r)    | pfSense (b/r) |
  ORDER 2 | pfB (p/m)     | pfSense (p/m) | pfB (b/r) | pfSense (b/r) |
  ORDER 3 | pfB (p/m)     | pfB (b/r)  | pfSense (p/m)| pfSense (b/r) |
  ORDER 4 | pfB (p/m)     | pfB (b/r)  | pfSense (b/r)| pfSense (p/m) |
  ```

- The result is written only if it differs from the original (`$orig_rules_nocreated !=
  $new_rules_nocreated`, `:14854`), and only then does `filter_configure()` (the full rule
  reload) fire downstream.

### 1.2 The problem

Rebuilding the whole list and **re-bucketing user rules through per-interface loops** means the
reconciliation can silently **mutate** the user's own firewall rules. Three failure modes, all
**confirmed on a live CE 2.8 VM** this session (factory-restored `filter/rule` between scenarios,
swept across every `pass_order` × float on/off, asserting the exact user-rule multiset):

1. **DROP — empty `pass_order`.** A managed-interface user `pass` rule is bucketed into
   `$permit_rules`, which has **no emission path for an empty/unknown order** (the loops emit it
   only for `order_1`..`order_4`). So the rule vanishes from `config.xml` on reload. This is
   issue #532; it was band-aid-fixed in #539 by defaulting an empty order to `order_0`
   (`:14638`-adjacent), with a live smoke test in #544
   (`tests/smoke/test_smoke_lan_rule_preserve.py`).
2. **DUPLICATE — non-floating `order_1`/`order_2`, shared in/out interface.** When a list's
   inbound and outbound interface are the **same** (e.g. both LAN), `$permit_rules` is emitted in
   **both** the inbound loop (`:14732`/`:14763`) and the outbound loop (`:14785`/`:14808`).
   Because the next pass re-buckets the already-duplicated rules, they grow **×2 per reload** —
   one `Default allow LAN to any` rule became **eight** after three reloads on the live VM.
3. **REORDER — e.g. `order_4`.** Managed-interface user rules are repositioned relative to other
   user rules (the managed/non-managed split + the order-keyed placement). On the live VM
   `order_4` emitted the `opt1` rules *before* the `lan` rules, inverting their `config.xml`
   order vs the factory layout.

These are three symptoms of **one** fragile design: *strip everything and rebuild, re-bucketing
user rules*. Patching each symptom (the #539 empty-order default; a dedup guard for #2) is
whack-a-mole on code that should never be touching user rules in the first place.

### 1.3 Load-bearing facts

- **`$permit_rules` is populated only on the non-floating path.** The float branch (`:14612`)
  routes user rules to `$fpermit_rules`/`$fmatch_rules`/`$fother_rules`; `$permit_rules` is
  populated only in the `else` (non-float) branch (`:14638`). The live sweep confirms **float =
  on preserves user rules for every `pass_order`** — the drop/duplicate/reorder are all
  **non-floating** path defects. The rewrite must keep the floating path's correct behaviour.
- **The pfB deny rule only materialises once its alias table has members.** `pfb_firewall_rule()`
  is called only when the alias has content (`:14446`, gated on `pfctl -t <alias> -Tshow | wc -l`
  OR fresh `$alias_ips`). On a brand-new list the table is empty on update #1 (it is *loaded* at
  the end of that update by `pfblockerng.sh`), so no pfB rule exists, the managed-interface set is
  effectively empty, and the user rules are left alone — the drop/duplicate first appears on
  **update #2**. (The #544 smoke harness compresses this with `force_ip_refetch` + a pre-written
  feed.)
- **DNS-redirect / DoT-block bypass rules carry a `pfB_` descr but are NOT this region's rules**
  (`PFB_DNS_REDIR_DESCR_V4_PFX` / `PFB_DOT_BLOCK_DESCR_PFX`, `:14594`). They are managed by the
  inline redirect/DoT sync and must be **preserved like user rules** — the rewrite keeps treating
  them as immutable, not as "pfB rules to regenerate".
- **`pass_order` is a firewall-precedence control — a SECURITY surface.** It decides whether
  pfBlockerNG's block rules sit before or after the user's pass rules. pfSense's `filter.inc`
  generates per-interface rules **first-match** (it emits `quick` on interface rules); a wrong
  position can let a pass rule shadow a pfB block (traffic not blocked) or a pfB block shadow the
  default LAN allow (LAN lockout). **This precedence model is asserted, not assumed — Phase 2
  pins it on the live VM before any splice is designed (the ADR-01 lesson).**
- **The reconciliation output is a pure function of its inputs.** Given (existing `filter/rule`,
  the generated pfB rule arrays, `pass_order`, `float`, the inbound/outbound interface sets), the
  emitted list is deterministic. So the emission can be extracted into a pure helper and pinned
  off-appliance with PHPUnit — pf need not be real to test the *ordering* logic; only the
  *precedence semantics* (Phase 2) need the live VM.
- **The live oracle harness exists.** Built this session: restore the factory `filter/rule`,
  inject a pfB list, sweep `pass_order` × float, reload twice, and assert (a) the non-pfB
  multiset is preserved (no drop/dup), (b) positions are stable across reloads, (c) pfB-vs-user
  precedence matches the ORDER table. It is the acceptance gate.

### 1.4 Why this is worth an ADR (and not a drive-by patch)

The change reworks **load-bearing, security-sensitive** firewall-ordering code: a wrong rule
position is a block-bypass or a lockout, not a cosmetic bug. It carries a **falsifiable premise**
— "a single insertion anchor per `pass_order` reproduces the intended pfB-vs-user precedence
without ever splitting/reordering user rules" — that must be **proven against live pf semantics
before** the splice is built (ADR-01: prove the premise first). It is also a **deliberate
behaviour change** (the `order_4`/managed-rule reordering goes away) on public behaviour. Those
deserve an explicit plan with a precedence kill-gate and the user-immutability contract pinned by
tests — not an inline edit.

## 2. Decision

Stop rebuilding the rule list. Treat **user rules as immutable** and only **move pfBlockerNG's own
rules**:

> Take the live `filter/rule` list. **Remove only the pfB-owned rules** this region regenerates
> (descr starts `pfB_`, excluding the DNS-redirect/DoT bypass rules). Keep every remaining rule —
> user rules and bypass rules — **exactly where it is, in its existing order, with its existing
> count**. **Generate** the pfB rules (unchanged generation). **Splice** them into the kept list
> at a single anchor computed from `pass_order`. Write back.

Drop, duplicate, and reorder of user rules become **structurally impossible** for every
`pass_order` and interface config, because the code never buckets, filters, or re-emits a user
rule — it only deletes pfB rules and inserts pfB rules.

| Area | Decision |
| --- | --- |
| **User rules** | **Immutable.** Never bucketed, filtered, duplicated, or reordered. The kept list = the live `filter/rule` minus the pfB-owned rules this region regenerates, in original order. |
| **Bypass rules** | DNS-redirect / DoT-block (`pfB_` descr, but inline-managed) are **kept** in place like user rules — not stripped, not regenerated here. |
| **pfB rule generation** | **Unchanged.** `pfb_firewall_rule()` and the `$pfb['permit_*']`/`$pfb['deny_*']`/DNSBL-float builders produce the same rules (same trackers, interfaces, types) as today. |
| **Placement** | A single **insertion anchor** per `pass_order`, derived from the ORDER table and **validated against live pf first-match precedence (Phase 2)**: the contiguous pfB block(s) are spliced before/after the kept user rules so the intended pfB-vs-user precedence holds **per interface** (where pf actually evaluates them). The `order_2`/`order_3`/`order_4` pfB-pm-vs-pfB-br distinction is preserved by splicing the pfB pass/match block and the pfB block/reject block at their table positions — still without touching user rules. |
| **Float vs non-float** | Both paths use the same immutable-user model. The floating path is already correct (live-confirmed); the rewrite must not regress it. Floating rules' relative order is preserved by keeping user rules verbatim (pf separates floating from interface rules regardless of `config.xml` interleaving). |
| **Empty/unknown `pass_order`** | Sanely defaulted (subsumes the #539 fix): an unrecognised order maps to the `order_0` anchor. With user rules immutable, an unknown order can at worst mis-*position* the pfB block — it can never drop a user rule. |
| **Write gate** | Unchanged: write + `filter_configure()` only when the rebuilt list differs from the original. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **User-rule fidelity.** Every non-pfB rule present before the reconciliation is present after,
   **exactly once**, in its **original relative order** — set, count, and order identical.
   (red→green for `order_1`/`order_2` dup and `order_4` reorder; oracle-green for `order_0`/`order_3`.)
2. **Bypass-rule fidelity.** DNS-redirect/DoT-block rules are preserved (not stripped, not
   duplicated) — same as today.
3. **pfB rule set identical.** The pfB rules emitted (descr, type, interface, tracker, ipprotocol,
   floating) are the same as today's for the same inputs — only their *position* relative to user
   rules is governed by the new anchor.
4. **pfB-vs-user precedence per `pass_order`.** For rules that actually interact (same interface,
   or floating), the new placement yields the **same first-match precedence** the ORDER table
   intends — pinned on the live VM (Phase 2 establishes the mapping; Phase 4 asserts it).
5. **Float path unchanged.** Every `pass_order` with `enable_float=on` preserves user rules and
   precedence exactly as today (live-confirmed correct).
6. **Write/`filter_configure` gating unchanged.** The list is written (and the rule reload fired)
   iff it actually changed; an unchanged config is a no-op (idempotence pinned).
7. **No drop on empty order.** The #532 invariant holds **by construction** (user rules are never
   bucketed), independent of the `order_0` default.

### Explicitly kept / out of scope

- **pfB rule generation** (`pfb_firewall_rule()`, the permit/match/deny builders, DNSBL ping/permit
  pair) — unchanged; we change *where* pfB rules land, not *what* they are.
- **The `pass_order` UI / config field** and its `order_0..order_4` vocabulary — unchanged.
- **The alias-table build + reload path** (ADR-40 territory) — untouched.
- **DNSBL rule management** — untouched.
- **`config.xml` schema** — no migration; the existing `filter/rule` list is read and rewritten in
  place.
- **The #539 empty→`order_0` default** — kept as a harmless belt-and-suspenders (the immutability
  contract makes it non-load-bearing), or folded into the anchor's unknown-order mapping. Decided
  in Phase 3.

## 3. Consequences

**Positive**

- **Correctness by construction.** Drop, duplicate, and reorder of user rules are impossible — not
  "fixed for the cases we found", but eliminated as a class. One design replaces three latent bugs.
- **Smaller, clearer surface.** The bucketing (`$permit_rules`/`$other_rules`/per-interface
  filtering) and the duplicate per-interface emission loops collapse into "delete pfB rules, splice
  pfB block at the anchor". Far less code, far fewer branches.
- **Security posture.** User firewall rules are never silently mutated by a feed update — a
  property admins can rely on.
- **Reuses pfB generation verbatim** — no change to what rules pfBlockerNG creates, so no risk to
  the blocking behaviour itself.

**Negative / risks**

- **Precedence premise (ADR-01 trap).** If a single anchor per `pass_order` cannot reproduce the
  intended precedence for some config without splitting user pass vs user block rules (which would
  violate immutability), the design must narrow. **Mitigation:** Phase 2 proves the anchor model on
  live pf *before* Phase 3; if it fails, re-scope (see §7 reject criteria).
- **Deliberate behaviour change.** `order_4` (and the managed/non-managed split) no longer reorders
  user rules; some installs' `config.xml` rule order changes. Functionally inert where pf is
  per-interface first-match, but visible. **Mitigation:** documented; Phase 2 confirms no
  precedence regression on the same interface; release-notes call-out.
- **Multi-interface / mixed pfB permit+deny configs are under-represented in the factory image.**
  The live image's user rules are LAN/opt1 pass rules; pfB permit rules (`Permit_*` actions) and
  inbound≠outbound need explicit fixtures. **Mitigation:** Phase 1 PHPUnit fixtures cover them
  off-appliance; Phase 4 smoke adds an inbound≠outbound and a `Permit_*` case.

## 4. Requirements (acceptance)

- Across **every** `pass_order` (absent, `order_0`..`order_4`) × **float on/off**, the non-pfB
  user-rule multiset is **preserved exactly** (same set, count, order) before vs after the
  reconciliation, and **stable** across repeated reloads — on the live VM. (Today: fails for
  non-float `order_1`/`order_2`; passes after.)
- The pfB rules emitted are identical (descr/type/interface/tracker) to today's for the same
  inputs — pinned off-appliance.
- pfB-vs-user **precedence** for same-interface (and floating) rules matches the ORDER table on the
  live VM, for each `pass_order` (the Phase 2 mapping).
- DNS-redirect/DoT bypass rules are preserved.
- Re-running with identical inputs is a no-op (no write, no `filter_configure()`); idempotence
  pinned.
- The #532 drop cannot recur for any order (immutability), with #544's smoke still green.

## 5. Constraints (from CLAUDE.md)

- PHP: tabs; PHP 8.3; no `die()`/`exit()` in library code; match `pfB_*`/`$pfb[...]` naming; route
  any registered config access through `PfbConfig` (ADR-29) — none expected (no new field).
  pfSense functions via `stubs/pfsense/` + `tests/php/pfsense_doubles.php`; never `require_once` a
  pfSense file in tests. Keep PHPCS green (UppercaseBooleanLiteral, PFBL-01, RequireConfigGateway).
- Test coverage (five non-negotiables): the core phase pins a test that **fails before / passes
  after** (the dup/reorder/drop preservation); prep phases pin TODAY's emission as an **oracle**
  that stays green; **every branch** (each `pass_order`, float on/off, inbound==outbound vs ≠,
  `Permit_*` vs `Deny_*`) gets its own assertion; no phase without tests; intent-named, not coverage
  theater.
- pf rule generation + precedence are **not real in CI** → precedence + end-to-end preservation are
  **live-VM** (ADR-04) items; PHPUnit pins the pure emission/splice off-appliance.
- ADR text + phase prompts land **directly on the branch** (docs carve-out, no PR); every
  `src/`/`tests/` phase uses the full worktree + rebase-only-PR flow.

## 6. Action plan

Front-loaded with behaviour-preserving prep (extract + oracle-pin the emission) and a **precedence
kill-gate** before any splice. The core rewrite (Phase 3) only proceeds once Phase 2 proves the
anchor model on live pf.

### Phase 1 — Extract + oracle-pin the rule reconciliation (prep, behaviour-preserving)

- **Prompt:** `01_Extract_And_Pin.txt`
- Extract the emission (bucketing `:14586`–`:14651` + the per-interface loops + tail
  `:14729`–`:14839`) into a **pure, named helper** in `pfblockerng.inc` — e.g.
  `pfb_build_autorule_list($existing_rules, $pfb_generated, $order, $float, $in_ifaces,
  $out_ifaces)` returning the new `filter/rule` array — keeping the call site behaviour-identical.
  pfB-rule *generation* stays where it is; the helper consumes the already-generated arrays.
- **Tests (oracle, stay green):** PHPUnit pins TODAY's exact output (including the known-bad
  `order_1`/`order_2` duplication and the `order_4` reorder — pinned as "what it does now") for a
  fixture matrix: single managed interface (inbound==outbound), inbound≠outbound, `Deny_*` and
  `Permit_*` pfB rules, float on/off, every `pass_order`, and DNS-bypass rules present. This makes
  the Phase-3 diff exact and visible.

### Phase 2 — Pin pf precedence + prove the anchor model (the kill-gate; ADR-01 lesson)

- **Prompt:** `02_Precedence_Gate.txt`
- On the ADR-04 live VM, dump the **generated** ruleset (`pfctl -sr` / `rules.debug`) for
  representative `pass_order` configs and **establish the real evaluation model** (first-match /
  `quick` per interface; floating handling) — verified, not assumed. Build the
  **`pass_order` → insertion-anchor** mapping (where the pfB pass/match block and block/reject
  block go relative to the kept user rules) and **prove** it reproduces the ORDER table's intended
  pfB-vs-user precedence **per interface** for every order, including a config with both pfB permit
  and pfB deny rules.
- **Kill / re-scope (record in RESULTS):** if a single contiguous anchor per order cannot express
  some order's intended precedence without splitting user pass vs user block rules (which would
  break immutability), **re-scope** (see §7) — keep immutability and accept the closest faithful
  precedence, or narrow which orders are reworked. The deliverable is the anchor-mapping table,
  the live `pfctl` evidence, and the verdict. **No production code in this phase.**

### Phase 3 — Implement immutable-user-rules reconciliation (core; red→green)

- **Prompt:** `03_Immutable_Splice.txt`
- Replace the bucketing + per-interface user emission with: keep-list = existing minus pfB-owned
  (excluding bypass); generate pfB rules (unchanged); splice the pfB block(s) at the Phase-2 anchor
  for the active `pass_order`; write iff changed. Remove the now-dead bucketing/`$permit_rules`
  machinery. Update the Phase-1 PHPUnit oracle to the **new** expected output (the diff shows user
  rules now verbatim; pfB rules repositioned, identical set).
- **Tests (red→green):** the Phase-1 fixtures now assert **user-rule fidelity** (multiset + order
  preserved) for every case — red on today's code for `order_1`/`order_2`/`order_4`, green after;
  pfB-rule-set-identical assertion; idempotence (same input → no change). Add the **live oracle
  smoke** (`tests/smoke/` — factory-restore sweep across `pass_order` × float asserting exact
  user-rule preservation + stability) — red on old pkg, green on new (validated this session's
  way: build the fix-reverted pkg, watch it fail).

### Phase 4 — Live precedence + smoke + docs + DoD

- **Prompt:** `04_Smoke_Docs_DoD.txt`
- Live-VM assertions that pfB-vs-user **precedence** matches the Phase-2 mapping for each
  `pass_order` (a blocked vs allowed probe through pf, not just `config.xml` order) — including an
  inbound≠outbound and a `Permit_*` case. Keep #544's `test_smoke_lan_rule_preserve.py` green.
  Update `docs/misc/architecture-notes.md` (the new immutable-user reconciliation model, replacing
  the strip-and-rebuild description), the CLAUDE.md autorule mechanics, and note the deliberate
  `order_4` behaviour change for release notes.

## 7. Definition of done

- All §4 requirements met; the live-VM factory-restore oracle sweep (every `pass_order` × float,
  exact user-rule preservation + stability) green on the CE + Plus fan-out.
- Phase 2's pf-precedence mapping recorded with live `pctl`/`rules.debug` evidence and an explicit
  verdict that the anchor model reproduces the ORDER table per interface (or the documented
  re-scope).
- The bucketing / `$permit_rules` / per-interface user-emission machinery removed; the
  reconciliation reduced to delete-pfB + splice-at-anchor.
- PHPUnit oracle updated to the new output; idempotence + pfB-rule-set-identical green; #544 smoke
  still green.
- Docs updated; the deliberate `order_4`/managed-reorder behaviour change noted for release notes.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- On a real box, with a user `pass` rule and a pfBlockerNG `Deny` list on the **same** interface,
  confirm across `order_1`/`order_2` that the user rule is **not** duplicated over repeated
  Cron/Force updates (the live image approximates this; confirm on hardware with real interfaces).
- Confirm, for each `pass_order`, that a blocked destination is actually blocked and the LAN allow
  still passes — i.e. the new placement preserves **precedence**, not just `config.xml` order
  (true pf evaluation under live traffic).
- Confirm a config restore / XMLRPC sync that lands an absent-`pass_order` config does not drop the
  user's LAN rule on the next update.

**REJECT / re-scope criteria (what would kill or narrow this ADR):**

- **Phase 2** shows a single contiguous anchor per `pass_order` **cannot** reproduce the ORDER
  table's intended precedence for a realistic config (mixed pfB permit+deny + user rules) without
  splitting/reordering user rules → **re-scope:** keep user immutability as the hard invariant and
  accept the nearest faithful precedence (document the small divergence), or limit the rework to
  the orders where a clean anchor exists, leaving the others on a guarded version of today's path.
- The deliberate `order_4`/reorder behaviour change is judged unacceptable for back-compat →
  narrow to "never drop/duplicate" only (keep today's positions), i.e. land the de-dup + the
  immutability for count, defer the position normalisation.
- The rewrite cannot keep the **float** path's already-correct behaviour without regression →
  scope the rewrite to the non-floating path only (where all three defects live) and leave floating
  untouched.
