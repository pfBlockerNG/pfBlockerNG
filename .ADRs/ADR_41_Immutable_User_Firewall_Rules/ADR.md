# ADR-41: Immutable user firewall rules in the IP autorule reconciliation

- **Status:** **Implemented — 4-way restored (pending live-VM smoke)** (2026-06-25). PR #561
  shipped a **flawed** binary-anchor design (Phase 3): its Phase-2 kill-gate (`RESULTS/02`) returned
  a **false GO** — its precedence reduction omitted the **pfB-Permit (pass) vs user-Block**
  interaction, so the single anchor broke that precedence for `order_1`/`order_2` (a pfB Permit list
  could not override a user Block) and dropped `order_4`'s **intended** user-block-before-user-pass
  emission. Corrected on `fix/adr-41-restore-pass-order` to the **4-way bucket stable reorder** (pfB
  p/m · pfB b/r · user p/m · user b/r, ordered per `pass_order`, applied independently to the
  floating and interface pf groups), keeping the genuine ADR-41 wins (never duplicate/drop/mutate a
  user rule). Off-appliance contract pinned **red→green** in `AutoruleListOracleTest` (the
  pfB-Permit-vs-user-Block trap per order + behavioural equivalence to the frozen `8c4c482`
  reference on every dup-free config). Full analysis: **`RESULTS/05`** (supersedes the binary-anchor
  `RESULTS/02`). Flips to **Accepted** once the §7 live-VM fan-out (CE + Plus) — the per-`pass_order`
  data-plane precedence sweep in `test_smoke_autorule_immutable.py` (still skipped pending Phase-4
  wiring) — is green.
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

> **Correction (`fix/adr-41-restore-pass-order`).** Only **DROP (#1)** and **DUPLICATE (#2)** are
> genuine defects. The "REORDER" (#3) is two separate things, and neither is a removable bug:
> (a) `order_4` placing a user **Block** before a user **Pass** is the *intended* `pass_order`
> semantics (GUI `order_4 = pfB p/m | pfB b/r | pfSense Block/Reject | pfSense Pass/Match`); and
> (b) the cross-interface reposition (`opt1` before `lan`) is **behaviourally inert** under
> per-interface first-match (different-interface rules never interact). The fix keeps both: it
> restores the 4-way `pass_order` bucketing and eliminates only the DROP and the DUP. The
> binary-anchor design (PR #561) wrongly "fixed" #3 by freezing user-rule order — which deleted
> order_4's intended reorder **and** broke pfB-Permit-vs-user-Block precedence (see §2/§3).

These symptoms come from **one** fragile design: *strip everything and rebuild, re-bucketing
user rules*. The fix removes the DROP and DUP while preserving the intended `pass_order` bucketing
— not by abandoning the bucketing, but by making it a stable reorder that never dups/drops/mutates.

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

Stop *mutating* user rules. Reconcile by a **stable bucket reorder** — the same `pass_order`
bucketing as before, but one that can never drop, duplicate, or content-mutate a user rule:

> Sort every surviving rule (user rules and the regenerated pfB rules) into one of four buckets —
> **pfB pass/match**, **pfB block/reject**, **user pass/match**, **user block/reject** — preserving
> each rule's content verbatim (bar the legacy `_v4` upgrade) and the original order **within** each
> bucket. Concatenate the buckets in the `pass_order` sequence (the ORDER table), applying it
> **independently** to the two pf groups pf evaluates separately — the **floating** group (DNSBL/
> match pass rules; plus pfB permit/deny when float mode is on) and the **interface** group (pfB
> permit/deny when float mode is off). pfB-owned rules (descr starts `pfB_`, excluding the
> DNS-redirect/DoT bypass rules) are regenerated; everything else passes through. Write back.
>
> **Correction (`fix/adr-41-restore-pass-order`).** The original Decision below said "keep every
> remaining rule **exactly where it is, in its existing order**" and splice the pfB block at a
> **single anchor**. That is wrong: `order_1`/`order_2` deliberately **split** the user rules around
> the pfB block (user pass/match in front, user block/reject behind), and `order_4` places the
> user's own Block before its Pass — so the buckets *must* be reordered relative to one another.
> Freezing user-rule order (the single-anchor design) breaks pfB-Permit-vs-user-Block precedence
> and deletes order_4's intended layout. The corrected invariant is **no DROP, no DUP, no content
> mutation, and within-bucket order preserved** — *cross*-bucket placement is exactly what
> `pass_order` controls.

DROP, DUPLICATE, and content-MUTATION of user rules become **structurally impossible** for every
`pass_order` and interface config, because each user rule lands in exactly one bucket and is emitted
once, verbatim — while the `pass_order` table still governs where the buckets sit.

| Area | Decision |
| --- | --- |
| **User rules** | **Content-immutable.** Never duplicated, dropped, or content-mutated; within-bucket order preserved. They ARE sorted into the user pass/match and user block/reject buckets and placed per `pass_order` (that cross-bucket placement is what `pass_order` means). |
| **Bypass rules** | DNS-redirect / DoT-block (`pfB_` descr, but inline-managed) are **kept** like user rules — not stripped, not regenerated here. |
| **pfB rule generation** | **Unchanged.** `pfb_firewall_rule()` and the `$pfb['permit_*']`/`$pfb['deny_*']`/DNSBL-float builders produce the same rules (same trackers, interfaces, types) as today. |
| **Placement** | The **4-bucket stable reorder** (pfB p/m · pfB b/r · user p/m · user b/r), concatenated in the ORDER-table sequence and applied **independently** to the floating and interface pf groups. NOT a single before/after anchor: `order_1`/`order_2` split the user rules around the pfB block so a pfB **Permit** precedes a user **Block**, and `order_4` places the user's own Block before its Pass — neither expressible with one contiguous anchor. (The Phase-2 "single anchor" claim was a false GO; see `RESULTS/02` correction + `RESULTS/05`.) |
| **Float vs non-float** | Both paths use the same immutable-user model. The floating path is already correct (live-confirmed); the rewrite must not regress it. Floating rules' relative order is preserved by keeping user rules verbatim (pf separates floating from interface rules regardless of `config.xml` interleaving). |
| **Empty/unknown `pass_order`** | Sanely defaulted (subsumes the #539 fix): an unrecognised order maps to the `order_0` anchor. With user rules immutable, an unknown order can at worst mis-*position* the pfB block — it can never drop a user rule. |
| **Write gate** | Unchanged: write + `filter_configure()` only when the rebuilt list differs from the original. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **User-rule fidelity.** Every non-pfB rule present before the reconciliation is present after,
   **exactly once**, with its **content intact** and its order preserved **within its bucket** —
   no drop, no dup, no mutation. (Cross-bucket placement follows `pass_order`; a global "same
   order" check would be wrong — it would forbid order_1/2/4's intended reorder.) Pinned red→green:
   the pfB-Permit-vs-user-Block precedence trap fails on the binary helper, green on the 4-way.
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

- **Precedence premise (ADR-01 trap) — this is exactly what bit PR #561.** The premise "a single
  anchor per `pass_order` reproduces the intended precedence" is **false**: `order_1`/`order_2` need
  the pfB block *between* the user pass/match and user block/reject rules, so a pfB **Permit** can
  override a user **Block** — impossible with one contiguous anchor. The Phase-2 gate false-GO'd by
  reducing the table to "pfB-block vs user-pass" and omitting the **pfB-pass vs user-block**
  interaction, then testing only a Deny-only config (pfB-pass bucket empty). **Resolution:** the
  4-way bucket assembly (this revision); the off-appliance trap fixture is the gate the Deny-only
  live probe should have been. The genuine ADR-01 lesson holds: a kill-gate that does not exercise
  the falsifying case (mixed pfB permit+deny + user pass+block) proves nothing.
- **`order_4` reorder is INTENDED, not removed.** `order_4` emits the user's own Block before its
  Pass — documented `pass_order` semantics, preserved here. (The binary-anchor revision wrongly
  deleted it by freezing user-rule order; that was a regression, not a feature.) The only visible
  `config.xml` change vs PR #561's behaviour is restoring the correct per-`pass_order` ordering;
  vs the pre-ADR-41 baseline, behaviour is preserved on every dup-free config (the DROP/DUP cases
  are the fixes). Release-notes call-out: the order_1/order_2 Permit-vs-Block precedence fix.
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

> **Correction (`fix/adr-41-restore-pass-order`).** The Phases below are the *original* plan, which
> built the **binary-anchor** design. Phase 2's GO was false and Phase 3 shipped a flawed helper
> (PR #561). The course correction (Phase 5, `RESULTS/05`) replaces it with the **4-way bucket
> stable reorder** and supersedes the "single anchor" / "remove the bucketing" / "order_4 reorder
> removed" framing here: the `pass_order` bucketing is **kept** (as a no-dup/no-drop/no-mutate
> stable reorder), not deleted. Read the §0 Status, §2, and §3 corrections for the current design.

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
