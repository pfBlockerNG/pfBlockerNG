# ADR-55: Client Groups & Group Policy (M:N policy bindings, scoped IP firewall rules)

- **Status:** **Proposed** (2026-07-04)
- **Date:** 2026-07-04
- **Part of the Group-Policy redesign trilogy:** ADR-54 (data model) → **ADR-55 (this)** →
  ADR-25 revised (DNSBL enforcement engine). Committed follow-ups: ADR-56, ADR-57. See §0.
- **Depends on:** ADR-54 **complete** (FEED/FEED GROUP entities). DNSBL *enforcement* of
  bindings is **not** here — ADR-25 consumes what this ADR stores.
- **Branch:** `adr/55-client-groups-group-policy` (off `devel`) / **Component(s):**
  `pfblockerng.inc` (CG alias materialization, scoped rule generation, validation),
  `pfblockerng_extra.inc` (helpers), `src/usr/local/www/pfblockerng/` (new
  `pfblockerng_group_policy.php`, `pfblockerng_group_policy_edit.php`; touched
  `pfblockerng_dnsbl.php` + tab arrays across pages), `config.xml` schema, ports
  pkg-plists, `tests/`, PHPCS PFBL-01 scope.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). No Python change in this ADR.
- **Test suite:** `tests/php/` (PHPUnit — rule generation, validation, migration),
  `tests/smoke/` (ADR-04; source-bound harness extension) + ADR-14 `ui_render`/`ui_e2e`.
- **UI reference implementations:** [`UI/`](UI/) — authoritative design targets for
  Phase 3 (§2.6).

---

## 0. Relationship & execution order (read this first)

```text
ADR-25 Phase 1 (cache spike) ────────────────────────────┐  parallel from day one
                                                          ▼
ADR-54 P1→P2→P3→P4 ──→ ADR-55 P1→P2→P3→P4 ──→ ADR-25 P2..P7 ──→ ADR-56 ──→ ADR-57
                        (this ADR)
```

- ADR-54 gives the entities; **this ADR gives the WHO (Client Groups) and the EDGES
  (policy bindings) and materializes the IP side** (scoped pf rules + native schedules).
- **DNSBL-family bindings are stored but locked** (§2.4): the binding editor offers only
  `ipv4`/`ipv6` Feed Groups until ADR-25's engine lands; ADR-25 then unlocks `dnsbl`
  options (Block/Warn/Bypass overrides) in this ADR's UI. This keeps every landed phase
  fully functional — no dead controls, no silent no-ops.
- Every phase is orchestrator-gated: Sonnet 5 implements; the orchestrator adversarially
  reviews at `xhigh` against the phase kill-gates before the next phase (CLAUDE.md
  planner/implementer flow — mandatory, per phase).

## 1. Context — today

- **Rules have no per-source scoping.** `pfb_firewall_rule()` (`pfblockerng.inc:9654-9899`)
  builds: outbound shapes with `source = any`, `destination = pfB alias`; inbound shapes
  with `source = pfB alias`, `destination = any`. A `Deny_Outbound` group blocks **every**
  LAN host. The only narrowing is the per-group Advanced fields — exactly ONE custom
  alias per direction (`aliasaddr_in/out` → `$asrc_out`/`$adest_in`), resolved from
  pfSense `aliases/alias` in `pfb_determine_list_detail()` (`:4160-4195`). **The seam this
  ADR needs already exists** — it is just single-valued.
- **Ordering is owned by ADR-41** (Implemented): `pfb_build_autorule_list()`
  (`:12982-13151`) sorts four buckets per the `pass_order` table (`:12950-12957`) —
  **pfB pass/match precedes pfB block/reject in every order_0..4** — applied independently
  to the floating and interface groups; user rules never dropped/mutated. `Alias_*`
  actions create the table but **no rule** (`:4112-4136`).
- **Schedules**: pfSense firewall rules natively carry a `sched` reference evaluated by
  `filter_get_time_based_rule_status()` — free for our generated rules. (DNSBL-side
  schedule evaluation is ADR-25's serialised-ranges mechanism.)
- **Today's "Group Policy"** is one global DNSBL bypass textarea (`pfb_gp` +
  `pfb_gp_bypass_list`, registered PfbConfig fields; UI at `pfblockerng_dnsbl.php`
  ~`:2966-2984`). ADR-25 §1.3 documents it; this ADR migrates it.
- pf runs `rdr` **before** filtering: WAN inbound rules match the **translated**
  destination, so scoping inbound rules by internal Client-Group addresses matches
  port-forwarded traffic — standard pfSense semantics.

Anchors verified 2026-07-04; resolve fresh at implementation time.

## 2. Decision

### 2.1 CLIENT GROUP entity

New section `installedpackages/pfblockerngclientgroups`, a `config` listtag:

| Field | Meaning |
| --- | --- |
| `name` | ≤24 chars (`pfB_CG_` + name ≤ 31, the pf table limit), `\W`-rejected, unique |
| `description` | free text (HTML-filtered) |
| `enabled` | `on`/`''` — disabled ⇒ config kept, **nothing materialized** |
| `addresses` | base64 textarea (the `pfb_gp_bypass_list` storage idiom): IPv4/IPv6 addresses/CIDRs, one per line, `sanitize_ipaddr`-validated (PFBL-01) |
| `aliases` | list of pfSense alias names (host/network type, non-`pfB_*`) |
| `allow_domains` / `deny_domains` | base64 textareas — DNSBL domain rules for this CG's clients (stored now, **enforced by ADR-25**) |
| `binding` | nested listtag — the policy edges (§2.2) |

Materialization: ONE pfSense native alias **`pfB_CG_{name}`** (network type; inline
addresses + nested alias refs — pf resolves nesting, `filterdns` resolves FQDN host-alias
members), written through the existing alias-reconcile writer
(`pfblockerng.inc:16943-16961`). **DNSBL caveat** (stored for ADR-25): FQDN alias members
are ignored for DNSBL client matching (manifest needs literal IPs/CIDRs) — UI warns.

### 2.2 POLICY BINDING (the CG↔FG M:N edge)

Nested `binding` rows under the client group:

| Field | Meaning |
| --- | --- |
| `feedgroup` | FG `name` ref (family implied by the FG) |
| `enabled` | `on`/`''` |
| `action_override` | `''` (= FG default) \| IP: `Deny_Inbound/Outbound/Both`, `Permit_*`, `Match_*` (no `Alias_*`) \| DNSBL (locked until ADR-25): `Block`/`Warn`/`Bypass` |
| `log_override` | `''` (default) \| `enabled`/`disabled` |
| `sched` | `''` (always) \| a pfSense `<schedules>` entry name |

(CG, FG) pairs unique. Dangling `feedgroup` (group deleted) ⇒ binding skipped + notice
(fail-safe, never a crash); dangling `sched` ⇒ rule emitted **without** a schedule
(= always active — fail-open matches ADR-25's rule and pfSense's own behaviour for a
deleted schedule).

### 2.3 Enforcement semantics — default + exceptions (the model, both sides)

- **An FG with no bindings behaves exactly as today** — its `default_action` emits the
  global rules. Zero-CG configs are byte-identical (regression oracle).
- **Bindings never remove the default — they ADD scoped rules:**
  - outbound shapes: `source = pfB_CG_{cg}` → `destination = pfB_{fg}` (today's custom-src
    seam, now per-edge);
  - inbound shapes: `source = pfB_{fg}` → `destination = pfB_CG_{cg}`;
  - action = `action_override ?: FG default_action`; log = `log_override ?:` group logging;
    `sched` riding the native rule field.
- **Policy-only groups**: FG `default_action = Alias_*` ⇒ table exists, no global rule ⇒
  enforcement exists ONLY through bindings. Same knob, no new concept. (DNSBL analogue:
  `policy_only`, ADR-54 §2.2, consumed by ADR-25.)
- **Ordering**: ADR-41's buckets already give scoped-Permit-before-global-Deny in every
  `pass_order` (pfB pass/match bucket precedes pfB block/reject — verified,
  `pfblockerng.inc:12950-12957`). Within a bucket, binding rules order before that FG's
  default rules (deterministic; not load-bearing).
- **The dead-override trap — REFUSED at save**: a `Deny_*` override on a `Permit_*`-default
  FG can never match (the FG's global pass bucket precedes every deny bucket; pf has no
  "skip only these" — the ADR-53 §1.4 lesson). `input_errors`: *"A Deny override on a
  Permit-default Feed Group has no effect (pfBlockerNG Permit rules precede Block rules).
  Remove the override or change the Feed Group's Default Action."* The symmetric
  Permit-override-on-Deny-default is the supported carve-out case and works by bucket
  order.
- **Override conflicts** (client in ≥2 CGs with different overrides on the same FG): on
  the IP side there is no conflict to resolve — all edges emit rules and pf's first-match
  over the ordered buckets yields **most-permissive wins** (pass bucket first). ADR-25
  implements the same rule (`Bypass > Warn > Block`) on the DNS side for consistency —
  overrides are carve-outs. Documented in the UI help.
- **Rule-count surface**: the policy pages display the generated-rule count per CG and in
  total (bindings × directions × families × interfaces is real money; the admin sees it).

### 2.4 DNSBL bindings: stored, locked, unlocked by ADR-25

The schema accepts `dnsbl`-family bindings, but **Phase 3's UI offers only `ipv4`/`ipv6`
Feed Groups** and the generator ignores `dnsbl` bindings entirely. ADR-25's UI phase flips
the switch (adds the dnsbl options + `Block/Warn/Bypass` override vocabulary + the CG
domain-rule enforcement). Rationale: never ship a control that silently does nothing.

### 2.5 Migration

`pfb_gp` + `pfb_gp_bypass_list` (when enabled and non-empty) → a **`Legacy_Bypass`** CG:
`addresses` = the bypass list verbatim, plus one `Bypass`-override binding per **dnsbl**
FG (stored-but-locked per §2.4 — behaviourally the legacy path stays live through the
existing `gpListDB` mechanism **until ADR-25 lands and replaces it**; this ADR does NOT
touch the python bypass path). Idempotent; absent ⇒ no-op. The DNSBL-page section is
replaced by a pointer (§2.6). The legacy keys are kept in place until ADR-25 completes the
handover (they are PfbConfig-registered; ADR-25 owns their retirement).

### 2.6 UI (stock components ONLY — hard constraint, same rules as ADR-54 §2.6)

Reference implementations in [`UI/`](UI/), authoritative for Phase 3:

- `UI/pfblockerng_group_policy.php` — **new page, complete file**: CG list (panel +
  sortable table, AJAX quick-edit `enabled`, rule-count footer).
- `UI/pfblockerng_group_policy_edit.php` — **new page, complete file**: CG editor — Info /
  Members (addresses textarea + alias multi-select) / DNSBL Domain Rules (collapsed) /
  Feed Group Policies as stock `repeatable` rows (FG select + override select + log
  select + schedule select + delete; Add Policy button) / live rule-count StaticText.
- `UI/dnsbl_page_changes.md` — replace the legacy Group Policy section with the pointer
  text; tab-array sweep instructions (add `Group Policy` after `Feeds` on every page).

### 2.7 Semantics that MUST be preserved (contract)

- **Zero CGs ⇒ byte-identical rule output** (ADR-54's oracles extended with a
  bindings-empty fixture — same goldens).
- **ADR-41 invariants intact**: buckets, user-rule immutability, tracker determinism
  (binding rule descrs are `pfB_{fg}_CG_{cg}{suffix}`-style so `pfb_tracker()` stays
  deterministic and `pfb_is_managed_obj()` owns them via the `pfB_` prefix).
- **Rule regeneration stays change-gated** (`$orig_rules_nocreated != $new_rules_nocreated`
  → `filter_configure()`); binding edits ride the same gate; **no `filter_configure()` on
  the content-only path** (ADR-40 contract).
- **Legacy bypass keeps working untouched** until ADR-25's handover (§2.5).
- **PFBL-01** on every new input surface (addresses, names, binding fields) — the new save
  handlers join the sniff's `scopeFunctions`.
- The CG alias is a **managed object**: created/updated/removed via the alias-reconcile
  writer; deinstall sweep removes `pfB_CG_*` like every `pfB_` alias.

### 2.8 Explicitly out of scope

- DNSBL enforcement of bindings, CG domain rules, Warn/Bypass semantics, divergence-gated
  caching — **ADR-25**.
- Per-CG SafeSearch/DoH (ADR-56), GeoIP bindings (ADR-57).
- MAC/hostname/interface client identity (IP/CIDR + alias refs only).
- A "warning/continue" block page (Warn on the DNS side = resolve+log, ADR-25).

## 3. Consequences

### Positive

- Per-client-set firewall policy with defaults + carve-outs — the requested capability on
  the IP side — using the existing rule seam, bucket order, and native schedules.
- The WHO (CG) is a reusable entity: ADR-25/56 consume it without new schema.
- Policy visibility: one page shows who gets what, with the rule-cost surfaced.

### Negative / risks

- Rule multiplication (edges × directions × interfaces) — surfaced in UI, bounded only by
  admin restraint; documented `maximumtableentries` note stays relevant.
- The dead-override class is validation-refused, but future action vocabulary changes must
  keep the validator in sync with the bucket table (test pins the matrix).
- Smoke needs source-bound traffic (Phase 4 harness extension) — per-CG behaviour is
  otherwise only unit-proven.

## 4. Requirements (acceptance)

- CG CRUD + alias materialization per §2.1; bindings per §2.2; scoped rules per §2.3 with
  every shape/direction/family combination unit-pinned (before+after state).
- Dead-override refusal with the exact message; (CG,FG) uniqueness; dangling refs fail-safe.
- `Legacy_Bypass` migration idempotent; legacy bypass functional throughout.
- Zero-CG oracles green; ADR-41 oracle (`AutoruleListOracleTest`) green with binding rules
  in the pfB buckets.
- Full gates green (PHPUnit, pytest, linters, PHPCS incl. updated PFBL-01 scope, Tier A
  everywhere, Tier B for both new pages + the binding flow) on the CE+Plus fan-out.

## 5. Constraints (from CLAUDE.md)

- PHP tabs / 8.3; no `die()/exit()`; stubs + doubles for any new pfSense fn; naming follows
  `pfb_*`/`pfB_` siblings; enums via the ADR-28 adapter pattern where a stored vocabulary
  is added (binding `action_override` is a stored string vocabulary — absorb unknown tokens
  to `''`/default at the read boundary).
- Worktree + rebase-only + `/pr-merge-flow`; ports lockstep for the two new pages;
  every phase one commit, orchestrator-gated.

## 6. Action plan

### Phase 1 — CG entity + alias materialization (inert)

- Prompt: `01_CG_Entity_Alias.txt`
- Schema, helpers, validation, `pfB_CG_*` alias reconcile, `Legacy_Bypass` migration
  (bindings stored/locked), deinstall sweep. **No rule generation.** Zero-CG +
  CG-with-no-bindings oracles both byte-identical.

### Phase 2 — Scoped rule generation + validation

- Prompt: `02_Scoped_Rules.txt`
- The per-edge rule emission through `pfb_firewall_rule()` (src/dst params), ADR-41 bucket
  integration, dead-override validator, rule-count helper, change-gate proof. Red→green
  for every new shape; ADR-41 oracle green.

### Phase 3 — Group Policy pages

- Prompt: `03_Policy_Pages.txt`
- Splice `UI/` references; tab sweep; DNSBL-page pointer; ports plists; Tier A + Tier B.

### Phase 4 — Source-bound smoke + docs + DoD

- Prompt: `04_Smoke_Docs_DoD.txt`
- Smoke harness source-bound queries/traffic (per-CG scoped deny/permit proven live on the
  VM), architecture-notes section, config-gateway foreign-key list, DoD sweep.

## 7. Definition of done

- [ ] §4 requirements green in CI; live-VM smoke green on the **CE + Plus fan-out**.
- [ ] Scoped-rule matrix unit-pinned: {Deny,Permit,Match} × {Inbound,Outbound,Both} ×
      {v4,v6} × {override, default-inherit} × {sched, none} — each with before+after
      assertions.
- [ ] Dead-override matrix test (every override token × every FG default) matches the
      validator table.
- [ ] `Legacy_Bypass` migration + legacy bypass still functional (smoke).
- [ ] Tier A all pages; Tier B: CG create→bind→save→reload→persisted; dead-override
      refusal text; rule-count renders.
- [ ] Docs updated (architecture-notes, config-gateway); PR references this ADR + `UI/`
      artifacts.
