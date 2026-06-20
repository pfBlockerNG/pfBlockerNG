# ADR-35: Unify ownership + teardown of pfBlockerNG-managed firewall objects

- **Status:** **Proposed** (2026-06-20)
- **Date:** 2026-06-20
- **Branch:** `adr/35-managed-firewall-objects` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):** new `src/usr/local/pkg/pfblockerng/pfblockerng_fwobj.inc` (ownership +
  marker helpers), `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (VIP/NAT/filter create +
  remove call sites), `src/usr/local/pkg/pfblockerng/pfblockerng_install.inc` /
  `pfblockerng.xml` (deinstall sweep wiring)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8)
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` (live-VM, ADR-04)
- **Enables:** ADR-36 (DNS Redirection NAT), ADR-37 (DoT/DoQ port block) — both register their
  rules through the seam this ADR establishes.

## 1. Context

pfBlockerNG writes objects into three pfSense-core `config.xml` sections — **`virtualip/vip`**,
**`nat/rule`**, **`filter/rule`** — and is responsible for removing them on disable and on
package uninstall. Today each is managed by its own ad-hoc code with **inconsistent ownership
markers and inconsistent teardown**:

- **VIP** (ADR-13). Markers `PFB_AUTO_VIP_DESCR_V4 = 'pfB_AUTO_VIP_v4'` /
  `PFB_AUTO_VIP_DESCR_V6 = 'pfB_AUTO_VIP_v6'` (`pfblockerng.inc:315`). Created idempotently by
  `pfb_manage_dnsbl_vip()` (`:1178`) via `pfb_find_marked_vip()` (`:1121`, matches `descr`
  marker only). Disable removes only entries matching the marker **AND** the IP stored in
  `pfb_dnsvip4`/`pfb_dnsvip6` (a double-guard so a manually created VIP is never touched). A
  legacy `'pfB DNSBL'` descr is migrated to the marker on upgrade (`pfblockerng_install.inc:48`).
- **NAT** (DNSBL anti-lockout / web redirect). `pfb_create_dnsbl()` (`:3775`) writes `nat/rule`
  entries with `descr = 'pfB DNSBL - DO NOT EDIT'` (`:3822`), detected by
  `strpos($descr, 'pfB DNSBL') !== FALSE` (`:3798`), stripped on `$mode == 'disabled'`.
- **Filter** (DNSBL pass rules + IP-feed deny/permit/match). `pfb_firewall_rule()` (`:7835`) +
  `sync_package_pfblockerng()` manage `filter/rule` keyed on a **`pfB_` descr prefix** (`:13709`
  separates pfBlockerNG rules from user rules); **all** `pfB_`-prefixed rules are stripped and
  rebuilt from scratch each sync.

Load-bearing facts:

- **Uninstall relies on lifecycle ORDER, not on a marker sweep.**
  `pfblockerng_php_pre_deinstall_command()` (`pfblockerng.inc:14423`, wired via
  `pfblockerng.xml` `<custom_php_pre_deinstall_command>`) calls `sync_package_pfblockerng()`
  (which runs `pfb_manage_dnsbl_vip('disabled')` and the filter/NAT teardown) **before**
  `pfb_remove_config_settings()` (`:14512`) bulk-deletes `installedpackages/pfblockerng*`. The
  deinstall never independently scans `virtualip/vip` / `nat/rule` for the marker. **If a prior
  run half-failed and left an orphan** (e.g. a VIP whose `pfb_dnsvip4` reference was already
  cleared, so the double-guard no longer matches it), that orphan is **never removed** — it
  survives uninstall. This is the concrete fragility this ADR closes.
- **`config.xml` storage is hard-frozen (ADR-28).** Existing markers are persisted strings:
  renaming `'pfB_AUTO_VIP_v4'` or `'pfB DNSBL - DO NOT EDIT'` would orphan every object created
  by a prior release across upgrade. Marker strings already on disk are therefore **immutable**;
  this ADR may add recognition + a new convention for *new* objects, never rewrite the old ones.
- **These are pfSense-core sections** (`virtualip`, `nat`, `filter`) — on the ADR-29
  foreign-key exclusion list, accessed via direct `config_*_path` (not `PfbConfig`). Unchanged.
- **No live pf/Unbound in CI** — the pure ownership/marker logic is unit-tested off-appliance
  against `config.xml`-shaped fixtures; the real add/remove/uninstall against a running box is a
  live-VM smoke (ADR-04).
- **Two new features are queued** (ADR-36 DNS-redirect NAT, ADR-37 DoT/DoQ filter block) that
  each need exactly this: create an owned rule, reconcile it idempotently, remove it on disable,
  and have it swept on uninstall. Without a shared seam they would each re-invent the marker +
  teardown code a fourth and fifth time.

## 2. Decision

Introduce a **small, shared ownership-and-teardown layer** for pfBlockerNG-managed firewall
objects (VIP / NAT / filter), and **retrofit** the existing VIP + DNSBL-NAT management onto it
**without changing any persisted marker string or observable behaviour**. The layer adds the one
genuinely missing guarantee — a **marker-based defensive sweep on disable and on uninstall** —
and exposes a **registration seam** that ADR-36/37 plug into.

This is a **refactor + hardening**, not a rewrite. It is deliberately a set of **functions +
constants in one new include**, not a class/registry hierarchy (see Alternatives).

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| Ownership model | A pfBlockerNG object is **owned iff its `descr` carries a recognised pfBlockerNG marker**. Marker is the sole ownership signal. New objects use a single convention: `descr` begins `pfB_` (the prefix the filter side already uses). |
| Marker recognition | `pfb_fwobj_is_owned($descr)` recognises the **union of all known markers** — the new `pfB_` prefix **plus** the exact legacy strings (`pfB_AUTO_VIP_v4/v6`, `pfB DNSBL`, `pfB DNSBL - DO NOT EDIT`, the legacy `'pfB DNSBL'` VIP descr). Legacy strings are matched verbatim; never rewritten (storage freeze). |
| Helper layer | new `pfblockerng_fwobj.inc`: pure predicates (`pfb_fwobj_is_owned`, marker builders) + section operators `pfb_fwobj_find()` / `pfb_fwobj_remove()` over a given section (`virtualip/vip`, `nat/rule`, `filter/rule`) with an optional **secondary-guard** predicate (e.g. VIP's `subnet == stored IP`). |
| Retrofit (VIP) | `pfb_manage_dnsbl_vip()` / `pfb_find_marked_vip()` call the shared find/remove with the **same** marker + the **same** IP double-guard. Behaviour identical; pinned before/after. |
| Retrofit (NAT) | `pfb_create_dnsbl()` NAT add/strip calls the shared find/remove with the existing `'pfB DNSBL'` marker. Behaviour identical. |
| Filter side | **Left as-is** (already strips all `pfB_` rules each sync — effectively a sweep). The shared `pfb_fwobj_is_owned()` reuses the same `pfB_` predicate so recognition is consistent, but the rebuild-each-sync model is **not** changed. |
| Deinstall sweep | **NEW.** After the normal lifecycle teardown and **before** `pfb_remove_config_settings()`, run `pfb_fwobj_sweep()` over `virtualip/vip` + `nat/rule` (+ a `filter/rule` `pfB_` safety pass) removing **every** owned object by marker — even orphans the lifecycle missed. Idempotent; a no-op when nothing is owned. |
| Disable sweep | The same marker sweep is the teardown primitive `pfb_manage_dnsbl_vip('disabled')` etc. call, so a disable that races a half-written state still converges. |
| Registration seam | `pfb_fwobj_register($spec)` — a feature declares `{ type: vip/nat/filter, marker, builder, guard? }`. The reconcile/remove/sweep machinery then covers it for free. ADR-36/37 consume this; ADR-13's VIP and the DNSBL NAT are expressed as the first two registrations. |
| Safety invariant | A removal/sweep **only ever** deletes an object whose `descr` matches a pfBlockerNG marker. A user object (no marker) is **never** touched — asserted by tests that seed sibling user VIP/NAT/filter rows and prove they survive. |

### 2.2 Semantics that MUST be preserved / hold (the contract — pin with tests before refactor)

- **No persisted marker string changes.** Every `descr` written today is written byte-identical
  after the refactor; recognition is additive. (Upgrade safety: objects from a prior release
  stay owned.)
- **Behaviour-preserving retrofit.** For the existing VIP and DNSBL-NAT paths, the exact same
  objects are created, found, and removed as before — same idempotency, same VIP IP double-guard.
  Pinned by before/after tests over `config.xml` fixtures.
- **User objects are inviolable.** No marker → never created, modified, or deleted. A removal or
  sweep that would touch a non-marked row is a bug; tests seed user rows and assert survival.
- **Orphan teardown.** An owned object whose secondary guard no longer matches (e.g. a VIP whose
  stored IP reference was cleared) is still removed by the marker sweep on disable/uninstall.
- **Idempotent + safe-on-empty.** Reconcile finds-or-creates exactly one object per spec; sweep
  on a clean config is a no-op (no spurious `write_config`).
- **No new `config.xml` schema / no `PfbConfig` change.** The managed sections stay
  pfSense-core, accessed by direct `config_*_path`; no registered field is added by this ADR.

### 2.3 Explicitly kept / out of scope

- **The actual new rules** (DNS-redirect NAT, DoT/DoQ block) — those are **ADR-36 / ADR-37**;
  this ADR only builds the seam and proves it on the existing VIP + NAT.
- **Renaming/normalising legacy markers** — out (storage freeze; would orphan prior-release
  objects). Recognition handles the heterogeneity instead.
- **Reworking the filter-rule rebuild-each-sync model** — out; it already self-sweeps. Only
  recognition is unified.
- **A generic OO "managed resource registry" / class hierarchy** — out (over-engineering for
  ~3 object types; see Alternatives). Functions + constants only.
- **Changing `pfb_remove_config_settings()` bulk-delete of `installedpackages/pfblockerng*`** —
  unchanged; the sweep is additive and runs before it.

## 3. Consequences

**Positive**

- One ownership convention + one teardown primitive across VIP/NAT/filter — less duplicated,
  drift-prone marker logic.
- Closes the real uninstall gap: orphaned VIP/NAT objects from a half-failed run are now removed
  on uninstall instead of surviving forever.
- Gives ADR-36/37 (and any future managed rule) create/reconcile/remove/sweep for free, so those
  ADRs stay thin and consistent.
- Behaviour-preserving + storage-frozen, so it ships with no upgrade risk and is fully unit-pinnable.

**Negative / risks**

- A sweep that mis-identifies ownership could delete a user object — mitigated by "marker is the
  sole signal", the immutable legacy-marker allow-list, and tests that prove user rows survive.
- Retrofitting two live call sites (VIP, NAT) risks a subtle behaviour change — mitigated by
  before/after golden tests over `config.xml` fixtures **written first** (Phase 1).
- Real config mutation (VIP bring-up/down, pf reload) can only be fully validated on a live box —
  covered by the ADR-04 smoke (add/remove/uninstall + orphan sweep), a documented non-CI gate.

## 4. Requirements (acceptance)

- `pfblockerng_fwobj.inc` with `pfb_fwobj_is_owned`, `pfb_fwobj_find`, `pfb_fwobj_remove`,
  `pfb_fwobj_sweep`, `pfb_fwobj_register`; pure where possible, unit-tested.
- VIP + DNSBL-NAT retrofitted onto it with **identical** persisted markers and behaviour
  (before/after tests green).
- Deinstall (and disable) marker sweep wired in before `pfb_remove_config_settings()`; orphans
  removed; user objects untouched (asserted).
- The registration seam demonstrated by expressing the VIP + DNSBL NAT as registrations.
- All gates green (§5); live-VM smoke proves add→remove→uninstall leaves `config.xml` clean and
  a seeded orphan is swept, while a user-created VIP/NAT/filter survives.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code; new pfSense fns stubbed
  (`stubs/pfsense/`) + doubled (`tests/php/pfsense_doubles.php`).
- ADR-28: uppercase `TRUE`/`FALSE`; storage freeze (no persisted marker/string change).
- ADR-29: managed sections are pfSense-core (foreign) → direct `config_*_path`, **not**
  `PfbConfig`; do not register a new field; the `RequireConfigGateway` sniff must stay green.
- PFBL-01: any new dynamic path / `exec` in scope validated; if `pfb_fwobj_*` lands in
  `pfblockerng.inc` scope, keep the sniff green (the helpers do no shell/exec — pure config).
- ADR-04 smoke for the end-to-end add/remove/uninstall + orphan sweep (no pf in CI).

## 6. Action plan

### Phase 1 — Prep: pin current VIP/NAT ownership + teardown behaviour (behaviour-preserving)

- Prompt: `01_Pin_Current_Behaviour.txt`
- Add PHPUnit golden tests over `config.xml`-shaped fixtures pinning **today's** behaviour:
  VIP find-by-marker + create idempotency + disable removal (marker **AND** IP double-guard);
  DNSBL-NAT add + `strpos('pfB DNSBL')` strip; and that a sibling **user** VIP/NAT row is never
  touched. No production change — this is the oracle the refactor must not break.
- Tests: the above, all green against current `pfblockerng.inc` (via the existing doubles).

### Phase 2 — Extract the ownership/marker layer (`pfblockerng_fwobj.inc`)

- Prompt: `02_Fwobj_Layer.txt`
- New include with pure `pfb_fwobj_is_owned($descr)` (union of new `pfB_` prefix + the exact
  legacy markers), `pfb_fwobj_find($section, $marker, $guard=NULL)`, `pfb_fwobj_remove(...)` —
  no shell, no `write_config` inside the helpers (caller flushes, mirroring `PfbConfig`).
- Tests: `is_owned` truth table (each legacy marker + new prefix = owned; unmarked/user = not);
  find/remove over fixtures with and without the secondary guard; user rows survive.

### Phase 3 — Retrofit VIP + NAT onto the layer (behaviour-preserving)

- Prompt: `03_Retrofit_Vip_Nat.txt`
- Rewire `pfb_find_marked_vip()` / `pfb_manage_dnsbl_vip()` and `pfb_create_dnsbl()`'s NAT
  add/strip to call the shared find/remove with the **same** markers + the VIP IP guard. No
  persisted string changes.
- Tests: the Phase-1 golden suite still green (proves identical behaviour); plus the retrofit
  paths now exercise the shared helpers.

### Phase 4 — Deinstall + disable marker sweep + registration seam

- Prompt: `04_Sweep_And_Seam.txt`
- Add `pfb_fwobj_sweep()` (marker sweep over `virtualip/vip` + `nat/rule` + `filter/rule` `pfB_`
  safety pass) and wire it into `pfblockerng_php_pre_deinstall_command()` **before**
  `pfb_remove_config_settings()`; have the disable teardown use the same primitive. Add
  `pfb_fwobj_register($spec)` and express the VIP + DNSBL NAT as the first registrations.
- Tests: a seeded **orphan** (owned marker, guard no longer matching) is swept on deinstall;
  a sibling user object survives; sweep on a clean config is a no-op (no `write_config`).

### Phase 5 — Live-VM smoke + DoD + docs

- Prompt: `05_Smoke_DoD_Docs.txt`
- ADR-04 smoke: enable → assert pfBlockerNG VIP + DNSBL NAT exist in `config.xml`; disable →
  assert removed; seed an orphan VIP + a **user** VIP/NAT, uninstall → orphan gone, user objects
  survive, `installedpackages/pfblockerng*` gone. Architecture-notes blurb + manual checklist.

## 7. Definition of done

- [ ] `pfblockerng_fwobj.inc` layer (is_owned/find/remove/sweep/register), pure parts unit-tested
      (branch coverage: each legacy marker + new prefix; guard on/off; user-row survival).
- [ ] VIP + DNSBL NAT retrofitted with **no** persisted marker/string change; Phase-1 golden
      suite green (behaviour identical, before/after).
- [ ] Deinstall + disable marker sweep wired before bulk config delete; orphan removed; user
      objects untouched; clean-config sweep is a no-op (asserted).
- [ ] Registration seam in place and demonstrated (VIP + NAT registered through it); ready for
      ADR-36/37.
- [ ] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS (PFBL-01 + ADR-28 + ADR-29 sniffs),
      `php -l`, `python -m pytest`; live-VM smoke proves add→remove→uninstall + orphan sweep.

**Manual smoke (owner: maintainer):**

- [ ] Install → enable DNSBL VIP + DNSBL → confirm VIP + NAT present (Firewall ▸ Virtual IPs /
      NAT) with the pfBlockerNG markers.
- [ ] Create an unrelated user VIP + a user NAT/filter rule → uninstall pfBlockerNG → confirm the
      user objects survive and **no** `pfB_*` object remains.
- [ ] Force an orphan (e.g. clear the `pfb_dnsvip4` reference but leave the marked VIP) →
      uninstall → confirm the orphan is swept.

**Reject criteria:** if the unified ownership signal cannot distinguish pfBlockerNG objects from
user objects reliably across the heterogeneous legacy markers (risk of deleting user data), or
the retrofit cannot be made provably behaviour-preserving, **reduce** to "deinstall sweep only"
(keep the per-object code, add just the defensive sweep) or **reject**, recording the evidence.
