# ADR-29: Centralized configuration gateway (one reader/writer owning defaults, migrations, and the rollback contract)

- **Status:** **Proposed** (2026-06-19)
- **Date:** 2026-06-19
- **Branch:** `adr/29-config-gateway` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` — the new `PfbConfig` gateway + field registry (joins the existing ADR-28 enums/adapters that already live here)
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — `pfb_global()` read seam, `pfb_remove_config_settings()`, the migration/seed helpers, the pre-deinstall hook
  - `src/usr/local/pkg/pfblockerng/pfblockerng_install.inc` — the install-time migration blocks (become a registry-driven driver)
  - `src/usr/local/www/pfblockerng/` — every UI page's `$pconfig` load/save
  - `tests/php/` — registry round-trip + migration + rollback unit tests; `tests/smoke/test_upgrade_config_stability.py` — extended with a downgrade (rollback) leg
  - `tests/phpcs/PfBlockerNG/` — the enforcement sniff
  - `CLAUDE.md` — the gateway policy of record
- **Target runtime:** PHP 8.3 (pfSense CE 2.8). `config.xml` is written **only** by PHP (UI pages, install hooks, XMLRPC sync); Python (`pfb_unbound.py`) and shell read **generated** artifacts (`py_unbound.ini`, manifests), never `config.xml` — so the gateway is PHP-only and there is no cross-language writer.
- **Test surface:** `vendor/bin/phpunit` + `vendor/bin/phpcs` + `vendor/bin/phpstan` (PR gate); `python -m pytest` (tooling); `tests/smoke` (ADR-04 live VM — the upgrade + rollback contract); `ui_render` (Tier A PR gate)

Originates from **issue #281** (config-loss-on-upgrade) and its maintainer follow-up: *"isolate the
configuration reader/writer … all reads and writes go through it and it owns all
migration/adapters required to ensure the configuration can be read … and to avoid as many
contract breaks as possible (so rolling back is tentatively smooth)."* Builds directly on **ADR-28
§2.2** (config storage hard-freeze + field-aware read/write adapters), which this ADR generalises
from a per-call-site convention into a single enforced gateway. The #281 point-fix (a `pfb_keep`
default + seed migration) already landed (`1e2904f`); this ADR removes the *class* of bug.

---

## 1. Context (today)

### 1.1 How config is accessed now (measured, not assumed)

- `config.xml` access is **scattered and unmediated**: **204** `config_get_path()`, **132**
  `config_set_path()`, **25** `config_del_path()` calls across `src/` — in `pfblockerng.inc`,
  `pfblockerng_install.inc`, and **every** `www/pfblockerng/*.php` page. Each site hand-rolls its
  own defaulting, vocabulary, and absent-key handling.
- The config→runtime **read seam** is `pfb_global()` (`pfblockerng.inc:1302-1309+`): it loads each
  `installedpackages/...` blob into `$pfb[...]`. ADR-28 routed ~78 checkbox/mode fields here
  through **field-aware adapters** (`pfb_cfg_toggle_read/write`, `pfb_cfg_lenient_read/write`,
  `pfb_cfg_idn_mode_read/write` in `pfblockerng_extra.inc`, backed by enums `PfbToggle`,
  `PfbLenient`, `PfbIdnMode`). Those adapters are invoked **per call site by convention** — nothing
  enforces it, and the `www/` pages largely still read raw strings.
- **Defaults are duplicated per read site and can diverge.** Issue #281 was exactly this: the GUI
  defaulted `pfb_keep` to `'on'` (`pfblockerng_general.php:57`) while `pfb_global()` read it raw
  (`:1309`, no default), so the pre-deinstall hook saw "off" and wiped all config on upgrade. Same
  key, two effective defaults.
- **Migrations are ad-hoc and unordered.** Four independent upgrade migrations exist —
  ADR-02 (inline in `pfblockerng_install.inc`), `pfb_control_legacy_seed()`,
  `pfb_dnsbl_lenient_migrate()`, `pfb_keep_migrate()` (`pfblockerng.inc:6332/6358/6379`) — each a
  hand-wired `config_get → *_migrate → config_set → write_config` block. There is **no registry**,
  **no ordering guarantee**, and **no inventory** of "every key → its default → its migration".
- **The wipe surface is broad.** `pfb_remove_config_settings()` (`pfblockerng.inc:6360+`)
  `config_del_path()`s **~22** `installedpackages/pfblockerng*` sections; the pre-deinstall hook
  (`pfblockerng_php_pre_deinstall_command()`) invokes it. It cannot distinguish a true package
  removal from an upgrade-time reinstall (pfSense fires `pre_deinstall` for both).

### 1.2 Load-bearing constraints

- **`config.xml` stored values are hard-frozen** (ADR-28 §1.3/§2.2): no config-version routine
  exists; the stored representation **is** the upgrade contract. Any change that alters a stored
  value is a silent settings-loss regression with no repair path. The gateway **must not** change
  stored bytes.
- **PHP is the sole writer.** No concurrent cross-language writer to coordinate (Python/shell read
  generated files). The gateway needs no locking beyond what pfSense's `write_config()` already
  provides.
- **No live Unbound / no live pfSense in CI** except the dispatch-only ADR-04 smoke VM; the
  off-box PHPUnit suite loads the real `.inc` via shims/doubles (`tests/php/`).

### 1.3 Premise check (this is NOT an ADR-01-style perf bet)

There is **no performance premise** — per-key config reads are unmeasurably cheap. The
justification is **correctness and maintainability**: (a) a single canonical default per key
removes the #281 class (divergent defaults between read sites); (b) an **explicit rollback /
backward-compatibility contract** — older code reading values written by newer code — which ADR-28's
*forward-only* freeze never addressed. The risk to weigh is **over-build** (ADR-01): a 204/132-site
refactor whose payoff is structural, not behavioural. Mitigation is the phasing discipline (§6) and
a falsifiable rollback gate (§7) — and the explicit reject path (§7) to narrow scope if the churn
cannot be contained.

## 2. Decision

Introduce a single **`PfbConfig` gateway** in `pfblockerng_extra.inc` that owns **every**
`config.xml` access for the package, backed by a **declarative field registry** and an **ordered
migration registry**, and **migrate all existing call sites onto it in staged, behaviour-preserving
phases** (§6). Adopt "all reads/writes go through the gateway" as **policy of record in
`CLAUDE.md`**, enforced by a targeted sniff.

### 2.1 The gateway + field registry

- **`PfbConfig::read($key)` / `::write($key, $value)` / `::delete($key)`** become the only
  sanctioned config accessors for registered keys. They wrap `config_get_path/set_path/del_path`.
- **Field registry** — one declarative table, `key → { section, default, vocabulary, read-adapter,
  write-adapter, since-version }`. The ADR-28 enums/adapters become registry **entries**, not
  scattered call-site logic. The #281 `pfb_keep` default (`'on'`) becomes one registry default,
  defined **once**.
- **Read** applies the registered default + read-adapter (stored string → runtime enum/bool/string).
  **Write** applies the write-adapter (runtime value → the **exact legacy stored string**), upholding
  the ADR-28 §2.2 byte-identity freeze and round-trip identity.
- **Section-level helpers** for the bulk section read/write/delete the `www/` pages and
  `pfb_remove_config_settings()` use, so the broad wipe and the per-page `$pconfig` round-trips also
  flow through one place.

### 2.2 The migration registry

- The four existing migrations (ADR-02 inline, `pfb_control_legacy_seed`, `pfb_dnsbl_lenient_migrate`,
  `pfb_keep_migrate`) become **ordered, idempotent, `since-version`-gated entries** run by **one
  driver** in `pfblockerng_install.inc` — replacing the hand-wired blocks. Behaviour-preserving: the
  same keys are seeded with the same values in a defined order; each stays run-once/idempotent.
- Adding a future migration is a registry entry with a `since-version`, not a copy-pasted block.

### 2.3 The rollback / backward-compatibility contract (the new guarantee)

- Each registry field carries a **`since-version`**. The contract: **code at version *N* must read,
  without crash or silent settings-loss, any `config.xml` written by version *N±k*** for every
  shipped *k* — both **forward** (ADR-28's existing freeze: new code reads old store) and
  **backward / rollback** (old code reads what new code wrote).
- The gateway makes this achievable: because writes always emit the **legacy stored vocabulary** for
  a field (never a new on-disk token), a downgrade leaves older code reading values it already
  understands. A field that **cannot** be made rollback-safe (e.g. a genuinely new stored token an
  older release would not recognise) is **excluded** — kept as a plain string / documented — exactly
  as ADR-28 excludes non-round-trippable fields.

### 2.4 Semantics that MUST be preserved (the contract — pinned before each swap)

1. **Every `config.xml` stored value is byte-identical** before/after every phase (the ADR-28
   freeze) — proven per field by round-trip tests + the upgrade smoke (§7).
2. **No behavioural change** from routing a read/write through the gateway — the DNSBL/IP/Geo
   decisions, UI page output, install/upgrade side effects, and the wipe surface are identical.
   Proven by PHPUnit golden tests over touched logic + the ADR-04 smoke fan-out + `ui_render`.
3. **Default parity** — for every key, the gateway's single registered default equals the value the
   *current* read site would have produced for an absent/empty key (so centralising a default is
   behaviour-preserving — except where it deliberately repairs a #281-class divergence, which is
   called out and tested).
4. **Migration order + idempotency** — the registry driver runs the existing migrations in an order
   and run-once discipline that reproduces today's outcome on every existing install state.

### 2.5 Explicitly kept / out of scope

- **`config.xml` stored format** — frozen (ADR-28 §2.2); the gateway never migrates stored bytes.
- **`py_unbound.ini`, manifests, and any serialized/wire value** read by Python or shell — those are
  generated artifacts / inter-process contracts, not `config.xml`; unchanged.
- **Non-pfBlockerNG config** (`system/*`, `installedpackages/shellcmdsettings`, widgets sequence,
  `unbound`) the package incidentally touches — the gateway covers the `installedpackages/pfblockerng*`
  keys; foreign keys stay on direct `config_*_path` (documented per site).
- **Changing the pre-deinstall upgrade-vs-removal behaviour** — broadening the hook to skip the wipe
  on upgrade is a *behavioural* change; it is **out of scope here** (a possible separate ADR). This
  ADR only routes the existing wipe through the gateway.
- **`stubs/`, generated artifacts, third-party vendored code.**

## 3. Consequences

**Positive**

- One canonical default per key → the #281 class (divergent defaults between read sites) becomes
  structurally impossible.
- Migrations gain a registry, ordering, and an inventory; adding a key/migration is a declarative
  entry, not a copied block.
- An explicit, CI-pinned **rollback** contract (not just forward-compat) — downgrades are smooth by
  construction because writes always emit legacy vocabulary.
- The ADR-28 adapters move from "invoked by convention" to "enforced by the gateway + sniff"; new
  code follows mechanically.

**Negative / risks**

- **Large, correlated refactor** (204 reads / 132 writes / all `www/` pages). Mitigated by the
  phasing: tested infra first, then bounded per-subsystem migration phases, each one commit, each
  green, each reviewed at the boundary.
- Centralising a default can change behaviour if a read site secretly relied on a *different*
  absent-key default than the registry picks — §2.4.3 pins **default parity** per key to catch this;
  a deliberate repair (#281-style) is called out and tested.
- The rollback guarantee is only as good as the test that falsifies it (§7); a field that cannot
  round-trip or downgrade is excluded rather than forced.

**Neutral**

- Python/shell are untouched (they read generated artifacts). The gateway is PHP-only.

## 4. Requirements (acceptance)

- `PfbConfig` gateway + declarative field registry + section helpers in `pfblockerng_extra.inc`,
  reusing the ADR-28 enums/adapters; round-trip identity pinned for every registered field's full
  stored vocabulary.
- Ordered, idempotent, `since-version`-gated **migration registry** + driver replacing the four
  hand-wired migrations; behaviour-preserving, pinned by tests (incl. the existing migrate tests).
- **All** `installedpackages/pfblockerng*` read/write/delete call sites routed through the gateway,
  in the §6 phases — `pfb_global()`, install/migrations, the wipe, and every `www/` page.
- A **rollback/backward-compat** test gate: off-box per-field `since-version` invariants + the
  `tests/smoke/test_upgrade_config_stability.py` smoke extended with a **downgrade leg** (install
  newer build, write settings, downgrade to older build, assert sane reads + byte-identical store).
- A targeted **enforcement sniff** (PHPCS/PHPStan) forbidding raw `config_*_path` on a registered
  key outside the gateway; wired into `phpcs.xml.dist` + CI; pinned by a fixture test.
- Policy of record in `CLAUDE.md`; full suite green at every phase (`python -m pytest`,
  `vendor/bin/phpunit`, `vendor/bin/phpstan`, `vendor/bin/phpcs`, `ui_render`).
- Final acceptance: **smoke fan-out (CE + Plus) + UI tiers green** + the upgrade **and** rollback
  smoke green.

## 5. Constraints (from CLAUDE.md)

- **Naming** — gateway/registry symbols follow the `pfb_*`/`Pfb*` house pattern; registry keys are
  the exact existing `config.xml` keys (no renames).
- **PHP** — tabs; PHP 8.3; uppercase `TRUE`/`FALSE`/`NULL` (ADR-28 sniff); no `die()`/`exit()` in
  library code; keep the PFBL-01 `RequirePfbFilter` sniff green; stub any newly-reached pfSense
  function from upstream.
- **Hard-freeze** — never change a stored `config.xml` value/format (ADR-28 §2.2).
- **Clean the diff** — each phase minimal and intentional; no gratuitous reformatting of untouched
  lines; alignment opportunistic within touched blocks only.
- **Plan with a higher model, implement with Sonnet** — each phase executed by a Sonnet sub-agent
  under orchestrator gating (`/adr-phase`).

## 6. Action plan

**Strategy.** (1) The tested gateway + field/migration registries land **first** as infra, unused by
prod call sites, so the safety net exists before any routing. (2) The rollback contract + its
falsifiable test land next, so every later migration phase is gated by it. (3) Call sites are then
migrated **per subsystem** in bounded, behaviour-preserving phases — highest-risk seam first
(`pfb_global` + the wipe, the #281 surface), then install/migrations, then the `www/` pages grouped
to keep each diff reviewable. (4) Enforcement + DoD last. Each phase is one commit, leaves the full
suite green, and is reviewed against its objective before the next.

### Phase 1 — Gateway + field registry infrastructure + policy (prep)

Prompt: `01_Gateway_And_Registry.txt` — behaviour-preserving, unused-in-prod.

- Add `PfbConfig` (gateway: `read/write/delete` + section helpers) and the **declarative field
  registry** (key → section/default/vocabulary/read-adapter/write-adapter/since-version) to
  `pfblockerng_extra.inc`, reusing the ADR-28 enums/adapters.
- Pin **round-trip identity** per registered field over its full stored vocabulary, and an
  **inventory-completeness** test: every `installedpackages/pfblockerng*` key currently read in
  `src/` has a registry entry (or is explicitly listed as out-of-scope/foreign).
- Write the gateway policy into `CLAUDE.md`. No call site changed yet.

### Phase 2 — Migration registry + driver (prep)

Prompt: `02_Migration_Registry.txt` — behaviour-preserving.

- Consolidate ADR-02 inline + `pfb_control_legacy_seed` + `pfb_dnsbl_lenient_migrate` +
  `pfb_keep_migrate` into one **ordered, idempotent, since-version-gated** migration registry + a
  single driver in `pfblockerng_install.inc`. Same keys, same values, same effective order.
- Pin with the existing migrate tests + a new ordering/idempotency/run-once test over representative
  pre-existing install states.

### Phase 3 — Rollback / backward-compat contract + test gate (prep)

Prompt: `03_Rollback_Contract.txt` — behaviour-preserving (tests + doc).

- Encode each field's `since-version` and the forward+backward invariant (§2.3). Add off-box
  per-field rollback tests, and extend `tests/smoke/test_upgrade_config_stability.py` with a
  **downgrade leg** (newer→older `pkg` install; assert sane reads + byte-identical store). Document
  any field excluded for rollback.

### Phase 4 — Route the high-risk seam: `pfb_global()` reads + the wipe + pre-deinstall

Prompt: `04_Seam_Global_And_Wipe.txt` — behaviour-preserving via the gateway.

- Convert `pfb_global()` flag/section population and `pfb_remove_config_settings()` (+ the
  pre-deinstall read of `$pfb['keep']`) to `PfbConfig`. **Default parity** (§2.4.3) pinned per key.
  This is the #281 surface — the divergent-default repair is asserted here.

### Phase 5 — Route install-time writes + migrations through the gateway

Prompt: `05_Install_Writes.txt` — behaviour-preserving.

- Route `pfblockerng_install.inc` reads/writes (incl. the Phase-2 driver's `config_set` sites and the
  remaining install-time `config_*_path` calls) through `PfbConfig`. Retire any now-redundant raw
  access.

### Phase 6 — Route `www/` group A: General + IP + DNSBL

Prompt: `06_Www_Group_A.txt` — behaviour-preserving.

- Route `$pconfig` load/save in `pfblockerng_general.php` (the #281 `pfb_keep` save site),
  `pfblockerng_ip.php`, `pfblockerng_dnsbl.php` through the gateway/section helpers. `ui_render` green.

### Phase 7 — Route `www/` group B: SafeSearch + Reputation + Feeds + Blacklist

Prompt: `07_Www_Group_B.txt` — behaviour-preserving.

- Same for `pfblockerng_safesearch.php`, the reputation tab, `pfblockerng_feeds.php`,
  `pfblockerng_blacklist.php`, `pfblockerng_category_edit.php`.

### Phase 8 — Route `www/` group C: Alerts + Sync + Software + Logs + widgets/wizard

Prompt: `08_Www_Group_C.txt` — behaviour-preserving.

- Same for `pfblockerng_alerts.php`, `pfblockerng_sync.php` (XMLRPC-fed config), `pfblockerng_software.php`,
  log pages, the dashboard widget, and the setup wizard. After this, no `installedpackages/pfblockerng*`
  raw `config_*_path` remains outside the gateway (foreign keys excepted, documented).

### Phase 9 — Enforcement sniff + CLAUDE.md reconcile

Prompt: `09_Sniff_And_Policy.txt`.

- Add a targeted PHPCS sniff (sibling to PFBL-01 / the ADR-28 sniff) flagging a raw `config_*_path`
  on a **registered** key outside `PfbConfig`; wire into `phpcs.xml.dist` + CI; pin with a fixture
  test. Reconcile `CLAUDE.md` (registry inventory, exclusions, the rollback contract).

### Phase 10 — Smoke/UI validation + upgrade & rollback contract + Definition of Done

Prompt: `10_Smoke_And_Validation.txt` — the acceptance gate.

- Confirm the upgrade smoke (`test_upgrade_config_stability.py`) + its **downgrade leg** green;
  dispatch `smoke-fanout.yml` (CE + Plus, AND-gated) and the UI tiers; record green run links;
  confirm the full DoD (§7).

## 7. Definition of done

- Every §4 requirement met; full suite green at every phase.
- **Round-trip identity** proven for every registered field over its full stored vocabulary; any
  excluded field documented in `CLAUDE.md` / the ADR.
- **Default parity** proven per key at the `pfb_global()` seam (the centralised default reproduces
  the prior per-site default, except the called-out #281 repair).
- **Migration registry** reproduces the four legacy migrations' outcomes on representative install
  states (ordered, idempotent, run-once).
- **Upgrade + rollback smoke green** on the live-VM fan-out: install older build → write a
  representative settings spread → `pkg upgrade` to branch build → assert byte-identical store +
  unchanged runtime behaviour (the #281 case); **and** the reverse downgrade leg → assert older code
  reads sane values. No manual sign-off (CLAUDE.md "ADR acceptance").
- **Smoke fan-out (CE + Plus) + UI tiers green**; the enforcement sniff active and green.
- **Residual manual check (owner: maintainer, out-of-CI):** true *visual* GUI correctness — a
  spot-check that the settings pages render unchanged. Documented out-of-CI limitation, not a
  blocker.
- **Reject criteria (explicit):**
  - If a field's stored value **cannot round-trip or downgrade losslessly** and cannot be excluded
    without losing the gateway's value → that field's centralisation is **rejected** (kept a string).
  - If routing a subsystem through the gateway **introduces behavioural regressions the tests cannot
    contain** → narrow scope to the infra + the high-risk seam (Phases 1–4) and leave the remaining
    `www/` sites on the "mandatory-for-new/touched-code" policy rather than forcing the full sweep.
  - If the gateway measurably complicates rather than simplifies the call sites (net negative on the
    maintainability premise) → stop at the infra + seam and reassess.

See the ordered `NN_*.txt` phase prompts in this directory.
