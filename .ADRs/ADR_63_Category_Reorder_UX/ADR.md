# ADR-63: Staged client-side reorder (drag + anchor-click) for category and category-row lists

- **Status:** **Proposed** (2026-07-10)
- **Date:** 2026-07-10
- **Branch:** `adr/63-category-reorder-ux` (off `devel`) / **Component(s):**
  `src/usr/local/www/pfblockerng/pfblockerng_category.php`,
  `src/usr/local/www/pfblockerng/pfblockerng_category_edit.php`, a new shared client-side JS
  reorder helper (folded into `pfBlockerNG.js` or a new `js/pfb_reorder.js`), `tests/php/`,
  `tests/smoke/ui/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); vanilla JS + jQuery/jQuery-UI (already loaded by
  pfSense's webConfigurator on every page — no new front-end dependency).
- **Test suite:** `tests/php/` (PHPUnit), `tests/smoke/ui/` (Tier A `ui_render`, Tier B
  `ui_e2e`/`ui_browser` — Playwright, already the repo's Tier-B tool; no JS unit-test harness
  exists in this repo today, confirmed absent — no `package.json`/`jest.config*`).

All `file:line` anchors below are measured on `origin/devel` @ `ce8aa8a9` (2026-07-10) and drift
as `devel` advances — re-grep before relying on one.

---

## 1. Context — today

### 1.1 Two pages, two different reorder mechanisms, both incomplete

**`pfblockerng_category_edit.php`** (editing the member rows *inside* one category — e.g. the
feed URLs of one DNSBL list) has an `Auto-Sort Header field` select (`sort`/`no-sort`,
`:1458-1460`, options at `:413`): `sort` (default, "Enable auto-sort") auto-orders rows by
header then enabled/disabled state on every render (`:1096`, `!isset($input_errors) &&
(empty($rowdata[$rowid]['sort']) || $rowdata[$rowid]['sort'] == 'sort')`) and shows **no**
manual-reorder UI at all. `no-sort` ("Disable auto-sort") is the **only** way to see or use
manual reordering — it renders a checkbox (`Lmove[{r_id}]`) + an anchor `<button
type="submit" name="Xmove" value="{r_id}">` per row (`:1132`). Clicking that button is a
**full-page form submit**: it lands in the `isset($Lmove) && isset($Xmove) && ...` reorder
block (`:928-980`) which computes a majority-vote `$pre` (before/after the anchor — just fixed
for issue #1145/PR #1150, a real placement-logic bug), rewrites `$rowdata[$rowid]['row']`
server-side, `config_set_path()` + `write_config()`, then `header("Location: ...")` + `exit` —
**one full page reload and one config write per single-row move**. A second, still-open,
orthogonal bug in the same block (issue #1149: a loose `!=` comparison silently drops the
anchor row when `Xmove` is literally `0`) lives in this exact code and would be retired by this
ADR rather than patched again. There is **no drag** affordance on this page at all today.

**`pfblockerng_category.php`** (the categories/lists themselves, one row per category) has
**no** `sort`/`no-sort` toggle — rows are always manually orderable via jQuery UI `.sortable()`
(`:687`, mouse-only: `cursor: 'move'`, `distance: 10`, no `update:` auto-save callback). This
page's persistence is **already** the better shape: dragging only moves `<tr class="sortable"
id="pfb_r{r_id}">` (`:426`) elements in the DOM — no server round-trip per drag. Only when the
user clicks `#btnsave` does `save_new_changes()` (`:611-664`) run: `$('#pfb_table table
tbody').sortable('serialize', {key:"ids[]"})` reads the `pfb_rN` DOM ids in **current visual
order** into `ids[]=r3&ids[]=r0&ids[]=r1…`, bundled with `$('#iform').serialize()` (every other
field, itself keyed by the **same stable original row id**, not by DOM position) into **one**
AJAX POST (`act=update`). Server-side (`:276-303`): each `ids[]` entry is parsed back to its
original `$rowid`, `$new_rows[$key] = $rowdata[$rowid]` rebuilds the array in the posted order,
one `config_set_path()` + `write_config()`. **This is already a correct "stage in the DOM, one
write on Save, keyed by a stable original id" design** — it does not need a persistence rework,
only a non-drag fallback: no anchor-click affordance exists, so a touch/mobile user with no
drag support cannot reorder at all (**issue #1147**, filed this session).

### 1.2 pfSense core's `firewall_rules.php` — the referenced prior art

Read at the user-supplied pin
(`github.com/pfsense/pfsense@9363ac5b8651a1c7a333180425ce7719070f95f9`,
`src/usr/local/www/firewall_rules.php`) to verify the claim, not assume it:

- **Anchor-click** (`:1109-1170`): a checkbox (`frc{N}`) per row + a per-row anchor icon
  (`Xmove_{N}`). Clicking it does a **pure client-side DOM move**
  (`insertBefore`/`insertAfter` the clicked row; shift-click = insert-after instead of
  insert-before) — no server round-trip. It calls `reindex_rules()` after every move and
  enables a `#order-store` **Save** button (initially `disabled`).
- **Drag** (`:1178-1196`, only rendered `if (!config_path_enabled('system/webgui',
  'roworderdragging'))`): jQuery UI `.sortable()`; its `update:` callback also just calls
  `reindex_rules()` and enables Save — no auto-persist.
- Both mechanisms are **staged**: nothing writes until `#order-store` (Save) is clicked, which
  submits the whole `#mainform` (rule identity travels as the `rule[]` checkbox **value**, i.e.
  the original PHP row index — order is simply that array's POST order) — server does one
  `set_filter_rules_order($_POST['rule'])`.
- `system/webgui/roworderdragging` (`:359`, `:1178`) is a **pfSense-core, site-wide user
  preference** (read via `config_path_enabled()`) — when set, only anchor-click is offered
  (no drag); default is both. This is prior art worth reusing read-only (ladder rung 2/4): it
  already exists, a package page can read it, and honouring it keeps behaviour consistent with
  every other page the user administers.
- **Verified, not assumed: `reindex_rules()`/`fr_toggle()`/`save_separators()` are NOT a
  reusable library.** They live in pfSense core's global `src/usr/local/www/js/pfSenseHelpers.js`
  (fetched and inspected this session, commit-pinned) but are **hard-coded to
  `firewall_rules.php`'s own DOM conventions** (`#ruletable`, `fr{N}`/`frc{N}` id prefixes,
  `separator[…]` fields, an `iface`/`configsection` global). `reindex_rules()` itself only
  rewrites a `<tr>`'s `id`/`onclick` — it does **not** touch any other per-row named field.
  pfBlockerNG cannot call these functions; only the **pattern** (stage client-side, reindex on
  move, gate a Save button, one write) is reusable, not the code.

### 1.3 Why literally porting `reindex_rules()` is the wrong fit — and why category.php's own pattern is the better model

`firewall_rules.php`'s reindex only ever renumbers **one** id per row. pfBlockerNG's
`pfblockerng_category_edit.php` save handler reads **several** independently-named per-row
POST fields keyed by the row's positional index at render time — `state-{r_id}`,
`format-{r_id}`, `url-{r_id}`, `header-{r_id}` (and more per `$gtype`) — correlated back
together by a `key_1` suffix-parse loop (`:546-607`). Porting `reindex_rules()`'s
"rewrite-the-DOM-attributes-on-every-move" approach here would mean relabelling **every** named
field of a moved row's `<tr>` on every single drag/anchor-click — more surface area for a
renumbering bug than the code it would replace.

**`pfblockerng_category.php` already avoids this trap**: it never renumbers per-row field
names on move. Every field keeps its **original**, render-time row id forever; only a single
separate `ids[]` array (the DOM's current `id` **order**, not new field names) is computed at
Save time and used server-side to re-key the array. This is the design this ADR generalises to
both pages — not a port of `firewall_rules.php`'s literal mechanism, its **UX pattern**
(drag + anchor-click, staged, explicit Save) layered onto pfBlockerNG's **own**, already-correct
persistence shape (stable id + one order array + one write on Save).

### 1.4 Config / gateway facts

- Both pages' row lists (`installedpackages/{$conf_type}/config/{$rowid}/row`) and the `sort`
  field live under the per-category-type config tree, not the top-level
  `installedpackages/pfblockerng*` scalars `PfbConfig` (ADR-29) registers — already a documented
  "foreign structure" exemption (`pfblockerng_category_edit.php:971` comment). No `PfbConfig`
  registration changes needed for anything this ADR touches.
- `system/webgui/roworderdragging` is pfSense-core namespace; this ADR only **reads** it
  (`config_path_enabled()`), never writes it.
- `geoip` rows are **not** `gtype`-excluded from either page's row-list/reorder code paths
  (only excluded from the generic per-row-field save loop on `category.php:261`, an unrelated
  branch) — the coverage matrix (§2) includes `geoip` alongside `ipv4`/`ipv6`/`dnsbl`.

### 1.5 Existing test coverage this ADR must reconcile

- `tests/php/CategoryEditRowMoveTest.php` — pure-array-transform oracle for the
  `$Lmove`/`$Xmove` server-side placement algorithm (15 tests as of PR #1150/#1145's fix). This
  entire file's premise is retired by Phase 4 (the algorithm it pins is deleted, not patched
  again) — it is **deleted**, not migrated; its final green state (post-#1145-fix) is the
  "before" snapshot this ADR's Phase 1 must independently corroborate is still intact
  pre-change.
- `tests/smoke/ui/test_category_edit_row_move.py` — 3 Tier-B (`ui_e2e`) tests driving the raw
  full-page POST that hits the `$Lmove`/`$Xmove` block directly (issues #1129/#1135). Same fate:
  **deleted** with the mechanism, replaced by new Tier-B coverage of the new save path.
- `tests/smoke/ui/test_category.py` — has **zero** existing coverage of the `ids[]` AJAX
  order-save path (confirmed by grep — no `ids[]`/`"ids"` reference anywhere in the file). A
  **pre-existing gap**, unrelated to this ADR's motivation but must be closed in Phase 1 anyway
  (an oracle for "today's" `category.php` reorder behaviour is a prerequisite for proving the
  new UI doesn't change it).
- `tests/smoke/ui/test_browser_category_edit.py`, `tests/smoke/ui/test_browser_category.py` —
  Playwright-driven Tier-B (`ui_browser`) harnesses **already exist** for both pages (currently
  covering unrelated fields: enable toggles, autoports, `chgstate`, `addrow`) — reuse this
  harness for the new drag/anchor-click browser tests; do not stand up a second one.

### 1.6 Cross-ADR interaction

Grepped every `.ADRs/*/ADR.md` for `sortable`/`Lmove`/`Xmove`/`row-move`/`reorder`/`drag`:
**ADR-54** (`Feed_Group_Normalization`, Proposed) and **ADR-55** (`Client_Groups_Group_Policy`,
Proposed) each mention a "sortable table" once, as a **generic UI-pattern reference** for a
*new* page they propose — neither claims or plans to touch
`pfblockerng_category.php`/`pfblockerng_category_edit.php`'s own reorder mechanism. No blocking
overlap; if ADR-54/55 land after this one, their new pages are natural (not mandatory)
consumers of this ADR's shared reorder component.

### 1.7 Explicit user decision (mid-design correction)

The `sort`/`no-sort` (Auto-Sort) toggle on `pfblockerng_category_edit.php` is **kept exactly as
today** — "auto-ordering is still something we want to support. Some people don't care." This
ADR only replaces the **manual** (`no-sort`) reorder UX; `sort=='sort'` behaviour (auto-order by
header/state, no manual UI shown) is Semantics item 2 below and must stay byte-identical.

---

## 2. Decision

**Layer pfSense-core's UX pattern (drag + anchor-click, staged client-side, one explicit Save)
onto pfBlockerNG's own already-correct persistence shape (stable row id + one order array,
`pfblockerng_category.php`'s existing design) — on both pages.**

1. **New shared client-side reorder component** (one JS file/module, parameterised by table
   selector, row-id prefix, checkbox name, and the hidden order-field name) implementing:
   drag (`jquery-ui sortable`, already used) **and** anchor-click (checkbox-per-row + a
   per-row anchor button; click = move checked rows before it, shift-click = after — mirrors
   `firewall_rules.php`'s UX, re-implemented against pfBlockerNG's own DOM, not copied). Both
   paths only move `<tr>` elements client-side and flip a `dirty` flag enabling a Save
   button — no per-move server call, on either page.
2. **Honour `system/webgui/roworderdragging`** (read-only): when set, render anchor-click only
   (no `.sortable()` init); default renders both, matching core pages.
3. **`pfblockerng_category.php`**: ADD the anchor-click affordance next to the existing drag.
   **No server-side change** — `ids[]` already accepts POST order from any client-side
   mechanism; only the client gains a second way to produce that order.
4. **`pfblockerng_category_edit.php`**: retire the `$Lmove`/`$Xmove` full-page-POST reorder
   branch (`:928-980`) entirely — this deletes the `$pre` majority-vote logic (#1145) and the
   loose-comparison anchor-drop bug (#1149) as a side effect of removing the code class they
   lived in, not as a targeted re-fix. Reorder becomes: render each row with a **stable**
   `id="pfb_er{r_id}"`-style id (mirroring `category.php`'s `pfb_r{r_id}` convention); the new
   JS component computes the same `ids[]`-style order array at Save time; the **existing** save
   handler (the `isset($_POST['save'])` branch) reads that order array **once**, validates it
   (Requirement 4 below — same spirit as #1129's guard, new implementation: every posted index
   must exist in the current row set, no missing/duplicate/foreign index, non-array/empty ⇒ no
   reorder applied, everything else saves normally), and reorders `$rowdata[$rowid]['row']`
   before the existing per-field save loop persists it. **One write, no separate
   move-then-redirect step**, folded into the page's normal Save.
5. **`sort`/`no-sort` unchanged** (§1.7): `sort=='sort'` shows no manual UI, exactly as today;
   `sort=='no-sort'` gets the new drag+anchor-click UI in place of the old checkbox+anchor-submit
   UI.

### Semantics that MUST be preserved (the contract — pin with tests before any swap)

1. **Final persisted row order, for any sequence of drag/anchor-click operations followed by
   Save, matches exactly what the user visually sees at the moment Save is clicked** — no
   reload-vs-DOM drift, on either page.
2. **`sort=='sort'` on `pfblockerng_category_edit.php` is completely unchanged**: same
   auto-order-by-header-then-state output, no manual-reorder UI rendered, byte-identical to
   `origin/devel`.
3. **`pfblockerng_category.php`'s non-order fields in the same Save** (per-row quick-edit
   fields serialized via `#iform`, plus the cron/log page-level settings) continue to save
   correctly alongside a reorder in the same request — today's bundling
   (`ids` + `postdata` in one AJAX call) must not regress.
4. **Hostile/stale posted order is rejected without corrupting or dropping rows** — the new
   `pfblockerng_category_edit.php` order-validation guard is at least as strict as #1129's
   retired guard: a posted order array referencing a row index that does not exist in the
   current row set, containing a duplicate, or missing an index present in the current row set,
   causes the reorder to be **skipped** (other posted fields still save normally) rather than
   silently dropping/duplicating a row.
5. **Auth/CSRF posture unchanged** — both pages already require an authenticated session +
   valid CSRF token on their POST/AJAX handlers; this ADR adds no new endpoint and does not
   relax either check (stated per CLAUDE.md "Security surface" design-completeness item — one
   line, no code change implied).
6. **`system/webgui/roworderdragging` is read-only from pfBlockerNG** — never written by either
   page.
7. **`geoip` rows behave identically to `ipv4`/`ipv6`/`dnsbl` rows for reorder purposes** on
   both pages (§1.4) — no `gtype`-specific carve-out is introduced by this ADR.

### Coverage matrix (Phase-1 re-derives from source; every row maps to a phase/test)

| Axis | Values | Notes |
| --- | --- | --- |
| Page | `pfblockerng_category.php`, `pfblockerng_category_edit.php` | different persistence entry points (§1.1) |
| `gtype` | `ipv4`, `ipv6`, `geoip`, `dnsbl` | §1.4 — no exclusions |
| `sort` (category_edit.php only) | `sort` (unchanged, Semantics #2), `no-sort` (new UI) | category.php has no such field |
| Reorder input | drag, anchor-click (checked-single-row), anchor-click (checked-multiple, straddling the anchor — mirrors the #1145 class of edge case, now client-side) | both must produce the same final order for the same visual outcome |
| `roworderdragging` | unset (both offered), set (anchor-click only) | read-only pfSense-core pref |
| Hostile posted order (category_edit.php) | missing index, duplicate index, foreign/stale index, non-array, empty | Semantics #4 |
| Concurrent non-order fields in the same Save | present (category.php `#iform` bundle; category_edit.php per-row `state-`/`format-`/`url-`/`header-`) | Semantics #3 |

### Explicitly kept / out of scope

- **The `sort`/`no-sort` Auto-Sort toggle itself** — kept, unchanged behaviour (§1.7).
- **`firewall_rules.php`'s separator-bar feature** (`save_separators()`, colored dividers
  between rules) — no pfBlockerNG equivalent exists; not introduced by this ADR.
- **A pfBlockerNG-owned equivalent of `roworderdragging`** — reuse the existing pfSense-core
  preference read-only; no new package-level preference is added.
- **ADR-54/55's proposed new pages** — out of scope; they may adopt the shared component later
  (§1.6), not a dependency either way.
- **`pfblockerng_category.php`'s existing `confirm()` dialog before AJAX save** — kept as-is;
  not part of this ADR's UX change (orthogonal friction point, not raised by the user).

## 3. Consequences

**Positive**

- Fixes issue #1147 (mobile/touch users cannot reorder categories) as a direct consequence of
  adding anchor-click, not a special-cased mobile fix.
- Deletes the entire `$pre`-majority-vote / anchor-placement server-side math class
  (`pfblockerng_category_edit.php:928-980`) — retires #1145's just-landed fix and #1149's open
  bug by removing the code they live in, not by patching either again. One fewer
  full-page-reload-per-click UX papercut the user explicitly flagged.
- No new persistence design risk: `pfblockerng_category.php`'s stable-id + order-array shape is
  already proven in production; this ADR extends its use, it does not invent a new one.

**Negative / risks**

- **Test migration cost, not just addition**: `tests/php/CategoryEditRowMoveTest.php` and
  `tests/smoke/ui/test_category_edit_row_move.py` are deleted, not merely extended — Phase 4
  must prove the new mechanism's coverage is a strict superset of what those files pinned
  (Semantics #4 / issue #1129's guard intent) before deleting them, or a real regression class
  quietly loses its test.
- **No isolated JS test harness in this repo** (confirmed absent) — the new client-side reorder
  component's correctness rides entirely on Playwright Tier-B browser tests (drag + anchor-click
  simulated in a real browser) rather than a fast unit test; slower feedback loop during
  development, acceptable given the existing `test_browser_category*.py` precedent already
  carries this cost for other JS-driven interactions on these same pages.
- **Two pages, one shared component**: a bug in the shared JS affects both pages at once
  (vs. today's two independently-broken mechanisms) — mitigated by Phase 1's oracles + Phase 3
  landing before Phase 4, so `category.php` (the lower-risk page, already correct server-side)
  proves the shared component before `category_edit.php` (which also changes its server-side
  save path) adopts it.

## 4. Requirements (acceptance)

1. For every §2 coverage-matrix row, the persisted row order after a drag-only, anchor-click-only,
   and mixed drag+anchor-click sequence followed by Save matches the DOM order visible at Save
   time — proven by Tier-B browser tests, not inferred from unit tests of the algorithm alone.
2. `sort=='sort'` output on `pfblockerng_category_edit.php` is byte-identical to `origin/devel`
   (Semantics #2) — the Phase-1 oracle stays green through the final phase.
3. `$Lmove`, `$Xmove`, and the majority-vote `$pre` logic (`grep -n
   '\$Lmove\|\$Xmove\|\$pre_votes\|\$post_votes'
   src/usr/local/www/pfblockerng/pfblockerng_category_edit.php`) are **deleted** — zero hits —
   by the final phase; `tests/php/CategoryEditRowMoveTest.php` is deleted with them.
4. The new `pfblockerng_category_edit.php` order-validation guard rejects every hostile-input
   row in §2 without dropping, duplicating, or corrupting any row (Semantics #4), pinned by
   tests mirroring #1129's original hostile-input coverage.
5. `system/webgui/roworderdragging` is read via `config_path_enabled()` only, never written, on
   both pages (Semantics #6).
6. Tier A (`ui_render`) coverage exists for both pages' new markup; Tier B (`ui_browser`,
   Playwright) coverage exercises real drag AND real anchor-click on both pages (CLAUDE.md Test
   coverage #4 — this is exactly a multi-step-flow + visual/structural change, Tier B is
   mandatory, not optional).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`; PFBL-01 `RequirePfbFilter` sniff stays green for any
  new `$_POST` handling in the order-validation guard (add the new capture site to
  `scopeFunctions` if the sniff's scope list requires it — verify in Phase 4).
- `www/` changes require Tier-A UI coverage always; Tier B is REQUIRED here (multi-step
  drag/click flow + structural change) — CLAUDE.md Test coverage #4.
- Config gateway: no `PfbConfig` registration needed (§1.4 — foreign-structure exemption
  already applies); do not add these fields to the registry.
- No new front-end dependency: jQuery + jQuery UI are already loaded platform-wide; do not add a
  JS package manager or bundler to satisfy this ADR.
- Behaviour-preserving phases pin current behaviour as an oracle (green before *and* after);
  behaviour-changing phases (4) get explicit red→green proof for their delta.

## 6. Action plan (phases — early ones are behaviour-preserving prep / de-risk)

### Phase 1 — Golden oracles for both pages' CURRENT reorder behaviour (behaviour-preserving; THE de-risk)

- Prompt: `01_Golden_Oracles.txt`
- Close the pre-existing gap (§1.5): add Tier-B (`ui_e2e`) coverage for
  `pfblockerng_category.php`'s `ids[]` AJAX order-save path (none exists today) across the §2
  `gtype` axis — capture the current persisted order as a golden oracle. Re-confirm
  `pfblockerng_category_edit.php`'s current `sort=='sort'` output and `no-sort`
  `$Lmove`/`$Xmove` behaviour (already covered by `CategoryEditRowMoveTest.php` +
  `test_category_edit_row_move.py`, post-#1145-fix) stays green as the "before" snapshot.
  Re-derive the §2 coverage matrix from a fresh grep of both files' current code (not from this
  ADR's memory) and record it in the phase handoff.
- Tests: the new `category.php` `ids[]` oracle (with a vacuity check: mutate one golden order →
  oracle goes red); confirm existing category_edit.php suites are green and unmodified.

### Phase 2 — Shared client-side reorder component (drag + anchor-click, staged, no server change)

- Prompt: `02_Shared_Reorder_Component.txt`
- Build the parameterised JS component (§2 Decision 1): drag via `jquery-ui sortable` (already
  used pattern, generalise `category.php`'s existing init options); anchor-click
  (checkbox-per-row + per-row anchor button, click = move-before, shift-click = move-after,
  re-implemented against pfBlockerNG's own row markup — NOT a call into pfSense's
  `reindex_rules()`/`fr_toggle()`, §1.2/§1.3). Both stage purely client-side (DOM move only) and
  flip a `dirty` flag that enables a Save button. Read `system/webgui/roworderdragging`
  server-side (PHP) to decide which affordance(s) to render — no client-side pref read needed.
  **Do not wire this into either page's save path yet** (Phase 3/4) — this phase's blast radius
  is PRODUCTION-DORMANT (the component exists and is unit-of-behaviour-testable via a scratch
  render, but nothing calls it from a live page).
- Tests: since no JS unit-test harness exists (§1.5, confirmed absent — do not introduce one
  for this alone), prove the component via a minimal Playwright smoke against a scratch/fixture
  HTML page (not yet either production page) exercising drag, anchor-click single-row, and
  anchor-click multi-row-straddling-the-target-scenarios purely client-side (assert final DOM
  order, no server call made).

### Phase 3 — Wire `pfblockerng_category.php` (behaviour-changing: adds anchor-click; drag path preserved)

- Prompt: `03_Category_List_Page.txt`
- Render the anchor-click UI alongside the existing drag init, gated by
  `roworderdragging` (§2 Decision 2). **No server-side change** — `ids[]` already accepts any
  POST order (§1.1). Delta budget: this phase may only add the anchor-click **input path**; the
  persisted-order **output** for a given final DOM state must be identical whether it was
  reached by drag or anchor-click (Semantics #1) — the existing drag-only Phase-1 oracle stays
  green unmodified; new tests cover the anchor-click path and mixed drag+anchor-click sequences.
- Tests: Tier A render check for the new markup; Tier B browser tests (drag — regression against
  Phase 1's oracle; anchor-click — new; mixed — new) across the §2 `gtype` axis;
  `roworderdragging` on/off rendering check.

### Phase 4 — Wire `pfblockerng_category_edit.php` + retire `$Lmove`/`$Xmove` (behaviour-changing; the delta-bearing phase)

- Prompt: `04_Category_Edit_Page.txt`
- Add the stable `pfb_er{r_id}`-style row id; render the shared component (drag + anchor-click,
  gated by `roworderdragging`) in place of the old checkbox+anchor-submit UI, **only** when
  `sort=='no-sort'` (Semantics #2 — `sort=='sort'` path untouched). Add the order-validation
  guard (Semantics #4) to the **existing** save handler; fold the posted order into
  `$rowdata[$rowid]['row']` before the per-field save loop persists it. **Delete** the
  `$Lmove`/`$Xmove`/`$pre`/`$pre_votes`/`$post_votes` reorder block (`:928-980`) and the
  `Location:`-redirect-per-move step entirely (Requirement 3). **Delete**
  `tests/php/CategoryEditRowMoveTest.php` and `tests/smoke/ui/test_category_edit_row_move.py`
  only after the new tests below are proven to be a strict superset of what they pinned
  (Consequences — test migration risk).
- Hostile-input rows (REQUIRED, from §2): missing posted index, duplicate posted index,
  foreign/stale posted index (references a row not in the current set), non-array order field,
  empty order field — each asserted to skip the reorder without dropping/duplicating/corrupting
  any row, while other posted fields in the same request still save (Semantics #3/#4).
- Tests: PHPUnit oracle for the new order-validation guard (mirrors #1129's original hostile-input
  discipline, new implementation); Tier A render check; Tier B browser tests (drag, anchor-click
  single-row, anchor-click multi-row straddling — the client-side analogue of #1145's edge case,
  now with no server-side placement math to get wrong) across the §2 `gtype` axis;
  `sort=='sort'` regression (Semantics #2, Phase-1 oracle stays green, byte-identical).

### Phase 5 — Docs, release-notes delta, DoD smoke rows

- Prompt: `05_Docs_Dod_Smoke.txt`
- Update `docs/misc/architecture-notes.md` if it documents either page's reorder mechanism
  (grep first — add a section if none exists, since this ADR retires a real code path future
  readers may look for); record the user-facing delta (mobile reorder now works on the category
  list; category-edit row reorder is now instant/staged instead of one-click-per-move) for
  release notes; ensure every §7 row below runs in the ADR-04 CE+Plus live-VM fan-out; update
  this ADR's Status.

## 7. Definition of done

- All phases landed (`RESULTS/01–05_Results.txt` + gate records); full PHPUnit + pytest green;
  PHPCS/PHPStan clean; the Phase-1 golden oracles green at the final phase (modulo the
  Requirement-2/Semantics-#2 byte-identity check, which must show ZERO delta, not a documented
  one — this ADR has no accepted output-changing delta table like ADR-62's, only an
  input-mechanism change with an identical-output contract).
- **Automated live-VM smoke rows (CE + Plus fan-out, ADR-04; CLAUDE.md "ADR acceptance" —
  automated, not a manual sign-off).** Each is a Tier-B (`ui_browser`) Playwright test:
  1. `pfblockerng_category.php`: drag-reorder two rows, click Save, reload, verify the new
     order persisted (regression, Phase 1 oracle).
  2. `pfblockerng_category.php`: anchor-click-reorder (single row, then multiple rows
     straddling the anchor target) with no drag interaction at all, click Save, reload, verify
     order (new — proves #1147 fixed without simulating touch/drag).
  3. `pfblockerng_category_edit.php`, `sort=='no-sort'`: drag AND anchor-click reorder member
     rows, click Save, reload, verify order; verify no full-page reload occurred per individual
     move (only on the final Save).
  4. `pfblockerng_category_edit.php`, `sort=='sort'`: verify no manual-reorder UI is rendered
     and the auto-sorted order is unchanged from `origin/devel` (Semantics #2 regression).
  5. `roworderdragging` set: verify only anchor-click renders (no drag handles) on both pages.
  6. A hostile posted order (stale/duplicate/missing index) on `pfblockerng_category_edit.php`'s
     save POST: verify the row set is unchanged/uncorrupted and other posted field edits in the
     same request still saved (Semantics #4, via direct POST simulation — mirrors how
     #1129/#1135's tests drove the retired mechanism).
- **Accepted** on the CE and Plus fan-out green (rows 1-6). No item is currently identified as
  genuinely out-of-CI.
- **Reject criteria (make the premise falsifiable):**
  1. Phase 2's shared component cannot express pfBlockerNG's per-row field-naming shape (§1.3)
     without reintroducing a `reindex_rules()`-style full-row-relabel-on-every-move mechanism →
     re-scope to a lighter-weight design (e.g. anchor-click only, no drag) rather than accept a
     new renumbering-bug surface class.
  2. Phase 4's order-validation guard cannot be made at least as strict as #1129's retired guard
     for every §2 hostile-input row → **do not delete** `CategoryEditRowMoveTest.php`/
     `test_category_edit_row_move.py`; keep the guard alongside the new mechanism until it can.
  3. Any Semantics-#2 (`sort=='sort'`) or Semantics-#1 (final-order-matches-DOM) test fails and
     cannot pass without weakening its assertion → REJECT the phase, do not weaken the test.
