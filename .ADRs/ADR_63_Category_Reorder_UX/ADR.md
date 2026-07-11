# ADR-63: Staged client-side reorder (drag + anchor-click) for category and category-row lists

- **Status:** **Proposed** (2026-07-10; amended same day after design review — see §1.8)
- **Date:** 2026-07-10
- **Branch:** `adr/63-category-reorder-ux` (off `devel`) / **Component(s):**
  `src/usr/local/www/pfblockerng/pfblockerng_category.php`,
  `src/usr/local/www/pfblockerng/pfblockerng_category_edit.php`,
  `src/usr/local/www/pfblockerng/pfBlockerNG.js`, a new shared client-side JS reorder helper,
  `tests/php/`, `tests/smoke/ui/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); vanilla JS + jQuery/jQuery-UI +
  `pfSenseHelpers.js` (all loaded by pfSense's webConfigurator `foot.inc` on every page —
  verified this session; no new front-end dependency).
- **Test suite:** `tests/php/` (PHPUnit), `tests/smoke/ui/` (Tier A `ui_render`, Tier B
  `ui_e2e`/`ui_browser` — Playwright, already the repo's Tier-B tool; no JS unit-test harness
  exists in this repo today, confirmed absent — no `package.json`/`jest.config*`).

All `file:line` anchors below are measured on `origin/devel` @ `655647e4` (2026-07-10) and drift
as `devel` advances — re-grep before relying on one.

---

## 1. Context — today

### 1.1 Two pages, two different reorder mechanisms, both incomplete

**`pfblockerng_category_edit.php`** (editing the member rows *inside* one category — e.g. the
feed URLs of one DNSBL list) has an `Auto-Sort Header field` select (`sort`/`no-sort`,
`:1457-1463`, options at `:413`): `sort` (default, "Enable auto-sort") auto-orders rows by
header then enabled/disabled state on every render (`:1096`) and shows **no** manual-reorder UI
at all. `no-sort` ("Disable auto-sort") is the **only** way to see or use manual reordering —
it renders a checkbox (`Lmove[{r_id}]`) + an anchor `<button type="submit" name="Xmove"
value="{r_id}">` per row (`:1132-1141`). Clicking that button is a **full-page form submit**:
it lands in the `isset($Lmove) && isset($Xmove) && ...` reorder block (`:928-983`) which
computes a before/after `$pre` placement, rewrites `$rowdata[$rowid]['row']` server-side,
`config_set_path()` + `write_config()`, then `header("Location: ...")` + `exit` — **one full
page reload and one config write per single-row move**. Two known bugs live in this exact
block, and **both are retired by deletion, not re-fixed, by this ADR**:

- **Issue #1145** (multi-row `$pre` placement vote loss): **the bug is LIVE on `devel`.**
  PR #1150 (the fix, introducing `$pre_votes`/`$post_votes`) was **closed unmerged** and #1145
  labelled `SUPERSEDED` — superseded by this ADR. Those symbols do **not** exist on `devel`;
  the shipped code is the pre-fix last-checked-row-wins `$pre` (`:944-947`).
- **Issue #1149** (loose `!=` drops the anchor row when `Xmove` is literally `0`): closed,
  folded into this ADR.

There is **no drag** affordance on this page at all today, and **no touch-capable** reorder.
A related flag, `$disable_move` (`:80`, `:199`, `:938`, exported to JS at `:1759` and consumed
by `pfBlockerNG.js:148-158`), disables the move controls on a brand-new unsaved alias — needed
only because the old mechanism moves rows in the **persisted** config, which a new alias does
not have yet. It retires with the mechanism (client-side staging works on unsaved rows).

**`pfblockerng_category.php`** (the categories/lists themselves, one row per category) has
**no** `sort`/`no-sort` toggle — rows are always manually orderable via jQuery UI `.sortable()`
(`:687`, mouse-only: `cursor: 'move'`, `distance: 10`, no `update:` auto-save callback). This
page's persistence is already staged: dragging only moves `<tr class="sortable"
id="pfb_r{r_id}">` (`:426`) elements in the DOM. Only when the user clicks `#btnsave` does
`save_new_changes()` (`:640-684`) run: `$('#pfb_table table tbody').sortable('serialize',
{key:"ids[]"})` reads the `pfb_rN` DOM ids in **current visual order** into
`ids[]=r3&ids[]=r0&…`, bundled with `$('#iform').serialize()` into **one** AJAX POST
(`act=update`). Server-side (`:277-306`): each `ids[]` entry is parsed back to its original
`$rowid`, `$new_rows[$key] = $rowdata[$rowid]` rebuilds the array in the posted order, one
write. It needs only a non-drag input method: no anchor-click affordance exists, so a
touch/mobile user cannot reorder at all (**issue #1147**, closed as superseded — implemented
by this ADR). Note the caveat in §1.8: this handler validates each `ids[]` entry only as
numeric, not the order as a permutation.

### 1.2 pfSense core's `firewall_rules.php` — the referenced prior art

Verified this session at `pfsense/pfsense@master` (fetched `firewall_rules.php` +
`js/pfSenseHelpers.js`; repeatable machinery additionally pinned at `37d60e23`, 2025-01-07,
pre-CE-2.8 — identical):

- **Identity**: each rule row's checkbox is `name="rule[]" value="<?=$filteri;?>"` (`:513`) —
  the value is the rule's **original PHP array index**, never rewritten by any move.
- **Anchor-click** (`:1127-1152`): pure client-side `insertBefore`/`insertAfter` of the
  checked rows around the clicked row (shift-click = insert-after); no server round-trip.
- **Drag** (`:1183-1190`, rendered only unless `system/webgui/roworderdragging` is set):
  jQuery UI `.sortable()`; the `update:` callback stages only.
- Both paths call `reindex_rules()` — **cosmetic only**: it renumbers the positional
  `fr{N}`/`frc{N}` ids and onclick handlers, never the identity value, never any named field —
  and enable a **dedicated** order-save button `#order-store` (rendered `disabled`, `:997`).
  Save posts the `rule[]` checkboxes in DOM order → one `set_filter_rules_order()` (`:225`).
- **Rules are added/deleted via separate pages (full round-trips)** — `firewall_rules.php`
  never faces row add/delete while an unsaved reorder is staged. This is the decisive
  difference from `pfblockerng_category_edit.php` (§1.3).
- `system/webgui/roworderdragging` is a pfSense-core, site-wide preference (written by
  `system.php:328`, read via `config_path_enabled()`); when set, only anchor-click is offered.
  Reused here read-only.
- `reindex_rules()`/`fr_toggle()`/`save_separators()` are hard-coded to `firewall_rules.php`'s
  own DOM conventions — not callable from pfBlockerNG. Only the UX pattern is reusable. The
  **repeatable-row machinery** in the same file is a different story — see §1.3.

So `firewall_rules.php` ≡ `pfblockerng_category.php` in shape (stable identity + one order
read at Save + staged client-side); our page is merely missing the non-drag input method.
It is **not** a precedent for `pfblockerng_category_edit.php`.

### 1.3 Why the order-array design does NOT fit category_edit — and what does

`pfblockerng_category_edit.php`'s rows are **not** table rows: each is a pfSense `Form_Group`
with class `repeatable` (`:1130`) — a bootstrap form-group div — with core-driven client-side
**add** (`addrow`, `:1341`) and **delete** (`deleterow{N}`, `:1226`) buttons. pfSense's global
`pfSenseHelpers.js` (loaded on every page via `foot.inc`) auto-binds them:

- `delete_row()` removes the group **client-side** and calls `renumber()`, which walks all
  `.repeatable` groups **in current DOM order** and rewrites every contained
  input/select/button `name`/`id` to sequential `0..N-1` (trailing-digit regex).
- `add_row()` clones the **visually-last** group and bumps its index by +1.

The page's save handler is **positional by field name**: each posted `state-{N}`/`url-{N}`/…
is written to `config/.../row/{N}/{field}` (`:822-839`), then every config row index absent
from the POST is pruned (`:842-846`). Whatever the field names say at POST time **is** the
persisted row set and order — that is how client-side delete already persists today.

An earlier draft of this ADR proposed the `category.php` shape here (stable per-row id + an
order array read at Save + a server-side permutation guard). Probing the repeatable machinery
killed it: with a reorder staged in the DOM, `add_row()` clones the *visually*-last group whose
field index is no longer the maximum, producing a **field-name collision** (two `state-2` sets
in one POST — one row's data silently clobbered), and `delete_row()`'s `renumber()` rewrites
field names by visual order while the stable ids keep original ids, so the order array and the
field keys diverge. Defending the order-array design would need a validation base switched to
the POSTed key set, a scalar order field (the `:502-513` array-reject loop blanks non-scalar
POST fields), and a bidirectional lock between staged reorder and add/delete — three patches
fighting machinery the platform already ships.

**Chosen instead (Option A): make reorder use the same channel delete already uses.** After
every staged move the component calls core's `renumber()` — field names are then always
positional, visual order and name order never diverge, `add_row()`'s clone-last is always the
max index, and the **existing, byte-unchanged** per-field save loop persists the staged order
on the page's normal Save. No order field, no new guard, no new `$_POST` surface, no stable
row ids needed. The server diff on this page is **pure deletion** of the old mechanism.

### 1.4 Config / gateway facts

- Both pages' row lists (`installedpackages/{$conf_type}/config/{$rowid}/row`) and the `sort`
  field live under the per-category-type config tree, not the top-level
  `installedpackages/pfblockerng*` scalars `PfbConfig` (ADR-29) registers — already a
  documented "foreign structure" exemption. No `PfbConfig` registration changes needed.
- `system/webgui/roworderdragging` is pfSense-core namespace; this ADR only **reads** it
  (`config_path_enabled()`), never writes it.
- `geoip` rows are **not** `gtype`-excluded from either page's row-list/reorder code paths
  (only excluded from the generic per-row-field save loop on `category.php:261`, an unrelated
  branch) — the coverage matrix (§2) includes `geoip` alongside `ipv4`/`ipv6`/`dnsbl`.
  **Phase-1 correction (2026-07-11):** on `category.php` the `ids[]` **order-persist sink is
  a silent no-op for GeoIP** — `$rowdata_path` is assigned only in the non-GeoIP branch
  (`:117-118`), the persist is guarded `isset($rowdata_path)` (`:302`), and GeoIP rows are
  rebuilt from `$pfb['continents']` on every request. Pre-existing (drag+Save already
  doesn't persist today), pinned by the Phase-1 oracle
  `test_category_ids_order_save_geoip_is_silent_no_op`, tracked as **issue #1201**. This ADR
  keeps the handler byte-identical, so the new anchor-click UI inherits the same no-op;
  Semantics #7 reads accordingly (identical *UI/code-path* behaviour; order persistence on
  `category.php` stays the pinned no-op). Also: `category_edit.php`'s gtype switch has **no
  `geoip` case** (`ipv4`/`ipv6`/`dnsbl`-default; `category.php` renders no edit link for
  geoip rows), so the §2 gtype axis is `{ipv4, ipv6, dnsbl}` wherever it crosses
  `category_edit.php`.

### 1.5 Existing test coverage this ADR must reconcile

- `tests/php/CategoryEditRowMoveTest.php` — pure-array-transform oracle for the
  `$Lmove`/`$Xmove` server-side placement algorithm. **9 tests on `devel`** (the 15-test count
  of PR #1150 never landed — §1.1). Its bootstrap **eval-extracts the reorder block from the
  live source by regex and throws if the block is absent** — so the block deletion and this
  file's deletion must land in the **same commit** (Phase 4), or the whole PHP suite errors.
  Its pinned intent that must outlive it: issue #1129 — a stale/hostile move request must
  never silently drop or duplicate a row. Its placement math is intentionally retired
  (including the live #1145 bug) — new coverage is a superset of the *data-integrity intent*,
  not of the deleted algorithm's outputs.
- `tests/php/CategoryEditPostGuardTest.php` — **stays**, but its R15 test pins the `Lmove`
  array-field exemption in the `:502-513` array-reject loop. With `Lmove` deleted, no
  legitimate array field remains on the page: Phase 4 removes the exemption (restoring full
  #1106 protection) and updates R15 test-first (red on the old code, green after).
- `tests/smoke/ui/test_category_edit_row_move.py` — 3 Tier-B (`ui_e2e`) tests driving the raw
  full-page POST that hits the `$Lmove`/`$Xmove` block (issues #1129/#1135). Deleted with the
  mechanism in Phase 4, same superset-of-intent discipline.
- `tests/smoke/ui/test_category.py` — mentions `ids[]` in its module docstring (`:12`, `:22`)
  but contains **zero test coverage** of the `ids[]` AJAX order-save path (no test posts an
  order). A pre-existing gap closed in Phase 1 (an oracle for today's behaviour is a
  prerequisite for proving the new UI doesn't change it).
- `tests/smoke/ui/test_browser_category_edit.py`, `tests/smoke/ui/test_browser_category.py` —
  Playwright Tier-B (`ui_browser`) harnesses already exist for both pages; reuse them. Neither
  contains any drag/mouse-protocol precedent — Phase 2 establishes it (jQuery UI `.sortable()`
  has `distance: 10`, so use `mouse.down`/`mouse.move(…, steps≥2)`/`mouse.up`, not
  `page.drag_and_drop()`).

### 1.6 Cross-ADR interaction

Grepped every `.ADRs/*/ADR.md` for `sortable`/`Lmove`/`Xmove`/`row-move`/`reorder`/`drag`:
**ADR-54** and **ADR-55** (both Proposed) each mention a "sortable table" once, as a generic
UI-pattern reference for a *new* page they propose — no overlap with either page here. If they
land after this one, their new pages are natural (not mandatory) consumers of the shared
component.

### 1.7 Explicit user decisions

1. **The `sort`/`no-sort` (Auto-Sort) toggle is kept exactly as today** — "auto-ordering is
   still something we want to support. Some people don't care." This ADR only replaces the
   **manual** (`no-sort`) reorder UX; `sort=='sort'` behaviour (auto-order by header/state, no
   manual UI shown) must stay byte-identical (Semantics #2).
2. **Option A chosen for category_edit** (2026-07-10 design review): renumber-on-move reusing
   core `renumber()`, including the small DOM pass refreshing the visible row-number gutter
   (`str_pad($r_id +1 …)`, `:1140`) after each staged move — "Option A with the small DOM pass
   to update the little number sounds great."

### 1.8 Design-review amendments (2026-07-10)

The original draft was reviewed against the live tree, pfSense core JS, and GitHub state
before implementation; this revision supersedes it. Substantive corrections beyond §1.3:

- PR #1150 was closed unmerged (§1.1) — all "post-#1145-fix" premises, the 15-test count, and
  the phantom `$pre_votes`/`$post_votes` grep symbols are gone from this text.
- **Pre-existing, out of scope, tracked as issue #1152**: `pfblockerng_category.php`'s `ids[]`
  handler accepts a hostile/stale order (missing index drops a row, duplicate persists a row
  twice, foreign rowid persists a null row). This ADR leaves that handler byte-unchanged;
  Phase 1's oracle pins only well-formed-order behaviour.
- `sortable('serialize')` (`:645`) throws if `.sortable()` was never initialised — the
  anchor-only (`roworderdragging` set) mode therefore **requires** replacing that call with a
  sortable-independent DOM order read (§2 Decision 3), and every `roworderdragging`-set test
  row exercises a **Save**, not just rendering.
- Neither page has a dedicated order-save button (`firewall_rules.php`'s `#order-store` is) —
  both Save buttons are general-purpose, so the component must **never** gate/disable them.

---

## 2. Decision

**Layer pfSense-core's UX pattern (drag + anchor-click, staged client-side, one explicit Save)
onto each page's own persistence shape: `pfblockerng_category.php`'s existing stable-id +
`ids[]`-at-Save design, and `pfblockerng_category_edit.php`'s existing positional-field-name
design driven by core's own repeatable-row machinery (`renumber()` on every staged move).**

1. **New shared client-side reorder component** (one JS module, parameterised by container
   selector, **row selector** — `tr.sortable` on one page, `.form-group.repeatable` on the
   other — and an `onAfterMove` callback) implementing the shared **input UX** only:
   drag (`jquery-ui sortable`, already used) **and** anchor-click (checkbox-per-row + a
   per-row anchor button; click = move checked rows before it, shift-click = after — mirrors
   `firewall_rules.php`'s UX, re-implemented against pfBlockerNG's own row markup). Anchor
   buttons are `type="button"` (the old category_edit anchor was deliberately
   `type="submit"`; copying that markup would submit the form per click). All event handling
   is **delegated** (container-level), and any per-row control the component adds carries a
   **trailing-digit-suffixed** name/id so core `renumber()` rewrites it consistently. The
   component also exposes a sortable-independent order-read helper (current DOM order of row
   ids, `ids[]=rN&…` wire format). It **never** touches any other per-row named field, and it
   **never** disables or gates any existing Save button (§1.8).
2. **Honour `system/webgui/roworderdragging`** (read-only, read server-side via
   `config_path_enabled()`, passed to the page JS as a boolean): when set, render anchor-click
   only (no `.sortable()` init); default renders both, matching core pages.
3. **`pfblockerng_category.php`**: ADD the anchor-click affordance next to the existing drag,
   and **replace** the `sortable('serialize')` call in `save_new_changes()` with the
   component's order-read helper (same `ids[]` wire format — the server cannot tell the
   difference), so Save works whether drag was initialised or not (§1.8). **No server-side
   change** (`:277-306` byte-identical; #1152 stays open, untouched).
4. **`pfblockerng_category_edit.php`**: retire the `$Lmove`/`$Xmove` mechanism **entirely** —
   the reorder block (`:928-983`), the POST capture (`:156-158`), the checkbox+anchor-submit
   UI (`:1132-1141`), the `Lmove` exemption in the array-reject loop (`:505-508`), the
   `$disable_move` flag (`:80`, `:199`, `:938`, `:1759`), and the `pfBlockerNG.js:148-158`
   disable block. In the `sort=='no-sort'` branch, render the shared component's
   checkbox+anchor (plus drag, gated by `roworderdragging`); its `onAfterMove` calls core
   **`renumber()`** (already loaded and already load-bearing on this page for delete) and
   refreshes the visible row-number gutter. Persistence is the **existing, byte-unchanged**
   save handler: positional field names written at `:822-839`, absent indices pruned at
   `:842-846`. **No order field, no new guard, no new `$_POST` parsing, no stable row ids.**
   Staged reorder composes with client-side add/delete by construction (§1.3).
5. **`sort`/`no-sort` unchanged** (§1.7): `sort=='sort'` shows no manual UI, exactly as today;
   `sort=='no-sort'` gets the new drag+anchor-click UI in place of the old
   checkbox+anchor-submit UI.

### Semantics that MUST be preserved (the contract — pin with tests before any swap)

1. **Final persisted row order, for any sequence of drag/anchor-click operations followed by
   Save, matches exactly what the user visually sees at the moment Save is clicked** — on
   either page. On category_edit this is explicitly **not** bug-compatible with the retired
   server-side placement math (the live #1145 bug produced orders diverging from the visual
   intent for multi-row straddles; the new mechanism has no placement math to get wrong).
2. **`sort=='sort'` on `pfblockerng_category_edit.php` is completely unchanged**: same
   auto-order-by-header-then-state output, no manual-reorder UI rendered, byte-identical to
   `origin/devel`.
3. **Same-Save composition keeps working.** category.php: the `ids` + `postdata` bundle (order
   plus every `#iform` field) in one AJAX call must not regress. category_edit: a Save that
   combines a staged reorder with per-row field edits AND client-side row add/delete applies
   all of them — no row lost, duplicated, or corrupted (issue #1129's data-integrity intent,
   now guaranteed structurally: names are always positional, so the POST is always a
   consistent snapshot of the visual state).
4. **category_edit's POST surface is byte-unchanged**: the save handler gains no new fields
   and no new parsing; the hostile-input surface is not enlarged. The `Lmove` array-field
   exemption is retired with its field, restoring the full #1106 array-reject guard (no
   legitimate array field remains on the page).
5. **Auth/CSRF posture unchanged** — both pages already require an authenticated session +
   valid CSRF token on their POST/AJAX handlers; this ADR adds no new endpoint and does not
   relax either check.
6. **`system/webgui/roworderdragging` is read-only from pfBlockerNG** — never written by
   either page.
7. **`geoip` rows behave identically to `ipv4`/`ipv6`/`dnsbl` rows for reorder purposes** on
   both pages (§1.4) — no `gtype`-specific carve-out is introduced by this ADR. *Phase-1
   qualification:* identical at the UI/code-path level; on `category.php` the GeoIP
   order-persist sink is a pre-existing silent no-op (pinned, issue #1201 — §1.4) and stays
   byte-unchanged, and `category_edit.php` has no `geoip` gtype at all (§1.4).

### Coverage matrix (Phase-1 re-derives from source; every row maps to a phase/test)

| Axis | Values | Notes |
| --- | --- | --- |
| Page | `pfblockerng_category.php`, `pfblockerng_category_edit.php` | different persistence shapes (§1.3) |
| `gtype` | `ipv4`, `ipv6`, `geoip`, `dnsbl` | §1.4 — no exclusions |
| `sort` (category_edit only) | `sort` (unchanged, Semantics #2), `no-sort` (new UI) | category.php has no such field |
| Reorder input | drag, anchor-click (single row), anchor-click (multiple rows straddling the anchor), mixed drag+anchor in one session | all must persist the visual order |
| `roworderdragging` | unset (both offered), set (anchor-click only) | the SET case includes a full reorder + **Save** on both pages (§1.8 serialize trap), not a render check alone |
| In-session row mutations composed with a staged reorder (category_edit only) | none, add, delete, add+delete | the §1.3 collision class; category.php has no client-side add/delete (server round-trips) |
| Concurrent non-order fields in the same Save | present (category.php `#iform` bundle; category_edit per-row `state-`/`format-`/`url-`/`header-` edits) | Semantics #3 |

### Explicitly kept / out of scope

- **The `sort`/`no-sort` Auto-Sort toggle itself** — kept, unchanged behaviour (§1.7).
- **`firewall_rules.php`'s separator-bar feature** — no pfBlockerNG equivalent; not introduced.
- **A pfBlockerNG-owned equivalent of `roworderdragging`** — reuse the core preference
  read-only; no new package-level preference.
- **ADR-54/55's proposed new pages** — out of scope; they may adopt the shared component later.
- **`pfblockerng_category.php`'s existing `confirm()` dialog before AJAX save** — kept as-is.
- **`pfblockerng_category.php`'s `ids[]` hostile-order gap** — pre-existing, tracked as
  **issue #1152**; the handler stays byte-unchanged here.
- **Help-text column labels** (`Format`/`State`/`Source`, rendered on the visually-last row at
  render time) may float mid-list after staged moves — accepted cosmetic quirk (the old
  mechanism re-rendered per move; the new one re-renders on Save). The row-number gutter, by
  contrast, IS refreshed per move (§1.7 decision 2).

## 3. Consequences

**Positive**

- Fixes issue #1147 (mobile/touch users cannot reorder categories) as a direct consequence of
  adding anchor-click, not a special-cased mobile fix.
- Deletes the entire server-side placement-math class (`:928-983` + its `$disable_move`
  scaffolding) — retiring the **live** #1145 bug and #1149 by removing the code they live in.
  One fewer full-page-reload-per-click UX papercut.
- category_edit's server diff is **pure deletion**: no new POST field, no new guard, no new
  hostile surface, and the #1106 array-reject guard gets stricter (exemption retired).
- Staged reorder, client-side add, and client-side delete compose by construction on
  category_edit — the class of bug the old design would have had to lock its way around.

**Negative / risks**

- **Reliance on core `renumber()`'s contract** (trailing-digit rename of input/select/button
  in DOM order). Shared fate, not new fate: the page's delete button already depends on
  exactly this, in production, today. The contract is probed in Phase 2's fixture — including
  composition with `add_row()`/`delete_row()` — **before** any production page changes
  (reject criterion 1).
- **Test migration, not just addition**: `CategoryEditRowMoveTest.php` and
  `test_category_edit_row_move.py` are deleted (same commit as the block, §1.5); their #1129
  data-integrity intent must be demonstrably covered by the new composition tests first.
- **No isolated JS test harness** — the component's correctness rides on Playwright Tier-B
  tests; slower feedback, precedented by the existing `test_browser_category*.py` harnesses.
- **Two persistence shapes remain** (ids[]-at-Save vs positional names). Deliberate: they are
  each page's existing production shape; the component shares only the input UX. Documented
  in architecture-notes (Phase 5).

## 4. Requirements (acceptance)

1. For every §2 coverage-matrix row, the persisted row order after a drag-only,
   anchor-click-only, and mixed sequence followed by Save matches the DOM order visible at
   Save time — proven by Tier-B browser tests.
2. `sort=='sort'` output on `pfblockerng_category_edit.php` is byte-identical to
   `origin/devel` (Semantics #2) — the Phase-1 oracle stays green through the final phase.
3. The old mechanism is **fully retired**: `grep -n '\$Lmove\|\$Xmove\|\$disable_move\|\$pre\b'
   src/usr/local/www/pfblockerng/pfblockerng_category_edit.php` returns zero hits, AND the
   sweep over **production/live code** (`git grep -n 'Lmove\|Xmove\|disable_move' -- 'src/'`,
   the mechanically-enforced retired-token scope of `src/`+`scripts/`+`.github/workflows/`)
   returns zero hits — retiring `pfBlockerNG.js`'s `disable_move` block and every production
   reference (the #1047 straggler class). **Phase-4 qualification (2026-07-11):** the tree-wide
   `git grep … -- ':!.ADRs'` is NOT literally zero, and correctly so — the surviving hits are
   **retirement-ENFORCING tests**, the opposite of stragglers: `CategoryEditPostGuardTest`'s
   R15 pins that an array `Lmove` field is now *rejected* (must name the field to prove it),
   and `test_render_smoke.py` asserts `name="Lmove"`/`name="Xmove"` are *absent* from the
   rendered page (must name the token to prove its removal). Removing those would delete the
   retirement proof. The zero-hit requirement therefore binds production code (0 `src/` hits,
   verified); absence-asserting/rejection tests naming the retired token are expected and
   required. `CategoryEditRowMoveTest.php` and `test_category_edit_row_move.py` are deleted in
   the same commit; `CategoryEditPostGuardTest.php`'s R15 is updated test-first (§1.5).
4. On category_edit, a staged reorder composed with client-side add and delete in one session
   persists exactly the visual state at Save — no row lost, duplicated, or corrupted
   (Semantics #3), across the §2 mutation axis.
5. `system/webgui/roworderdragging` is read via `config_path_enabled()` only, never written;
   with it SET, a full anchor-click reorder + Save round-trip succeeds on both pages
   (Requirement includes the §1.8 serialize trap).
6. Tier A (`ui_render`) coverage exists for both pages' new markup; Tier B (`ui_browser`,
   Playwright) coverage exercises real drag AND real anchor-click on both pages (CLAUDE.md
   Test coverage #4 — multi-step flow + structural change, Tier B mandatory).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`. Phase 4 introduces **no new `$_POST` handling**
  (Semantics #4), so the PFBL-01 `RequirePfbFilter` sniff scope list is untouched — verify,
  don't extend.
- `www/` changes require Tier-A UI coverage always; Tier B is REQUIRED here — CLAUDE.md Test
  coverage #4.
- Config gateway: no `PfbConfig` registration needed (§1.4); do not add these fields.
- No new front-end dependency: jQuery + jQuery UI + `pfSenseHelpers.js` are already loaded
  platform-wide; no package manager, bundler, or JS test framework.
- Behaviour-preserving phases pin current behaviour as an oracle (green before *and* after);
  the behaviour-changing phases (3, 4) get explicit red→green proof for their delta.
- Smoke tests that set `roworderdragging` on the shared VM must restore the prior value in a
  fixture teardown that fails loudly if the restore doesn't take (CLAUDE.md self-encapsulation
  rule) — a leaked SET breaks every later drag test.

## 6. Action plan (phases — early ones are behaviour-preserving prep / de-risk)

### Phase 1 — Golden oracles for both pages' CURRENT reorder behaviour (behaviour-preserving; THE de-risk)

- Prompt: `01_Golden_Oracles.txt`
- Close the pre-existing gap (§1.5): Tier-B coverage for `pfblockerng_category.php`'s `ids[]`
  AJAX order-save path (well-formed orders only — §1.8/#1152) across the §2 `gtype` axis.
  Reconfirm (unmodified) the existing category_edit suites green as the "before" tombstone —
  noting they pin the **live** #1145 behaviour (§1.1), which dies with the mechanism. Pin the
  `sort=='sort'` output oracle (Semantics #2's baseline). Re-derive the §2 coverage matrix
  from a fresh grep.

### Phase 2 — Shared client-side reorder component (drag + anchor-click, staged, dormant)

- Prompt: `02_Shared_Reorder_Component.txt`
- Build the component (§2 Decision 1) and prove it on a fixture page served from the live VM
  (using the box's own jQuery/jQuery-UI/`pfSenseHelpers.js`), including the **renumber
  composition proof**: staged move + core `add_row()` + core `delete_row()` on
  digit-suffixed fields → names stay positional, no collision, values intact (reject
  criterion 1's probe). Production pages untouched (PRODUCTION-DORMANT).

### Phase 3 — Wire `pfblockerng_category.php` (behaviour-changing: adds anchor-click; drag path preserved)

- Prompt: `03_Category_List_Page.txt`
- Anchor-click UI alongside the existing drag, gated by `roworderdragging`; replace
  `sortable('serialize')` with the component's order-read (§2 Decision 3); `#btnsave` never
  gated. Server-side `ids[]` handler byte-identical. Phase-1 drag oracle stays green
  unmodified; new tests cover anchor-click, mixed, and reorder+Save under
  `roworderdragging` set.

### Phase 4 — Wire `pfblockerng_category_edit.php` + retire `$Lmove`/`$Xmove` (behaviour-changing; the delta-bearing phase)

- Prompt: `04_Category_Edit_Page.txt`
- §2 Decision 4 in full: component in the `no-sort` branch (`onAfterMove` = `renumber()` +
  gutter refresh); delete the mechanism (block, capture, UI, exemption, `$disable_move`,
  `pfBlockerNG.js` disable block); update `CategoryEditPostGuardTest` R15 test-first; delete
  the two old test files in the same commit after the superset-of-intent mapping; tree-wide
  retirement sweep (Requirement 3). Tier-B composition coverage (Requirement 4).

### Phase 5 — Docs, release-notes delta, DoD smoke rows

- Prompt: `05_Docs_Dod_Smoke.txt`
- architecture-notes section (name the retired symbols `$Lmove`/`$Xmove`/`$pre`/
  `$disable_move` so a future grep finds the note, and document the two persistence shapes +
  renumber-on-move); release-notes delta; confirm all §7 rows run under one `-k` filter in the
  ADR-04 CE+Plus fan-out; flip Status on green evidence.

## 7. Definition of done

- All phases landed (`RESULTS/01–05_Results.txt` + gate records); full PHPUnit + pytest green;
  PHPCS/PHPStan clean; the Phase-1 golden oracles green at the final phase (the
  Requirement-2/Semantics-#2 byte-identity check shows ZERO delta; the category_edit
  Lmove-path oracles are deleted with their mechanism in Phase 4, per §1.5).
- **Automated live-VM smoke rows (CE + Plus fan-out, ADR-04; CLAUDE.md "ADR acceptance").**
  Each is a Tier-B (`ui_browser`) Playwright test:
  1. `pfblockerng_category.php`: drag-reorder two rows, Save, reload, verify the new order
     persisted (regression, Phase 1 oracle).
  2. `pfblockerng_category.php`: anchor-click-reorder (single row, then multiple rows
     straddling the anchor target) with no drag interaction, Save, reload, verify order
     (proves #1147 fixed without simulating touch/drag).
  3. `pfblockerng_category_edit.php`, `sort=='no-sort'`: drag AND anchor-click reorder member
     rows, Save, reload, verify order; verify no full-page reload occurred per individual
     move (only on the final Save).
  4. `pfblockerng_category_edit.php`, `sort=='no-sort'`: staged reorder + core add-row +
     core delete-row composed in ONE session, then Save: persisted rows and order match the
     visual state exactly — no row lost or duplicated (the §1.3 collision class).
  5. `pfblockerng_category_edit.php`, `sort=='sort'`: no manual-reorder UI rendered and the
     auto-sorted order unchanged from `origin/devel` (Semantics #2 regression).
  6. `roworderdragging` set (restored on teardown, §5): only anchor-click renders on both
     pages AND an anchor-click reorder + Save round-trip persists correctly on both pages
     (§1.8 serialize trap).
- **Accepted** on the CE and Plus fan-out green (rows 1-6). No item is currently identified
  as genuinely out-of-CI.
- **Reject criteria (make the premise falsifiable):**
  1. Phase 2's fixture proof shows core `renumber()` cannot keep our field shape consistent
     under move+add+delete composition (collision, misnumbering, or value drift) → STOP; fall
     back to the order-array design hardened with a bidirectional staged-reorder↔add/delete
     lock (the rejected Option B, documented in §1.3) — never improvise a third mechanism
     mid-phase.
  2. Any Semantics-#2 (`sort=='sort'`) or Semantics-#1 (final-order-matches-DOM) test fails
     and cannot pass without weakening its assertion → REJECT the phase, do not weaken the
     test.
