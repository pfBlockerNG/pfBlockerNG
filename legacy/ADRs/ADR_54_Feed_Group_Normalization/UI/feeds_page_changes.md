# ADR-54 UI reference — `pfblockerng_feeds.php` + `pfblockerng_category.php` splice instructions

Companion to `pfblockerng_feed_edit.php` and `category_edit_member_feeds.inc.php` in this
directory. Phase 4 applies these; divergences go in the phase handoff. Line anchors are
2026-07-04 — resolve fresh.

## 1. `pfblockerng_feeds.php` (the ADR-16 layout survives)

### 1.1 Drop the Feed Settings collapsible section

The `Form_Section('Feed Settings', …)` (`:639`) and its save loop (`:86-160`) are removed:
the `pfblockerngglobal/feed_<alias>` rename/merge and `feed_alt_<header>` selection layers
are absorbed by real Feed Group names and per-feed `url` (migration, ADR §2.4 step 3). The
**alternate-URL radios stay** in the predefined table, but their save now writes the FEED
entity's `url` (via the Phase-2 helpers) instead of a `pfblockerngglobal` key — same POST
shape, new target. The type-scoped save contract (hidden `type` field, ADR-16 A3) is
preserved for what remains.

### 1.2 Predefined table columns

Rendered by `pfb_feeds_render_predefined_type()` (`:290+`). Columns become:

```text
Category | (+ group) | Feed Group(s) | Feed/Website | Header/URL | (icons / + feed)
```

- **Feed Group(s)** cell (replaces the single `Alias/Group` name): for an installed feed,
  comma-separated links to each containing group's editor
  (`pfblockerng_category_edit.php?type={family}&rowid={N}`), `<p title>` ellipsis at 20
  chars (the Category page Name-cell idiom). For a not-installed catalog feed: the catalog
  category name, plain (what the group would be named on import).
- Membership is **display-only** here — edited on the group editor or the feed editor.

### 1.3 Legend + icons

- `fa-regular fa-circle-check` legend text (`:710-711`) becomes: `Installed in the listed
  Feed Group(s)` — M:N is first-class, not an anomaly.
- Per-feed `+` (`act=add`) and per-group `+` (`act=addgroup`) deep links unchanged in shape;
  `category_edit` now pre-selects the Member-Feeds multi-select (and pre-creates FEED
  entities on save) instead of pre-filling row grids.

### 1.4 Custom feeds table

- One row per FEED with no catalog match; the row gains an edit pencil →
  `pfblockerng_feed_edit.php?fid={family}:{header}`.
- **Orphan feeds** (state Enabled, zero group memberships) render the header cell with
  `text-danger` + `title="Feed is not a member of any Feed Group"`.

## 2. `pfblockerng_category.php` (Feed Group list)

Same URLs/sub-tabs/panel/drag-order/AJAX quick-edit. Column changes only:

```text
Name | Description | Default Action | Frequency | Logging[/Blocking Mode] | Feeds | Policies | (buttons)
```

- **Default Action** = the existing Action quick-edit select (`action-{rowid}`), retitled;
  add `title` attr: `Applies to all hosts. Client Group policies can override per group.`
  The dnsbl vocabulary gains `policy_only` (label `Unbound (Policy-only)`) in the
  `$list_array` (`:456-458`) **and** the AJAX validator's `$action_values` (`:169-190`).
- **Feeds** = member count (from the group's member list), linking to the group editor.
- **Policies** = count of Client-Group bindings referencing this group, linking to
  `/pfblockerng/pfblockerng_group_policy.php`; renders `&mdash;` when 0 **or when the
  ADR-55 helper is absent** — guard with `function_exists('pfb_cg_rule_counts')` so ADR-54
  can land before ADR-55.
- GeoIP tab untouched (ADR-57).

## 3. Tier A markers

- Feeds page: existing marker unchanged.
- Category page: existing marker unchanged (columns are additive).
- `pfblockerng_feed_edit.php` marker: the `Save Feed` form title. Register in the UI
  PAGE_TABLE.

## 4. Ports lockstep

`pfblockerng_feed_edit.php` needs pkg-plist + `do-install` entries in all three ports;
verify with `build-pkg-portable.py --dry-run`.
