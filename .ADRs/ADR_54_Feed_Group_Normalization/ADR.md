# ADR-54: Feed & Feed-Group normalization (first-class Feeds, M:N membership)

- **Status:** **Proposed** (2026-07-04)
- **Date:** 2026-07-04
- **Part of the Group-Policy redesign trilogy:** ADR-54 (this, data model) → ADR-55
  (Client Groups & policy bindings) → ADR-25 revised (DNSBL enforcement engine). Committed
  follow-ups: ADR-56 (per-CG DNSBL axes), ADR-57 (GeoIP fold-in). See §0.
- **Branch:** `adr/54-feed-group-normalization` (off `devel`; slug per CLAUDE.md "Branch
  naming") / **Component(s):** `pfblockerng.inc` (config schema, migration, download/parse
  pipeline, materialization), `pfblockerng_extra.inc` (read adapters),
  `src/usr/local/www/pfblockerng/` (`pfblockerng_feeds.php`, `pfblockerng_category.php`,
  `pfblockerng_category_edit.php`, new `pfblockerng_feed_edit.php`), `config.xml` schema,
  ports pkg-plists, `tests/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); Python untouched except manifest inputs
  (byte-identical by contract).
- **Test suite:** `tests/php/` (PHPUnit — schema/migration/materialization oracles),
  `tests/` (pytest where the manifest boundary is asserted), `tests/smoke/` (ADR-04 live
  VM plus ADR-14 `ui_render`/`ui_e2e`).
- **UI reference implementations:** [`UI/`](UI/) in this directory — authoritative design
  targets for Phase 4 (see §2.6). Dev-only artifacts; the phase copies/splices them into
  `src/`, it does not invent new UI.

---

## 0. Relationship & execution order (read this first)

Three ADRs deliver the redesign; two follow. **The order is strict** — each stage consumes
the previous stage's schema/entities:

```text
ADR-25 Phase 1 (cache spike) ────────────────────────────┐  start IMMEDIATELY, runs in
                                                          │  parallel with ADR-54/55; its
                                                          ▼  verdict gates ADR-25 P2..P7
ADR-54 P1→P2→P3→P4 ──→ ADR-55 P1→P2→P3→P4 ──→ ADR-25 P2..P7 ──→ ADR-56 ──→ ADR-57
(this ADR: data model)  (Client Groups +      (DNSBL enforcement   (per-CG    (GeoIP
                         IP policy rules)      engine)              axes)      fold-in)
```

- **ADR-54 (this)**: FEEDs become first-class entities; FEED GROUPs hold M:N memberships
  and pipeline defaults. **Behaviour-preserving end to end** — every phase lands with the
  zero-change oracles green.
- **ADR-55**: CLIENT GROUPs (named client sets) + POLICY BINDINGs (CG↔FG edges with action
  overrides + schedules) + scoped IP firewall rules + the Group Policy pages. IP-family
  bindings only; DNSBL bindings stay locked until ADR-25's engine lands.
- **ADR-25 (revised)**: the DNSBL decision layer consuming CGs/bindings — bitmask build,
  divergence-gated caching, schedule evaluation in the chroot. Its Phase-1 spike has no
  dependency on ADR-54/55 and MUST be dispatched first/in parallel so its kill/reduce
  verdict exists before anyone writes DNSBL enforcement code.
- **Every phase of every ADR in this trilogy is orchestrator-gated:** a Sonnet 5 implementer
  executes the phase; the orchestrating higher model (Opus/Fable) then **adversarially
  reviews the diff at reasoning effort `xhigh`** — verifying against the phase's kill-gates
  and the ADR contract, not the implementer's summary — and fixes/bounces inconsistencies
  before the next phase starts. This is the CLAUDE.md "Plan with a higher model, implement
  with Sonnet 5" flow made mandatory per phase.

## 1. Context — today

### 1.1 A feed is a row trapped inside one group

Feed lists live in three per-family config sections — `installedpackages/pfblockernglistsv4`,
`…listsv6`, `…dnsbl` — each a `config` listtag of **group** rows; a group's feeds are nested
`row` entries: `config/{N}/row/{M}` (`pfblockerng_category_edit.php:175-193`, save loop
`:738-826`). A feed row is `{header, url, state, format}` (+ per-row `action` Deny/Permit on
DNSBL rows, ADR-31). A **group** row carries `aliasname`, `description`, `action`, `cron`,
`dow`, `sort`, logging, the Advanced in/outbound rule fields, `suppression_cidr`, scripts,
and a base64 `custom` list. There is **no feed identity**: "the same feed in two groups" is
two unrelated copies of `{header, url}`.

### 1.2 What row duplication actually does (the pathologies)

- **On-disk collision:** `header` is the on-disk filename (`{header}{suffix}`; e.g. DNSBL raw
  at `pfb_py_raw/<header>.raw`, manifest built per row in `pfb_unbound_python_sources()`,
  `pfblockerng.inc:6532-6630`). The same `header` in two groups of the same action class
  writes the same file twice — double download, last write wins. The shipped catalog itself
  has a real intra-family duplicate: **`SWC` appears twice inside dnsbl** with different URLs
  (also flagged by ADR-33) — importing both silently collides.
- **Double download:** each row downloads independently; two groups referencing one URL fetch
  it twice (ADR-42's conditional GET helps the server, not the duplication).
- **The UI already half-models M:N:** the Feeds page renders one icon per group referencing a
  catalog feed's URL (`url_compare()`, `pfblockerng_feeds.php:197-280`; legend
  `fa-regular fa-circle-check` = "Item exists but in a different Alias/Group"). Cardinality
  is a storage accident, not a design.

### 1.3 The Feeds page is a catalog browser, not the editor

`pfblockerng_feeds.php` renders `pfblockerng_feeds.json` (47 categories / 247 feeds; dict
`family → category → {info, description, action, cron, feeds[]}`) via `convert_feeds_json()`
(`pfblockerng.inc:12557-12635`, strips `status == 'discontinued'`). Its `+` links deep-link
into `pfblockerng_category_edit.php?act=add|addgroup` which only **pre-fills** the edit form
(nothing written on GET). The page's own save writes two patch layers into
`pfblockerngglobal`: `feed_<alias>` (group rename/merge) and `feed_alt_<header>` (alternate
URL selection). The real editor is the Category tab pair
(`pfblockerng_category.php` list + quick-edit; `pfblockerng_category_edit.php` full editor).
ADR-16 (Accepted, landed) gave the Feeds page per-family sub-tabs + type-scoped saves.

### 1.4 Downstream consumers this ADR must not disturb

- **Manifest** (`pfb_unbound_python_sources()`): one entry per DNSBL feed row —
  `{raw, feed, group, format_hint, provenance, log_flag[, mode]}`; `group` =
  `DNSBL_{aliasname}`, used by `pfb_unbound.py` for attribution (`index_for(feed, group)`).
- **pf tables**: alias `pfB_{aliasname}_v4/_v6` per IP group (urltable,
  `pfblockerng.inc:16875-16884`); membership-gated reload (ADR-40) keyed **per table name**
  against `/var/db/aliastables/` mirrors.
- **Action-class folders**: `pfb_determine_list_detail()` (`pfblockerng.inc:4112-4136`)
  routes a group's content to denydir/permitdir/matchdir/nativedir by the group's action;
  ADR-11 aggregates and ADR-53 suppression consume those per-class member files.
- **Change detection** (ADR-42): content hashes + sidecars per feed file; **scheduling**
  (ADR-43): the due-ledger tick dispatches the `cron` verb which hour-gates each group's
  `cron`/`dow` (`pfblockerng.php:781-798`).
- **DNSBL Category (Blacklist page)**: provider archives (UT1) explode into
  `{dbdir}/{type}/{type}_{category}` local files; the update loop synthesizes ONE group per
  provider with one row per selected category (`pfblockerng.inc:14243-14291`,
  `header = {Title}_{category}`, `url` = local path).
- **ADR-33 (Proposed, not landed)**: reconciles stored rows against the catalog by
  **(category, header)** with `url ∈ {url}∪past_urls` disambiguation. This ADR's feed
  identity must keep that matching workable.

Line anchors above were verified 2026-07-04; **resolve fresh anchors at implementation time**
(the file drifts).

## 2. Decision

Normalize to two first-class entities with M:N membership, **preserving behaviour exactly**
(this ADR adds no enforcement semantics — that is ADR-55/25):

### 2.1 FEED entity

New section `installedpackages/pfblockerngfeeds`, a `config` listtag; one row per feed:

| Field | Meaning |
| --- | --- |
| `fid` | stable id, `{family}:{header}` (derived, stored for cheap joins) |
| `family` | `ipv4` \| `ipv6` \| `dnsbl` |
| `header` | label + on-disk filename; `\w`-only (`PFB_FILTER_WORD`); **unique per family** (enforced at save/import/migration — the SWC collision becomes impossible) |
| `url` | source URL (or local path — the Blacklist page emits local-path feeds) |
| `state` | `Enabled` \| `Disabled` \| `Hold` \| `Flex` (unchanged vocabulary) |
| `format` | IP: `auto/geoip/regex/whois/asn/rsync`; DNSBL: `auto/rsync` |
| `feed_action` | DNSBL only: `Deny` \| `Permit` (ADR-31 — a property of the feed's content, moved from the row) |
| `cat_category`, `cat_header` | catalog linkage for ADR-33 matching (empty for custom feeds) |
| `managed_by` | `''` (user) \| `blacklist` (emitted by the DNSBL Category page — see §2.5) |

**Download, hash (ADR-42 sidecars), and parse happen once per feed**, regardless of how many
groups reference it.

### 2.2 FEED GROUP entity

New section `installedpackages/pfblockerngfeedgroups`, a `config` listtag; one row per group.
Carries everything today's group row carries — `name` (`aliasname` semantics, ≤24 chars,
`\W`-rejected, unique), `description`, `default_action` (today's `action` vocabulary,
retitled: it is the *default* once ADR-55 lands), `cron`/`dow`, `aliaslog`/`logging`,
`order`, `filter_alexa`, the Advanced in/outbound rule fields, `suppression_cidr`,
`script_pre`/`script_post`, `custom` (stays a group-local pseudo-feed `{name}_custom`) —
**plus**:

| Field | Meaning |
| --- | --- |
| `members` | ordered list of `fid` refs (nested `member` listtag rows: `{fid}`) — **M:N** |

Hard rule: **every `Enabled` feed must belong to ≥ 1 group** (save-time validation on both
editors; orphans rendered `text-danger` on the Feeds page). A feed may belong to many groups;
a group holds many feeds.

DNSBL groups gain one `default_action` token: **`policy_only`** (GUI "Unbound (Policy-only)")
— the group is compiled into DNSBL but enforced for nobody; it exists for ADR-55/25 bindings.
Until ADR-25's engine lands, `policy_only` behaves exactly like `Disabled` at enforcement
time (compiled = no; the token is accepted, stored, and inert) — this keeps ADR-54
behaviour-preserving while letting the UI ship the full vocabulary once.

### 2.3 Materialization — unchanged shapes, new derivation

- pf table `pfB_{name}_v4/_v6` and DNSBL alias `DNSBL_{name}` per group, exactly as today —
  now derived as the deduped union of **member feeds'** parsed artifacts instead of nested
  rows. ADR-40's per-table gate, mirrors, and delta apply are untouched.
- **Processing stays keyed to the group's `default_action` class.** Routing into
  denydir/permitdir/matchdir/nativedir, dedup, reputation, ADR-53 suppression, ADR-11
  aggregation: all unchanged in shape. A feed shared by a Deny-group and a Permit-group
  materializes into both class folders **from one download** (per-(feed, group) derivation;
  the raw/parsed artifact is per-feed, the class-folder member file is per-(feed, group)).
- **Manifest**: one entry per (feed, group) edge — identical to today's one-entry-per-row,
  since a row *was* an edge. `feed` = header, `group` = `DNSBL_{name}`. Byte-identical for
  any 1:1 config (the oracle).
- **Cadence**: `cron`/`dow` stay group-level. A feed shared by groups with different crons
  downloads at the **most frequent** member-group cadence; each group's table rebuild rides
  its own ADR-40 membership gate (a less-frequent group simply sees fresher content — same
  end-state invariant). Rides the existing ADR-43 `cron` verb; **no new ledger jobs**.

### 2.4 Migration (one-time, idempotent, `write_config` backup)

1. Each legacy group `config/{N}` → a `pfblockerngfeedgroups` row (fields copied verbatim;
   `action` → `default_action`).
2. Each nested `row/{M}` → a `pfblockerngfeeds` row + a `member` ref. **Collapse** duplicates
   (same family+header+url found in several groups → one feed, several memberships).
   **Suffix** conflicts (same family+header, different url → second becomes `{header}_2`,
   logged; `SWC` is the mandatory fixture).
3. `pfblockerngglobal/feed_<alias>` rename/merge keys → applied as the migrated group's
   actual `name`; `feed_alt_<header>` selections → applied as the feed's `url`; both key
   families then deleted (they exist only to patch the catalog view).
4. Legacy sections (`pfblockernglistsv4/v6`, `pfblockerngdnsbl` group rows) are then
   **replaced** by the new sections — and a **frozen legacy mirror** of the pre-migration
   sections is written once (verbatim copy under `installedpackages/pfblockerngmigrated54`),
   so a package **downgrade** reads its old sections from the last pre-migration state
   instead of nothing (ADR-28 posture: behaviour preserved on upgrade; downgrade
   fail-safe-not-fresh). The mirror is write-once, never maintained.
5. GeoIP continent sections: **untouched** (ADR-57 will fold them in).
6. Re-running the migration is a no-op (presence of `pfblockerngfeedgroups` short-circuits).

### 2.5 DNSBL Category (Blacklist page) joins the model

The page keeps its role — provider/source manager (enable, provider+credentials, language,
frequency, category checkboxes). Its output becomes real entities: each selected category =
a FEED (`fid = dnsbl:{Title}_{category}`, `url` = the exploded local path,
`managed_by = blacklist`) auto-added to an auto-managed provider default group (`{Title}`).
Zero-config behaviour identical (that group is exactly today's synthesized `$list`).
Categories become individually groupable (the M:N payoff: a user "Adult" group =
`UT1_adult` + other feeds). Deselecting a category still referenced by **user** groups is
refused with a listing (never-destructive, ADR-33 posture). The Blacklist's special
`order == 'primary'` carve-out normalizes away — the provider group is an ordinary group
with the existing `order` field.

### 2.6 UI (stock pfSense components ONLY — hard constraint)

Reference implementations live in [`UI/`](UI/) and are the **authoritative design**;
Phase 4 splices them (they may need mechanical adaptation to drifted line numbers, never
design changes without an ADR note):

- `UI/pfblockerng_feed_edit.php` — **new page, complete file.** FEED entity editor.
- `UI/category_edit_member_feeds.inc.php` — **splice section**: replaces the
  "Source Definitions" row grid in `pfblockerng_category_edit.php` with the Member-Feeds
  multi-select (+ the `Default Action` retitle + `policy_only` option).
- `UI/feeds_page_changes.md` — exact splice instructions for `pfblockerng_feeds.php`
  (Feed Group(s) column, legend rewording, orphan rendering, Feed-Settings section removal)
  and `pfblockerng_category.php` (Default Action retitle, Feeds/Policies count columns).

Component rules: `Form_Section`/`Form_Group`/`Form_Select` (incl. `multiple`)/
`Form_Checkbox`/`Form_Input`/`Form_Textarea`/`Form_StaticText`/`Form_Button`, the
`repeatable` row-helper, `display_top_tabs`, panel + sortable tables, `print_info_box`,
`infoblock alert-info`. **No bespoke JS widgets.** Wording matches neighbours
(`Default: <strong>…</strong>`, `&#8226` bullets, `<span class="text-danger">Note:</span>`).

### 2.7 Semantics that MUST be preserved (the contract — pin before restructuring)

- **Zero-change oracles** (Phase 1, the regression gate for every later phase): for any
  pre-migration config, post-migration output is **identical** — manifest bytes, pf table
  memberships (`pfctl -t <t> -T show` equality), generated `filter/rule` array (modulo
  nothing — tracker ids derive from unchanged descrs), class-folder member files, DNSBL
  alias set. Pinned off-appliance (PHPUnit harness over the extractable builders) + live-VM
  smoke.
- **ADR-42/40/43 layering untouched**: detection stays content-addressed per feed file;
  apply stays membership-gated per table; scheduling stays the single tick + ledger. No
  parallel path.
- **ADR-31 per-feed `feed_action` semantics unchanged** (permit feeds keep band-2 behaviour;
  manifest `mode` key emitted only when permit).
- **PFBL-01** validation on every new save/migration surface; new input-handling functions
  join the sniff's `scopeFunctions`.
- **Config gateway**: the new sections are **dynamic/structural — foreign keys** (like the
  sections they replace): section helpers / direct `config_*_path`, NOT the `PfbConfig`
  registry. Add them to the documented foreign-key exclusion list in
  `docs/misc/config-gateway.md`.
- **Downgrade**: the §2.4 frozen mirror restores pre-migration behaviour on downgrade; a
  downgraded release never sees a novel token in *its* sections.

### 2.8 Explicitly out of scope

- Any enforcement change (Client Groups, bindings, scoped rules, per-client DNSBL) —
  ADR-55/25.
- GeoIP continents (ADR-57), SafeSearch/DoH axes (ADR-56).
- The feed **catalog** JSON schema (read-only here; ADR-33 owns reconciliation and is
  **re-based by this ADR**: its matching key stays (category, header) via the feed's
  `cat_category`/`cat_header`, its actions now target feed entities instead of nested rows —
  a small respec, ADR-33 is not landed).
- `python`-side changes (the manifest is byte-identical by contract).

## 3. Consequences

### Positive

- Feed identity kills the double-download and the `SWC`-style filename collision class.
- M:N grouping becomes honest data instead of row duplication; the Feeds page renders truth.
- The subscription unit ADR-55/25 need (the group) now exists with a stable name-space.
- Blacklist categories become first-class, individually policy-able feeds.
- Storage normalization happens **once**, behind byte-identical oracles, before any
  behaviour change rides on it — the cheapest possible time to be wrong.

### Negative / risks

- **Biggest schema migration this package has attempted** — every download/parse/table/rule
  path reads these sections. Mitigated by phase order (oracles first) and the frozen mirror.
- Per-(feed, group) materialization touches the class-folder derivation that ADR-11/53
  consume — the re-seam must keep `pfb_aggregate_member_list()` and suppression semantics
  bit-stable (oracle-pinned).
- A shared feed's most-frequent-cadence download changes *when* a less-frequent group's
  content refreshes (fresher, never staler). Documented; ADR-40's gate keeps applies
  correct.
- The frozen mirror is a one-shot snapshot: a downgrade after months sees stale lists until
  its own cron refreshes them — acceptable and documented.

## 4. Requirements (acceptance)

- All §2.7 oracles green off-appliance and on the live-VM CE+Plus fan-out.
- Migration: legacy → new is idempotent, collapses duplicates, suffixes conflicts, writes
  the mirror, absorbs `pfblockerngglobal` patch keys; absent legacy config ⇒ no-op.
- Feeds/groups editable per §2.6 with per-family header uniqueness + orphan validation.
- Blacklist page emits feed entities per §2.5 with identical zero-config behaviour.
- `python -m pytest`, `ruff`, `mypy tests/`, `php -l`, PHPStan, PHPUnit, PHPCS, markdownlint
  clean; Tier A `ui_render` green for every touched page; Tier B `ui_e2e` for the new page
  and the membership save flow.

## 5. Constraints (from CLAUDE.md)

- PHP: tabs, PHP 8.3, no `die()/exit()` in lib code; new pfSense fns stubbed +
  doubled; PFBL-01 scope updated.
- Naming: follow `pfb_*`/`pfB_` conventions; new config keys follow sibling patterns.
- Every phase = one commit, gates green; behaviour-preserving phases stay green across the
  swap (regression oracles, not red→green).
- Worktree + rebase-only landing flow; `/pr-merge-flow` for the implementation PRs.
- **Ports lockstep**: `pfblockerng_feed_edit.php` (and any new shipped file) needs
  pkg-plist + `do-install` entries in all three ports; verify with
  `build-pkg-portable.py --dry-run`.

## 6. Action plan

Every phase: one commit, executed by a Sonnet 5 implementer, **adversarially gate-reviewed
by the orchestrator at `xhigh` before the next phase** (§0). Prompts in this directory.

### Phase 1 — Pin the zero-change oracles (behaviour-preserving)

- Prompt: `01_Zero_Change_Oracles.txt`
- Build the off-appliance oracle harness: given a fixture config (several groups, shared
  feeds, a permit feed, a custom list, a Blacklist selection), capture manifest bytes,
  class-folder member lists, table membership inputs, and the generated `filter/rule`
  array. Freeze as golden files. No production change.

### Phase 2 — Schema + migration + read adapters (behaviour-preserving)

- Prompt: `02_Schema_Migration_Adapters.txt`
- New sections, migration per §2.4 (mirror included), read adapters so every consumer reads
  the new sections; oracles byte-identical pre/post migration.

### Phase 3 — Single-download + per-(feed,group) materialization (behaviour-preserving)

- Prompt: `03_Materialization_Reseam.txt`
- Download/hash/parse once per feed; derive per-(feed,group) class-folder files; re-seam
  ADR-11 member lists + ADR-53 suppression + Blacklist emission (§2.5); cadence rule
  (§2.3). Oracles green; duplicate-collapse fixtures (SWC) prove single-download.

### Phase 4 — UI (Feeds/Groups editors)

- Prompt: `04_UI_Feeds_Groups.txt`
- Splice the `UI/` reference implementations; ports plists; Tier A for all touched pages;
  Tier B: create group → pick members → save → reload → persisted; feed under two groups;
  orphan-feed validation message.

## 7. Definition of done

- [ ] §4 requirements all green in CI (`test.yml` full suite).
- [ ] Live-VM smoke green on the **CE + Plus fan-out** (default ADR-acceptance validation).
- [ ] Zero-change oracles green at every phase boundary (the per-phase gate reviews attest
      this explicitly).
- [ ] Migration fixtures: duplicate-collapse, SWC suffix, `pfblockerngglobal` absorption,
      idempotent re-run, absent-legacy no-op, mirror written once.
- [ ] Tier A + Tier B UI gates green (`ui_render` all pages; `ui_e2e` new-page + membership
      flow).
- [ ] `docs/misc/architecture-notes.md` gains the normalization section;
      `docs/misc/config-gateway.md` foreign-key list updated; ADR-33 respec note added to
      its ADR.md.
- [ ] The landing PR references this ADR and the `UI/` artifacts it implemented.
