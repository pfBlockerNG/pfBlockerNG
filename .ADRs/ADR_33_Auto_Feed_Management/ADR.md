# ADR-33: Add opt-in Auto Feed Management (reconcile stored feeds against feeds.json)

- **Status:** **Proposed** (2026-06-20)
- **Date:** 2026-06-20
- **Branch:** `adr/33-auto-feed-management` (off `devel`)
- **Folds in:** issue #292 ("Add Auto Feed Management")
- **Component(s):** `src/usr/local/www/pfblockerng/pfblockerng_feeds.json` (the feed catalog),
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (feed-list config + reconciler), feeds/general
  UI page, `config.xml` (`pfblockernglistsv4/v6`, `pfblockerngdnsbl` rows)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8)
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` (live-VM, ADR-04)

## 1. Context

The package ships a curated feed catalog, `pfblockerng_feeds.json`, a dict keyed by category
(`ipv4`, `ipv6`, `dnsbl`) → sub-category (`PRI1`, …) → `feeds: [ … ]`. Each feed row carries
(confirmed in the live file):

```json
{ "status": "discontinued", "feed": "Abuse Ransomware Tracker",
  "website": "…", "url": "https://…/RW_IPBL.txt", "header": "Abuse_IPBL",
  "alternate": [ { "url": "…", "header": "…" } ] }
```

- **`header`** is the stable identifier of a catalog feed (it matches the per-row `header`
  stored in a user's feed-list config under `pfblockernglistsv4/v6` / `pfblockerngdnsbl`).
- **`status`** can be `discontinued` (39 rows today), among others.
- **`past_urls`** (present on a few rows today) records prior URLs a feed has moved through —
  the breadcrumb that lets us recognise a user's stored-but-moved URL.
- **`alternate`** offers replacement feeds.

Load-bearing facts:

- These catalog fields (`status`, `past_urls`) exist **specifically** for a planned
  reconciliation process; nothing consumes them yet.
- A user's stored feeds live in `config.xml` (`pfblockernglistsv4/v6` rows: `header` + `url` +
  per-row `state`). **The config store is frozen as a *format* (ADR-28), but user feed rows
  are normal mutable settings** — pfBlockerNG already writes them (e.g. the alias/header
  space-stripping `write_config` at `pfblockerng.inc`). So *editing a user's own feed row* is
  allowed; what's frozen is the schema/vocabulary, not the user's data.
- There is **no** today-behaviour to reconcile feeds; default must be **fully inert**.

## 2. Decision

Add an **opt-in Auto Feed Management** reconciler that compares a user's stored feed rows
against `pfblockerng_feeds.json` and either **applies** or **reports** drift, per a user-chosen
**mode**. It runs on package install/update and on a manual "Recheck Feeds" action.

**Mode (new setting `feed_mgmt_mode`, default `off`):**

| Mode | Behaviour |
| --- | --- |
| `off` (default) | reconciler never runs — **byte-identical to today** |
| `notify` | detect drift, surface `file_notice` + a UI badge/list; **never** mutate config |
| `auto` | apply the changes to the user's feed rows (`write_config` with a backup), **and** emit a notification of what changed |

The maintainer's call: users pick between **auto-apply (with notification)** and
**notify-only** — both are offered; neither is forced.

### 2.1 Reconciliation rule (pure, testable)

For each stored user feed row, match it to a catalog feed and compute an **action**:

| Condition | Action (`auto`) | Action (`notify`) |
| --- | --- | --- |
| stored `header` matches a catalog feed, `url` == catalog `url` | none | none |
| stored `header` matches, stored `url` ∈ catalog `past_urls` (feed **moved**) | rewrite the row's `url` to the catalog `url` | report "URL moved" |
| matched catalog feed `status` == `discontinued` | set the row `state` to disabled (**never delete**) | report "discontinued" |
| stored `header` not in catalog (user-custom / removed) | none (leave untouched) | none |

Matching key = **`header`** (stable), with `past_urls` disambiguating a moved URL. `alternate`
rows are surfaced as a *suggestion* in both modes (never auto-added — adding a new feed is the
user's choice). Reconciliation is **idempotent** (re-running yields no further actions).

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before wiring)

- **`feed_mgmt_mode = off` ⇒ zero behaviour change** — no scan, no notice, no write. This is
  the default and the regression oracle.
- **Never delete a user feed** — discontinued feeds are *disabled* (`state`), preserving the
  row so the user can re-enable / inspect it.
- **`notify` never writes `config.xml`** — assert byte-identical store before/after a notify run.
- **`auto` writes only matched rows**, takes a `write_config` backup, and is **idempotent**.
- **Custom/unknown feeds are untouched** in every mode.
- The **catalog JSON schema/vocabulary is unchanged** by this ADR (we only *read* it).

### 2.3 Triggers

- **Manual "Recheck Feeds"** UI action (always available once mode ≠ off).
- **Package install/update** hook — runs the reconciler in the configured mode (off ⇒ nothing).
  Reuse the existing install/update entry points; do not add a new cron.

### 2.4 Explicitly kept / out of scope

- **Auto-adding `alternate` feeds** — out; suggested, never auto-applied.
- **Deleting feed rows** — out; discontinued ⇒ disable only.
- **A new scheduled job** — out; runs on install/update + manual action only.
- **Editing the catalog JSON** or its schema — out; read-only consumer.
- **Reconciling anything other than `url`/`state` from the catalog** — out for v1.

## 3. Consequences

**Positive**

- Users opt in to automatic upkeep: moved feeds self-heal, discontinued feeds stop erroring,
  with a clear notification — or stay fully manual via `notify`.
- Builds on catalog fields (`status`/`past_urls`) that already exist for exactly this purpose.
- Default `off` ⇒ no risk to existing installs.

**Negative / risks**

- `auto` mutates user config — must be conservative (header-keyed, `past_urls`-confirmed,
  backup, idempotent, never-delete) to avoid surprising users; mitigated by the pure-plan +
  before/after tests and the explicit notification.
- Catalog/`config` matching has edge cases (renamed headers, `alternate`, custom rows) — the
  pure reconcile-plan function must cover each branch.

## 4. Requirements (acceptance)

- `feed_mgmt_mode` setting (`off`/`notify`/`auto`, default `off`) via `PfbConfig`.
- A pure `pfb_feeds_index()` (catalog → header-keyed map) and a pure
  `pfb_feed_reconcile_plan(rows, index)` (→ actions), unit-tested for every branch.
- `notify` surfaces drift without writing; `auto` applies (backup, idempotent, never-delete) +
  notifies; `off` is inert.
- Manual "Recheck Feeds" action + install/update trigger.
- All gates green (§5); live-VM smoke (§7) proves a moved + a discontinued feed in both modes.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code; new pfSense fns stubbed + doubled.
- New scalar setting goes through `PfbConfig`/`pfb_cfg_registry()` (ADR-29) + the sniff
  `$registeredPaths`. Feed-row sections (`pfblockernglistsv4/v6`, `pfblockerngdnsbl`) are
  dynamic list sections — use the section helpers / direct `config_*_path` (foreign-key list).
- New input-handling honours PFBL-01; any feed URL written is validated (`PFB_FILTER_URL`).
- Catalog JSON parsed defensively (malformed/missing keys never fatal).

## 6. Action plan

### Phase 1 — Prep: pure catalog index (`pfb_feeds_index`) + tests (behaviour-preserving)

- Prompt: `01_Feeds_Index.txt`
- Add a pure function parsing `pfblockerng_feeds.json` into a header-keyed map
  `{header → {url, status, past_urls[], alternate[]}}`, defensively (missing keys ok). NOT
  wired to any caller.
- Tests: index a fixture catalog (incl. discontinued + past_urls + alternate + malformed rows);
  assert the map shape and that bad rows are skipped, not fatal.

### Phase 2 — Prep: pure reconcile-plan (`pfb_feed_reconcile_plan`) + tests (no side effects)

- Prompt: `02_Reconcile_Plan.txt`
- Add a pure function: `(user_rows, index) → [actions]` per §2.1 (none / rewrite-url /
  disable-discontinued / suggest-alternate). No I/O, no config writes.
- Tests: every branch — exact-url match → none; stored url ∈ past_urls → rewrite; status
  discontinued → disable; unknown header → none; alternate → suggestion; idempotency (re-plan
  after applying yields none). Assert before/after action sets.

### Phase 3 — Config: the `feed_mgmt_mode` setting (default off)

- Prompt: `03_Mode_Setting.txt`
- Register `feed_mgmt_mode` (`off`/`notify`/`auto`, default `off`) in `pfb_cfg_registry()` +
  the RequireConfigGateway sniff `$registeredPaths`; read/write via `PfbConfig`. No reconcile
  wiring yet.
- Tests: PHPUnit registry round-trip (write(read(v))==v for each token) + default-absent ⇒ off.

### Phase 4 — Apply engine + triggers (notify vs auto), wired to install/update + manual

- Prompt: `04_Apply_Engine.txt`
- Consume the Phase-2 plan: `notify` → `file_notice` + UI list, no write; `auto` → apply to the
  matched rows (`write_config` backup, never-delete, idempotent) + notify. Wire into the
  install/update entry point and a manual "Recheck Feeds" handler. `off` short-circuits.
- Tests: PHPUnit — notify run leaves config byte-identical (assert) + produces the expected
  notice list; auto run applies exactly the planned changes, takes a backup, is idempotent, and
  never deletes; off run does nothing.

### Phase 5 — UI: mode selector + "Recheck Feeds" + change review

- Prompt: `05_UI.txt`
- Add the mode selector + a "Recheck Feeds" action + a review panel listing
  proposed (notify) / applied (auto) changes. Server-side validation (PFBL-01); help text per
  neighbours.
- Tests: PHPUnit for any extracted decider; ADR-14 `ui_render` for the page (200, no
  Fatal/Parse/Warning/Notice/Uncaught, marker, no new php_error.log line).

### Phase 6 — Smoke + DoD + docs

- Prompt: `06_Smoke_DoD_Docs.txt`
- Live-VM smoke: seed a stored feed whose catalog `url` moved (stored url ∈ past_urls) and one
  whose catalog `status` is discontinued; assert `notify` reports both without writing, and
  `auto` rewrites the URL + disables the discontinued feed (assert before-state then after).
  Docs (`docs/misc/architecture-notes.md`, README); manual checklist for anything CI can't do.

## 7. Definition of done

- [ ] `feed_mgmt_mode` default `off` ⇒ byte-identical to today (oracle).
- [ ] `pfb_feeds_index` + `pfb_feed_reconcile_plan` pure + branch-covered.
- [ ] `notify` never writes (asserted); `auto` applies (backup, idempotent, never-delete) +
      notifies; custom feeds untouched.
- [ ] Manual "Recheck Feeds" + install/update trigger work.
- [ ] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS, `php -l`, `python -m pytest`,
      ADR-14 `ui_render`; live-VM smoke proves moved + discontinued in both modes.

**Manual smoke (owner: maintainer):**

- [ ] Real upgrade carrying a config with a moved + a discontinued feed → `notify` lists both,
      writes nothing; `auto` rewrites + disables + notifies; re-run is a no-op (idempotent).
- [ ] Confirm a user-custom feed (header absent from catalog) is never touched in any mode.

**Reject criteria:** if header-keyed matching proves unreliable on real configs (false
rewrites/disables), or `auto` cannot be made idempotent + non-destructive, **reduce to
`notify`-only** (drop `auto`) or **reject**, recording the failing cases.
