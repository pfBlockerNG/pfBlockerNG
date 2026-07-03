# ADR-33: Add opt-in Auto Feed Management (reconcile stored feeds against feeds.json)

- **Status:** **Proposed** (2026-06-20; facts + gates refreshed 2026-07-03 against `devel` —
  matching rekeyed to (category, header) after real duplicate headers were found in the
  catalog, rule precedence fixed (status before url-equality), the setting renamed
  `pfb_feed_mgmt_mode`, and Tier B / CE+Plus fan-out gates added; one sub-choice left open:
  intra-category duplicate handling, see §1)
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

- **`header`** identifies a catalog feed (it matches the per-row `header` stored in a user's
  feed-list config under `pfblockernglistsv4/v6` / `pfblockerngdnsbl`). **Correction
  (2026-07-03): `header` is NOT globally unique** — the shipped catalog has duplicates across
  categories (`MDL` in ipv4 *and* dnsbl; `Malc0de` similarly — different URLs) **and within
  one category** (`SWC` appears **twice inside dnsbl**, both active, different URLs). A flat
  `[header => …]` index is last-write-wins and cannot represent `SWC`. The matching key is
  therefore **(category, header)** — user config sections map `pfblockernglistsv4 → ipv4`,
  `…v6 → ipv6`, `pfblockerngdnsbl → dnsbl` — and intra-category duplicates are disambiguated
  by `url`/`past_urls` or treated as no-match (pick one when implementing; `SWC`/`MDL`/
  `Malc0de` are mandatory test fixtures). *Recommended (2026-07-03, non-binding): disambiguate
  by the stored `url` ∈ that candidate's `{url} ∪ past_urls`; if no candidate matches uniquely,
  treat as **no-match** — when ambiguous, touch nothing (consistent with the never-destructive
  posture).*
- **`status`** can be `discontinued` (**37** rows today, not 39) — and **1 row is
  `Suspended`**, a status the rules below must either fold into the discontinued handling or
  explicitly ignore (enumerate the full status vocabulary when implementing; today's live set
  is `discontinued` + `Suspended` + absent). *Recommended (2026-07-03, non-binding):
  `Suspended` is report-only in BOTH modes ("feed suspended upstream") — never auto-disabled;
  a suspension is temporary, and auto-disabling would need a symmetric re-enable path this ADR
  deliberately does not have.*
- **`past_urls`** (present on a few rows today) records prior URLs a feed has moved through —
  the breadcrumb that lets us recognise a user's stored-but-moved URL.
- **`alternate`** offers replacement feeds.

Load-bearing facts:

- `past_urls` is unconsumed today. **`status` is already consumed** (corrected 2026-07-03):
  `convert_feeds_json()` in `pfblockerng.inc` **strips discontinued rows** before the Feeds
  page renders, and `pfblockerng_feeds.php` renders `status`. Practical consequence: the
  Phase 1 indexer must **NOT reuse `convert_feeds_json()`** — it drops the very rows the
  reconciler needs — it reads the raw JSON itself.
- A user's stored feeds live in `config.xml` (`pfblockernglistsv4/v6` rows: `header` + `url` +
  per-row `state`, nested per-alias as `config/{N}/row/{M}`). **Per the ADR-28 policy of
  record, storage is NOT frozen — behaviour is preserved, not bytes** (the original "frozen
  as a format" wording predates the reconciled §2.2); user feed rows are normal mutable
  settings pfBlockerNG already writes (e.g. the alias/header space-stripping `write_config`
  in `pfblockerng.inc`). Editing a user's own feed row is allowed. Note the row `state`
  disable token is capital-`'Disabled'` (the enable checks compare `!= 'Disabled'`).
- There is **no** today-behaviour to reconcile feeds; default must be **fully inert**.

## 2. Decision

Add an **opt-in Auto Feed Management** reconciler that compares a user's stored feed rows
against `pfblockerng_feeds.json` and either **applies** or **reports** drift, per a user-chosen
**mode**. It runs on package install/update and on a manual "Recheck Feeds" action.

**Mode (new setting `pfb_feed_mgmt_mode`, default `off`):**

| Mode | Behaviour |
| --- | --- |
| `off` (default) | reconciler never runs — **byte-identical to today** |
| `notify` | detect drift, surface `file_notice` + a UI badge/list; **never** mutate config |
| `auto` | apply the changes to the user's feed rows (`write_config` with a backup), **and** emit a notification of what changed |

The maintainer's call: users pick between **auto-apply (with notification)** and
**notify-only** — both are offered; neither is forced.

### 2.1 Reconciliation rule (pure, testable)

For each stored user feed row, match it to a catalog feed and compute an **action**. **Rule
precedence is explicit and top-down (fixed 2026-07-03):** the `status` check runs **before**
the url-equality no-op — a discontinued feed's stored URL usually still equals the catalog URL
(it died, it didn't move), so an if/elif in url-first order would return `none` for exactly
the case this feature exists for. A test fixture with a discontinued feed whose `url` ==
catalog `url` is mandatory.

| Priority | Condition | Action (`auto`) | Action (`notify`) |
| --- | --- | --- | --- |
| 1 | matched catalog feed `status` == `discontinued` (incl. when `url` == catalog `url`) | set the row `state` to `'Disabled'` (**never delete**) | report "discontinued" |
| 2 | stored `header` matches, stored `url` ∈ catalog `past_urls` (feed **moved**) | rewrite the row's `url` to the catalog `url` | report "URL moved" |
| 3 | stored `header` matches a catalog feed, `url` == catalog `url` | none | none |
| 4 | stored `header` not in catalog for that category (user-custom / removed) | none (leave untouched) | none |

A feed that is both moved **and** discontinued takes priority 1 (disable; the URL rewrite is
moot). An `alternate` suggestion stacks with any of the above as a report line, never an
apply. Matching key = **(category, header)** per §1, with `past_urls` disambiguating a moved
URL. `alternate` rows are surfaced as a *suggestion* in both modes (never auto-added — adding
a new feed is the user's choice). Reconciliation is **idempotent** (re-running yields no
further actions).

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before wiring)

- **`pfb_feed_mgmt_mode = off` ⇒ zero behaviour change** — no scan, no notice, no write. This is
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

- `pfb_feed_mgmt_mode` setting (`off`/`notify`/`auto`, default `off`) via `PfbConfig`.
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
- The index is keyed **(category, header)** per §1 — do **NOT** reuse `convert_feeds_json()`
  (it strips the discontinued rows the reconciler needs); read the raw JSON.
- Tests: index a fixture catalog (incl. discontinued + `Suspended` + past_urls + alternate +
  malformed rows + the real duplicate-header cases `SWC` (twice in dnsbl), `MDL`/`Malc0de`
  (cross-category)); assert the map shape, the duplicate handling, and that bad rows are
  skipped, not fatal.

### Phase 2 — Prep: pure reconcile-plan (`pfb_feed_reconcile_plan`) + tests (no side effects)

- Prompt: `02_Reconcile_Plan.txt`
- Add a pure function: `(user_rows, index) → [actions]` per §2.1 (none / rewrite-url /
  disable-discontinued / suggest-alternate), honouring the §2.1 **priority order**
  (status before url-equality). No I/O, no config writes. Note the real user-row store shape:
  rows are nested per-alias (`config/{N}/row/{M}`), so each action carries a full row
  reference (list type, alias index, row index) — define it here.
- Tests: every branch — exact-url match → none; stored url ∈ past_urls → rewrite; status
  discontinued → disable **including the url == catalog-url fixture** (proves the priority
  order); moved+discontinued → disable only; unknown header → none; the intra-category
  duplicate (`SWC`) case; alternate → suggestion; idempotency (re-plan
  after applying yields none). Assert before/after action sets.

### Phase 3 — Config: the `pfb_feed_mgmt_mode` setting (default off)

- Prompt: `03_Mode_Setting.txt`
- Register **`pfb_feed_mgmt_mode`** (`off`/`notify`/`auto`, default `off`) — renamed
  2026-07-03 to match the `pfb_*` convention of the sibling registered keys
  (`pfb_agg_types`, `pfb_alias_delta_mode`, `pfb_tick_interval`) — in `pfb_cfg_registry()`
  (+ `since`) + the RequireConfigGateway sniff `$registeredPaths`; read/write via `PfbConfig`.
  Mode values ⇒ a **backed enum** per ADR-28 item 1 (the `PfbIdnMode` pattern), not a plain
  string; add the field's row to the `docs/misc/config-gateway.md` inventory. No reconcile
  wiring yet.
- Tests: PHPUnit registry round-trip (write(read(v))==v for each token), default-absent ⇒ off,
  and unknown token ⇒ off (parse-fallback).

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
  Fatal/Parse/Warning/Notice/Uncaught, marker, no new php_error.log line); **plus Tier B
  `ui_e2e` — REQUIRED per CLAUDE.md test principle 4** (multi-step flow + structural
  addition): set mode → save → Recheck → the review panel lists the proposed/applied changes.
  Mind the ADR-16 Feeds-page save scoping (`?type=` type-scoped save) when placing the
  selector — pin the host page here.

### Phase 6 — Smoke + DoD + docs

- Prompt: `06_Smoke_DoD_Docs.txt`
- Live-VM smoke: seed a stored feed whose catalog `url` moved (stored url ∈ past_urls) and one
  whose catalog `status` is discontinued; assert `notify` reports both without writing, and
  `auto` rewrites the URL + disables the discontinued feed (assert before-state then after).
  **On-box catalog fixture:** only 3 real `past_urls` rows exist, so the case overwrites the
  shipped `pfblockerng_feeds.json` with a test catalog on the box (restore after — the same
  overwrite-and-restore pattern other smoke fixtures use). **Gate: green on the CE + Plus
  fan-out** — for a feature that mutates user config in `auto` mode the notify/auto proof
  cannot be a maintainer checklist (CLAUDE.md "ADR acceptance"); no SKIP-with-checklist
  escape. Docs (`docs/misc/architecture-notes.md`, README); genuinely-out-of-CI residue is a
  documented limitation.

## 7. Definition of done

- [ ] `pfb_feed_mgmt_mode` default `off` ⇒ byte-identical to today (oracle).
- [ ] `pfb_feeds_index` + `pfb_feed_reconcile_plan` pure + branch-covered.
- [ ] `notify` never writes (asserted); `auto` applies (backup, idempotent, never-delete) +
      notifies; custom feeds untouched.
- [ ] Manual "Recheck Feeds" + install/update trigger work.
- [ ] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS, `php -l`, `python -m pytest`,
      ADR-14 `ui_render` **+ `ui_e2e`**; live-VM smoke proves moved + discontinued in both
      modes on the **CE + Plus fan-out**.

**Manual smoke (owner: maintainer):**

- [ ] Real upgrade carrying a config with a moved + a discontinued feed → `notify` lists both,
      writes nothing; `auto` rewrites + disables + notifies; re-run is a no-op (idempotent).
- [ ] Confirm a user-custom feed (header absent from catalog) is never touched in any mode.

**Reject criteria:** if header-keyed matching proves unreliable on real configs (false
rewrites/disables), or `auto` cannot be made idempotent + non-destructive, **reduce to
`notify`-only** (drop `auto`) or **reject**, recording the failing cases.
