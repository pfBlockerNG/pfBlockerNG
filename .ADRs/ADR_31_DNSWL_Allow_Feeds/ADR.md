# ADR-31: Subscribable remote DNSWL (allow-list) feeds for DNSBL

- **Status:** **Implemented (pending live-VM smoke fan-out)** (2026-06-20)
- **Date:** 2026-06-20
- **Branch:** `adr/31-dnswl-allow-feeds` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfb_unbound.py` — the matcher/build: route a `permit`-mode feed's
    hosts into `whiteDB` as band-2 (feed-allow) entries; `dnsbl_build_from_manifest()` (`:399`),
    `_resolve_numeric_allow()` (`:5436`), the ABP allow store (`:4700`).
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — the DNSBL feed download/stage loop
    (`:11054-11191`), the manifest writer `pfb_unbound_py_atomic_write()` (`:4784`,
    `$pfb['unbound_py_sources']` `:108`); reading the new per-row **action** field on the existing
    `pfblockerngdnsbl/config` rows.
  - `src/usr/local/www/pfblockerng/pfblockerng_category_edit.php` — a `Deny`/`Permit` action select
    added to the existing DNSBL feed-row editor (no new page).
  - `tests/` (pytest) + `tests/php/` (PHPUnit) + `tests/smoke/` (ADR-04 live VM, ADR-16 mock feeds).
- **Target runtime:** Python 3.11+ in Unbound's pythonmod (stdlib only, chrooted at `/var/unbound`);
  PHP 8.3 (pfSense CE 2.8).
- **Test surface:** `python -m pytest` (Python matcher/build); `vendor/bin/phpunit` + `phpcs` +
  `phpstan` (PHP, PR gate); `tests/smoke` (ADR-04 fan-out, CE + Plus); `ui_render` (Tier A PR gate).

Originates from **issue #324** (Redmine #16465): *"Add ability to use DNSWL subscription lists."*
Allow-list (whitelist) feeds are increasingly maintained to counter blacklist false-positives; other
vendors support subscribing to them. pfBlockerNG currently cannot subscribe to a standalone remote
allow-list.

---

## 1. Context (today)

### 1.1 How allow/whitelist coverage works now (measured, not assumed)

DNSBL allow coverage comes from exactly **three** sources, all converging on one store (`whiteDB`)
and one 6-band precedence resolver:

- **Manual suppression / whitelist** — operator-entered, stored base64 in
  `pfblockerngdnsblsettings/config/0/suppression` (`pfblockerng_dnsbl.php:113`), written to
  `/var/db/pfblockerng/pfbdnsblsuppression.txt` (`$pfb['dnsbl_supptxt']`, `pfblockerng.inc:91`),
  loaded into `whiteDB` at **band 6** (sovereign — beats every block; `pfb_unbound.py:5374-5396`).
- **Inline ABP `@@` allow rules** embedded *inside a block feed* (ADR-07/21): `@@||domain^` →
  `whiteDB` wildcard allow at **band 2** (band 4 with `$important`); `@@/re/` → `allow_regex_db`.
  Parsed by `_dnsbl_parse_abp_line()` (`pfb_unbound.py:3476-3570`), stored at `:4700-4711`.
- **TOP1M** optional Alexa list — loaded into `whiteDB` at query time (a fixed, non-subscribable
  list).

The precedence decision is one line: `_resolve_numeric_allow()` returns `allow_band >= block_band`
(`pfb_unbound.py:5436`). **Bands** (high beats low): `6` manual whitelist; `5` user block
`$important`; `4` feed allow `$important`; `2` feed allow (`@@`); `1` feed block. So a feed allow
(band 2) overrides a feed block (band 1) but loses to the operator's manual whitelist (band 6).

### 1.2 The feed download pipeline (the rails a DNSWL feed would ride)

- DNSBL feed rows live in the **dynamic** section `installedpackages/pfblockerngdnsbl/config`
  (per-row `state`, `url`, `header`, `logging`, `format`, `custom`;
  `pfblockerng_category_edit.php:254-256`, `:433-437`). It is **not** in the `PfbConfig` registry —
  it is a dynamic per-row list (a foreign/section-level structure; CLAUDE.md foreign-key list).
- The DNSBL update loop `pfblockerng.inc:11054-11191` iterates those rows, calls
  `pfb_download($row['url'], …)` (`:11165`) → `{header}.orig` (`$pfb['dnsorigdir']`,
  `/var/db/pfblockerng/dnsblorig`), and stages an IP-stripped raw feed under
  `$pfb['unbound_py_rawdir']` = `/var/unbound/pfb_py_raw` (`:115`).
- The **manifest boundary**: PHP writes `/var/unbound/pfb_py_sources.json`
  (`$pfb['unbound_py_sources']`, `:108`) via `pfb_unbound_py_atomic_write()` (`:4784`); each feed
  entry carries `header`, `group`, `log`, `format`, `provenance`. Python reads it in
  `dnsbl_build_from_manifest()` (`pfb_unbound.py:399`) and builds `data_db`/`zone_db`/`white_db`.
  **All ABP/allow parsing happens on the Python side** (ADR-06 moved preprocessing into Python); PHP
  stages raw feeds + the manifest.
- Downloads run on the existing pfBlockerNG update/cron pass — **there is no per-feed cron**; a new
  feed type that rides this pipeline is downloaded on the same schedule for free.

### 1.3 What does NOT exist (confirmed)

No subscribable standalone **allow** feed. `pfblockerngdnsbl/config` rows have no allow/permit type;
there is no DNSWL config section, no allow-feed download branch, no allow-feed UI. The IP-side
`$pfb['permitdir']` (`/var/db/pfblockerng/permit`) is unrelated (IP permit lists, not DNS). The only
allow paths are the three in §1.1.

### 1.4 Premise check (this is NOT an ADR-01-style bet)

No performance premise — a permit feed adds entries to the same `whiteDB` already consulted per
query; the marginal cost is a few more dict entries, unmeasurably cheap. The justification is
**functional**: let operators subscribe to a remote allow-list to counter blacklist false-positives
(issue #324). The risk to weigh is **scope** (a config section + UI + pipeline wiring + a Python
build branch + a precedence semantic) and **safety of the precedence choice** — both contained by
the phasing (§6), the pinned contract tests (§2.2), and the explicit reject path (§7).

## 2. Decision

Model a subscribed DNSWL feed as **"a feed every host line of which is an implicit `@@||host^`
allow."** It rides the **existing** DNSBL download/manifest/build pipeline; the novelty is confined
to a new **`mode`** dimension (`deny` default | `permit`) carried across the manifest and a build
branch that loads a `permit` feed's hosts into `whiteDB` at **band 2** (feed-allow — the same band as
an ABP `@@` allow). Three settled forks (issue #324 maintainer decisions):

- **Precedence = band 2 (feed-allow).** A subscribed allow overrides **block feeds** (the point —
  counter false-positives) but the operator's **manual whitelist (band 6)** and manual `$important`
  block (band 5) still win. A remote third-party list can never un-block what the operator
  *explicitly* blocked. Reuses the existing band exactly — no new resolver, no new band.
- **Config = a per-row `Deny`/`Permit` action on the existing DNSBL feed rows**
  (`pfblockerngdnsbl/config`), mirroring the **IP side's per-list `Deny`/`Permit`/`Match` action**
  (CLAUDE.md "follow the established pattern"). Default `Deny` ⇒ a `permit` row is purely additive;
  no new config section, no new download loop, **no new shipped page**.
- **Entry semantics = every host is an allow** (v1). In a `permit` feed every plain / hosts-file /
  `||host^` line yields a **subdomain-covering** allow (like `@@||host^`); ABP `@@` lines and
  block-only directives inside a permit feed are **ignored** (documented). No mixed ABP semantics in
  v1.

### 2.1 Per-area decision table

| Area | Decision |
| --- | --- |
| **Config field** | A per-row **`action`** field on the existing `pfblockerngdnsbl/config` rows: `Deny` (default / absent) or `Permit`, mirroring the IP-side per-list action. Dynamic per-row key ⇒ **not** in the `PfbConfig` registry (foreign/section-level, like its DNSBL siblings `custom`/`logging`); read via direct `config_*_path`. No new section. |
| **Manifest field** | Add **`mode`** to each manifest feed entry: `'deny'` (default, **absent ⇒ deny** — backward-safe) or `'permit'`. The single new value crossing the boundary. A `Permit`-action row emits `mode='permit'`. |
| **PHP download/stage** | The existing DNSBL loop (`:11054-11191`) reads each row's `action`; for a `Permit` row it calls the Phase-3 manifest-row seam with `mode='permit'` (the only structural difference vs a deny row). Permit rows stage raw feeds under the same `pfb_py_raw` / `dnsdir`, on the same download path + schedule. No second loop. |
| **Python build** | In `dnsbl_build_from_manifest()`, a feed entry with `mode=='permit'` routes **every host line** of its raw feed into `whiteDB` as a **band-2 wildcard allow** (the existing `@@\|\|host^` store/shape at `:4700-4711`), ignoring ABP directives. `mode` absent/`'deny'` ⇒ today's block build, byte-identical. Provenance tags the allow so reports can attribute it. |
| **Precedence** | **Unchanged resolver.** Permit entries are band 2; `_resolve_numeric_allow()` (`:5436`) already returns `allow_band >= block_band` ⇒ band 2 beats band 1 (block feeds), loses to band 5/6 (manual). No code change to the resolver. |
| **Subdomain semantics** | Subdomain-covering (`wildcard=True`), matching `@@\|\|host^` — `allow.example.com` permits `example.com` and `*.example.com`. |
| **UI** | A `Deny`/`Permit` **action select** added to the existing DNSBL feed-row editor (`pfblockerng_category_edit.php`) — no new page, no menu/tab/privilege change, nothing new to ship in `pkg-plist`. Brief help text stating the band-2 precedence (manual whitelist/blocks still win). Optionally surface the action in the feed grid column. |
| **Schedule / cron** | **None added.** Permit feeds download on the existing pfBlockerNG update pass alongside block feeds. |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before wiring)

1. **`mode` absent / `'deny'` ⇒ zero behaviour change.** A manifest with no permit feed builds
   `data_db`/`zone_db`/`white_db` byte-for-byte as today; existing ABP `@@` band-2/4 semantics are
   untouched.
2. **A permit-feed host overrides block feeds:** a domain on a `permit` feed **resolves** even when a
   block feed lists it (band 2 > band 1). Pinned both ways (listed-on-block-only ⇒ blocked;
   also-on-permit ⇒ resolves).
3. **The operator still wins:** the **manual whitelist (band 6)** and a manual `$important` block
   (band 5) take precedence over a permit feed (band 2). A permit feed can NOT un-block a domain the
   operator manually blocked.
4. **Subdomain-covering + per-feed independence:** a permit entry covers the host + subdomains; a
   non-listed domain is entirely unaffected; one permit feed never perturbs another feed's entries.
5. **Manifest back-compat:** an older Python reading a newer manifest (or vice-versa) treats absent
   `mode` as `deny`; no novel required field — the field is additive and optional.

### 2.3 Explicitly kept / out of scope

- **Mixed ABP semantics inside a permit feed** (honoring `@@`/`||`/`$important` per line) — out (v1:
  every host = allow). Revisit if operators need it.
- **Per-feed sovereignty / "important" toggle** (band 4/6) — out; band 2 only. The manual whitelist
  remains the only sovereign allow.
- **A new cron/schedule** — out; rides the existing update pass.
- **The IP-side permit lists** (`$pfb['permitdir']`) — unrelated, untouched.
- **The manual suppression list and TOP1M** — untouched; permit feeds are additive.

### 2.4 Alternatives considered (and why rejected)

- **Band 6 (sovereign) for subscribed feeds:** lets a remote third-party list override the
  operator's own manual blocks — a safety inversion. Rejected: the operator's explicit decisions
  must win (issue #324 fork → band 2).
- **A separate DNSWL / Allow-feeds section + page** (instead of the per-row action): cleaner
  conceptual separation, but duplicates the feed grid/editor, the download loop, and — critically —
  adds **new shipped `.php` pages** that must be registered in `pkg-plist` (an omitted plist entry
  ships nothing → the page 404s on the box; this bit the first implementation). Rejected: the per-row
  action mirrors the IP-side `Deny`/`Permit`/`Match` pattern, ships no new file, and is less surface
  (issue #324 fork → per-row action).
- **PHP-side allow parsing / a separate allow store:** duplicates the ABP allow machinery that
  already exists in Python (`whiteDB`, band 2). Rejected — reuse it; PHP only stages + flags `mode`.

## 3. Consequences

**Positive**

- Operators can subscribe to remote allow-lists to counter blacklist false-positives (issue #324),
  on the existing download schedule, with no new cron.
- Reuses the proven ABP allow store + the single precedence resolver — no new band, no new resolver,
  minimal new Python.
- Backward-safe by construction: absent `mode` ⇒ deny ⇒ existing installs build identically.
- The safety-critical precedence (operator always wins) is pinned by tests before any wiring.

**Negative / risks**

- A per-row config field + one UI select + a Python build branch + a manifest field — modest surface,
  contained by riding the existing DNSBL grid/editor/loop and by the phasing.
- A permit feed **can** un-block domains other block feeds list (by design) — an operator who adds a
  careless allow-list could weaken blocking. Mitigated by band 2 (manual blocks/whitelist still win)
  and called out in help text.
- The manifest gains an optional field; old/new skew must treat absent as `deny` (§2.2.5) — pinned.

## 4. Requirements (acceptance)

- A **DNSWL / Allow Feeds** page where an operator adds remote allow-list feed rows (header/url/state)
  parallel to DNSBL block feeds, downloaded on the existing update pass.
- A domain on an enabled permit feed **resolves** even when a block feed lists it; a domain only on a
  block feed stays blocked; the manual whitelist and manual blocks still win over a permit feed.
- Permit entries are subdomain-covering; non-listed domains unaffected.
- No permit feed configured ⇒ behaviour byte-identical to today.
- All gates green; the §2.2 contract pinned by tests.

## 5. Constraints (from CLAUDE.md)

- **Python:** 4-space indent, 3.11+, `from __future__ import annotations`; **stdlib only** inside
  Unbound's loader; no bare `except`. `pfb_unbound.py` is chrooted at `/var/unbound` — raw feeds must
  be read by chroot-relative paths (the existing `pfb_py_raw` staging already is).
- **PHP:** 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()/exit()` in library code. A new **registered
  scalar** (if any) goes through `PfbConfig` (ADR-29) with its `since`, sniff `$registeredPaths`, and
  `CfgGatewayTest`/`RollbackContractTest`; a **dynamic per-row section** stays on direct
  `config_*_path` (foreign-key exclusion, like `pfblockerngdnsbl`). Keep PFBL-01 (`RequirePfbFilter`)
  green — feed header/url handling is an input surface (`pfb_filter()`/`pfb_sanitise_feed_header()`).
- **Manifest:** additive, optional `mode`; absent ⇒ `deny` (ADR-28 storage-freeze spirit — no
  existing field changes meaning).
- **Test-coverage mandate:** every branch (mode deny/permit; allow-beats-block-feed
  vs manual-beats-allow; subdomain; non-listed), assert before-and-after, no coverage theater.
- **No live Unbound in CI** except the ADR-04 smoke VM; the off-box pytest suite exercises the build
  functions, the PHPUnit suite loads the real `.inc` via shims/doubles.
- ADR implementation uses the full worktree + rebase-only-PR flow (it touches `src/`+`tests/`).

## 6. Action plan

> Each phase is one commit and leaves `python -m pytest` + `vendor/bin/phpunit` green. The early
> phases are the **behaviour-preserving, test-first groundwork** — pin the precedence contract as an
> oracle and extract the PHP manifest-row seam — *before* the permit build branch and the per-row
> action are wired. The Python build branch (Phase 2) is dormant until a manifest actually carries
> `mode='permit'` (Phase 4); the UI select (Phase 5) lands after the engine works.

### Phase 1 — Pin the allow-precedence contract (oracle; behaviour-preserving)

- Prompt: `01_Precedence_Oracle.txt`
- **No production change.** Add pytest coverage that pins TODAY's band semantics as the oracle the
  feature relies on: an ABP `@@||host^` allow (band 2) **resolves a domain a block feed lists**, the
  **manual suppression (band 6) still wins** over a band-2 allow, and a non-listed domain is
  unaffected — using the existing `dnsbl_build_from_manifest()` + matcher entry points. Assert
  before-and-after (block-only ⇒ blocked; +allow ⇒ resolves). This is the regression net for
  Phases 2/4; it must pass on untouched `devel`.

### Phase 2 — Python: `permit`-mode build branch → `whiteDB` band 2

- Prompt: `02_Python_Permit_Build.txt`
- In `dnsbl_build_from_manifest()`, when a manifest feed entry has `mode=='permit'`, route **every
  host line** of its raw feed into `whiteDB` as a band-2 wildcard allow (reuse the `@@||host^`
  store/shape at `:4700-4711`), ignoring ABP directives; tag provenance so reports can attribute it.
  `mode` absent/`'deny'` ⇒ unchanged build. pytest: a synthetic manifest with a permit feed →
  host in `whiteDB` at band 2 → resolves despite a co-listing block feed; manual suppression still
  sovereign; absent-`mode` build byte-identical (reuse the Phase-1 oracle). **Dormant** — no PHP
  emits `mode='permit'` yet.

### Phase 3 — PHP: extract the reusable feed download/stage seam (behaviour-preserving)

- Prompt: `03_Php_Download_Seam.txt`
- Extract the per-row download + raw-stage + manifest-entry body of the DNSBL loop
  (`pfblockerng.inc:11054-11191`) into a function parameterised by **section + `mode`**, defaulting
  to today's deny behaviour; the existing DNSBL loop calls it with `mode='deny'`. **Behaviour-
  preserving**: the manifest for an unchanged config is byte-identical (no `mode` key, or `mode`
  omitted when deny — decide and pin). PHPUnit pins the extracted seam's manifest-entry output for a
  deny row. Keep PFBL-01 + `RequireConfigGateway` green.

### Phase 4 — PHP: the per-row `Permit` action → `mode='permit'` wiring

- Prompt: `04_Php_Permit_Action.txt`
- In the existing DNSBL feed loop (`pfblockerng.inc:11054-11191`), read each row's per-row `action`
  (`Deny` default / `Permit`); for a `Permit` row pass `mode='permit'` to the Phase-3 manifest-row
  seam and propagate `mode='permit'` into the manifest JSON entry. No new section, no second loop,
  no new global scalar. The per-row `action` key stays on direct `config_*_path` (foreign-key
  exclusion, like the sibling per-row `custom`/`logging`). Feed header/url validation reuses the
  input-handling contract (PFBL-01 green). PHPUnit: a `Permit` row produces a `mode='permit'`
  manifest entry, a `Deny`/absent row stays byte-identical; **this connects Phase 2's dormant branch**.

### Phase 5 — UI: the `Deny`/`Permit` action select on the DNSBL feed editor

- Prompt: `05_Ui_Permit_Action.txt`
- Add a `Deny`/`Permit` action `Form_Select` to the existing DNSBL feed-row editor
  (`pfblockerng_category_edit.php`), default `Deny`, round-tripping to the per-row `action` key Phase 4
  reads; help text stating the band-2 precedence (manual whitelist/blocks still win). **No new page,
  menu, privilege, or `pkg-plist` entry.** `ui_render` (Tier A) proof: the existing DNSBL editor page
  still GET 200, no PHP error/notice, marker present, the new select renders and a saved row carries
  `action='Permit'`.

### Phase 6 — Smoke + validation + docs

- Prompt: `06_Smoke_And_Docs.txt`
- Live-VM smoke (ADR-04 + ADR-16 mock feed server): configure a block feed + a permit feed via mock
  URLs; assert a domain on **both** resolves (allowed), a domain only on the block feed is blocked,
  the manual whitelist/manual block still win over the permit feed, and a non-listed domain is
  unaffected — every assertion before-and-after. Add the §7 manual checklist; update user-facing
  docs/help. Flip Status → Accepted on green fan-out (CE + Plus).

## 7. Definition of done

- All six phases landed; `python -m pytest` + `vendor/bin/phpunit` + `phpcs` + `phpstan` +
  `ui_render` green; the §2.2 contract pinned.
- Live-VM smoke (CE + Plus fan-out) green for: permit-overrides-block-feed, block-feed-still-blocks,
  manual-whitelist/block-still-wins, subdomain-covering, non-listed-unaffected, and absent-`mode`
  no-op.
- **Manual smoke checklist (owner: maintainer — out-of-CI confirmation on a real box):**
  1. Add a DNSWL feed (small public allow-list or a mock URL) and a block feed that lists one of its
     domains; update; confirm that domain **resolves** while a block-only domain is blocked.
  2. Manually block (DNSBL custom/manual) a domain that the permit feed allows; confirm the **manual
     block wins** (still blocked). Manually whitelist a block-fed domain; confirm it resolves.
  3. Remove the permit feed; update; confirm the previously-allowed block-fed domain is blocked again
     (clean teardown, no residue in `whiteDB`).
  4. Confirm a permit entry `example.com` also allows `sub.example.com`.

**Reject criteria.** Abandon/redesign if: (a) `permit` entries cannot be expressed as band-2
`whiteDB` allows without disturbing existing ABP `@@` band-2/4 semantics (Phase 1's oracle must stay
green through Phase 2); or (b) the precedence cannot be kept safe — i.e. a permit feed can be shown
to override the operator's manual whitelist or manual `$important` block (§2.2.3 fails); or (c)
absent-`mode` back-compat (§2.2.1/§2.2.5) cannot be guaranteed byte-identical. (The three forks —
band 2, per-row `Deny`/`Permit` action, every-host-allow — are **settled** maintainer decisions for
issue #324.)
