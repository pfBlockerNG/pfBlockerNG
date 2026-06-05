# ADR-16: Feeds page IPv4/IPv6/DNSBL tabs + live mock-feed load smoke

- **Status:** **Proposed** (2026-06-05)
- **Date:** 2026-06-05
- **Branch:** `adr/16` (off **`devel`**) / **Component(s):**
  `src/usr/local/www/pfblockerng/pfblockerng_feeds.php` (the split + the type-scoped
  save — the only `src/` change); `tests/smoke/ui/test_render_smoke.py` /
  `tests/smoke/ui/test_feeds.py` / `tests/smoke/ui/test_browser_misc.py` (retarget to
  the typed URLs + the cross-type non-clobber test); **reused, not modified:**
  `tests/smoke/conftest.py` (`_MockFeedServer`/`mock_feeds`), `tests/smoke/helpers.py`
  (`IpCase`/`DnsblCase`/`inject`/`reload`/`pfctl_table_members`/`rule_references`/
  `dns_probe`/`CaseContext`); new `tests/smoke/fixtures/` sample feeds + new
  `tests/smoke/test_smoke_feeds.py`.
- **Target runtime:** PHP 8.3 (the Feeds page, inside pfSense); the smoke is dev/CI-only
  Python 3.11+ (pytest) driving the ADR-04 live pfSense CE VM. **One** shipped file
  changes (`pfblockerng_feeds.php`); no parser/`.inc`/`.sh`/`pfb_unbound.py` change.
- **Test suite:** the ADR-14 UI tiers (`ui_render`/`ui_e2e`/`ui_browser`, `tests/smoke/ui/`)
  for Part A; a new live-VM `tests/smoke/test_smoke_feeds.py` (`-m smoke`) for Part C.
  **Default `python -m pytest` stays unchanged** (the whole `tests/smoke` tree is
  `--ignore`d in default collection). No `pytest` oracle for the PHP itself (it only
  runs inside pfSense) → validation = the live-VM assertions in §7 + a manual review.

---

## 1. Context

### Today (verified on `devel` @ 1d92345)

1. **One Feeds page renders all three types.** `pfblockerng_feeds.php` builds
   `$feeds_list['ipv4'] / ['ipv6'] / ['dnsbl']` (`:39`) and renders, in one view: a
   **Feed Settings** `Form_Section` of alias-name override inputs for IPv4/IPv6/DNSBL
   (`:246-306`) and a **predefined-feeds table** from `$feed_info = convert_feeds_json()`
   (`:33`) grouped by `$ftype` (`:420+`). It is one top tab among
   General/IP/DNSBL/Update/Update Hooks/Reports/**Feeds**/Logs/Sync (`$tab_array` `:230-240`,
   `display_top_tabs` `:240`). Counts: **IPv4 17 groups / 88 feeds, IPv6 8 / 10, DNSBL 21 / 134.**
2. **The save handler is type-blind AND resets absent fields.** The
   `isset($_POST['save'])` block loops **all** types
   (`foreach ($pfb['feeds_list'] as $type => $data)`, `:74`) and writes each rename with
   `$fconfig['feed_'.$l] = $_POST['feed_'.$l] ?: ''` → `config_set_path('installedpackages/
   pfblockerngglobal/feed_'.$l, …)` (`:85-86`). **An absent field is written as `''`.** The
   alt-URL block (`feed_alt_<header>`) is gated on `isset($_POST['alt_selected'])` (`:102`)
   and loops that hidden CSV (`:104-114`). → **A per-type tab that POSTs only its own fields
   would reset every other type's rename to empty.** This is the load-bearing trap (§Decision).
3. **The sub-tab idiom already exists — copy it.** `pfblockerng_category.php` reads
   `$_GET['type']` (`:49-51`), builds an `$active` map via a `switch` (`:92-118`), and calls
   `display_top_tabs` **twice** — the main top bar (`:335-345`) **plus a second sub-tab row**
   (`~:347-360`: IPv4/IPv6/GeoIP/Reputation, or DNSBL Groups/Category/SafeSearch), with the
   breadcrumb Firewall ▸ pfBlockerNG ▸ IP|DNSBL ▸ `<type>` (`:327`). `_category_edit.php` and
   `_alerts.php` (Reports, via `?view=`) do the same. **No new tab mechanism is needed.**
4. **The live-VM mock HTTP feed server already exists.** `_MockFeedServer`
   (`tests/smoke/conftest.py:374-463`, stdlib `ThreadingHTTPServer`) serves arbitrary content
   to the guest via `.register(name, content) → guest_url()`, reachable at
   `http://10.0.2.2:<port>/<name>` over SLIRP; the `mock_feeds` fixture (`:816-833`) stands it
   up and sets `SmokeVM.feed_base_url`. ADR-12's smoke already uses it (+ `_StubDnsServer`,
   `_MockCallbackSink`, and `use_system_dns_upstream` wiring System-DNS → `10.0.2.2`). →
   **Part B does NOT build a server — it generates sample feeds and registers them.**
5. **The whole IP/DNSBL load-and-assert path exists but is never driven over HTTP.**
   `IpCase`/`DnsblCase(feed_url=…)` (`helpers.py:161/216`), `inject` (`:1104`), `CaseContext`
   (`:2198`, inject→reload→probe→reset), `reload(scope)` (`:1242`), and the asserts —
   `pfctl_table_members`/`rule_references` (IP, `:1944/:1959`), `dns_probe`+`is_vip`/`is_null_ip`/
   `resolves_to`+`stub_dns.received` (DNSBL, `:1779/:1884`) — all exist. **Every current case
   feeds a LOCAL file** (`write_local_feed`, `:334`); the helper even notes local files are
   "more reliable in CI than the HTTP mock fetch". → **The HTTP-fetch path is built but
   untested; that is the gap Part C closes (and the reliability caveat is its kill-gate).**
6. **The curl fetch contract** (`pfblockerng.inc ~:4863-4930`): requests `gzip`, a pfBlockerNG
   `User-Agent`, **follows redirects**, captures `Last-Modified`/filetime for reuse, but sends
   **no** `If-Modified-Since` (no 304) and **ignores** `Content-Disposition`/`Content-Type`. →
   The mock server only needs to serve the body (the existing handler does); headers/disposition
   don't matter — so a sample feed is just a file with the right line shape.
7. **Feed formats** (catalogued for the sample set): **IP** = plain IP/CIDR, ranges, IPv6
   (format `auto`); CSV/iblocklist; regex; (geoip/asn/whois/rsync need egress/binary).
   **DNSBL** = plain-domain, hosts (`0.0.0.0 d`), ABP/EasyList (`||d^`, `@@`), CSV variants.
   The per-feed `header`/`format` come from `pfblockerng_feeds.json` / the `category_edit`
   source row.

> Line numbers are as-of-authoring (and `pfblockerng_feeds.php` drifted slightly under the
> `9465806` `$input_errors` PHPStan fix) — **symbols are the reliable handle**; grep them.

### Premise to falsify cheaply (the ADR-01 guard)

- **Part A (UI split) — verified, low risk.** The save can be type-scoped (carry the active
  `type` in a hidden field; loop only `$pfb['feeds_list'][$type]`; the `alt_selected` CSV is
  already naturally scoped to the rendered type). Confirmed by reading the handler — no costly
  spike needed. **Reject only if** the shared `alt_selected`/`feed_alt` logic can't be scoped
  cleanly (then rethink the UI approach).
- **Part C (HTTP-feed load smoke) — the real falsifiable premise.** Does a pfBlockerNG **Force
  Update** reliably **fetch an HTTP feed from the mock over SLIRP and load it**, in CI? The
  pieces are individually proven (the server, the curl path, the load+assert helpers, the
  System-DNS→mock wiring) but **never composed for a feed fetch** — and the harness chose local
  files partly for HTTP-fetch reliability (fact 5). → **Phase 5 falsifies this first** with a
  single IP + single DNSBL HTTP-feed case before the format matrix; if it can't reach the §7
  reliability bar, demote Part C to dispatch-only (local-file load coverage already exists) —
  Part A still ships. This is the kill-gate, decided on first CI evidence.

---

## 2. Decision

Split the Feeds page into **IPv4 / IPv6 / DNSBL sub-tabs** (`?type=`, default `ipv4`),
mirroring `pfblockerng_category.php` exactly, and **type-scope the save handler** so a tab
only ever writes its own type's nodes. Then add **representative sample feeds** served by the
**existing** `_MockFeedServer` and a **live-VM smoke** that adds them, runs Update/Force-Reload,
and asserts the feeds load — exercising the real HTTP-fetch path the suite has never covered.

| Area | Decision |
| --- | --- |
| **A1 — sub-tabs** | Read `$_REQUEST['type']` (`ipv4` default \| `ipv6` \| `dnsbl`); build an `$active` map; keep the **Feeds** top tab active; add a **second `display_top_tabs` row** `[IPv4 \| IPv6 \| DNSBL]` pointing at `pfblockerng_feeds.php?type=…`; breadcrumb ▸ Feeds ▸ `<type>`. Direct copy of the `category.php` pattern (Context 3). |
| **A2 — type-filtered body** | The Feed Settings alias-name section and the predefined-feeds table render **only the current type** (one of `$feeds_list[$type]` / `$feed_info[$type]`). |
| **A3 — type-scoped save (THE fix)** | Carry the active `type` in a hidden form field; the save loops **only `$pfb['feeds_list'][$type]`** for renames, and the `alt_selected` CSV is naturally scoped to the rendered type. Saving one tab **never** touches another type's `feed_*` / `feed_alt_*` nodes. (Closes the Context-2 clobber.) |
| **A4 — self-links** | Form `action`, the post-save redirect (`:127`), `$pglinks` (`:220`), and the page's own `$tab_array` entry (`:237`) preserve the active `?type`. **Other pages' "Feeds" links stay bare** (→ default `ipv4`), exactly as the top IP/DNSBL tabs link to their canonical pages without `?type` → **no edits to the other ~12 pages.** |
| **B — sample feeds** | Author representative fixture feeds for the supported formats (Context 7): **IP** {plain IP+CIDR, range, IPv6} and **DNSBL** {plain-domain, hosts, ABP/EasyList}. Inert content only (TEST-NET / `uuid`-style names). Served via `_MockFeedServer` (`fixtures/` dir or `.register()`). **No new server.** |
| **C — live load smoke** | New `tests/smoke/test_smoke_feeds.py`: per representative format, `mock_feeds.register(...)` → `IpCase`/`DnsblCase(feed_url=<mock URL>)` → Update/Force-Reload → assert load. IP: `pfctl_table_members(alias)` membership + `rule_references`. DNSBL: `dns_probe` block-shape (+ `stub_dns.received` to prove blocked-locally vs forwarded). One case proves the HTTP path first (kill-gate); the rest extend coverage. |

### Semantics that MUST be preserved (the contract — pin with tests with the change)

- **No save regression / no clobber.** Every rename (`feed_<alias>`), alt-URL
  (`feed_alt_<header>`), and alias-name override that persisted on the single page still
  persists from its type's tab; **saving one type never mutates another type's nodes** (the new
  guarantee — pinned by a cross-type non-clobber `ui_e2e` test in Phase 3, with the pre-split
  per-type save oracle pinned in Phase 2).
- **Render parity.** Each `?type` view render-smokes clean (the ADR-14 Tier-A oracle: 200 + no
  PHP diagnostic + a type-specific marker + no new `php_error.log`) showing **only** that type's
  predefined feeds.
- **Bare URL still works.** `pfblockerng_feeds.php` with no `?type` defaults to `ipv4` and
  renders/saves correctly (the other pages link to it bare).
- **Default suite untouched.** `python -m pytest` stays unchanged (smoke tree `--ignore`d).
- **No parser change.** `.inc`/`.sh`/`pfb_unbound.py` feed parsing is unchanged — formats are
  inputs to the smoke, not modified.

### Explicitly kept / out of scope

- **A new HTTP server** — out; reuse `_MockFeedServer` (Context 4).
- **Feed-parser changes** — out; formats are inputs.
- **Egress/binary formats in the hermetic smoke** (geoip/asn/whois/rsync) — out; they need
  MaxMind/egress. The smoke set is the body-only HTTP formats.
- **Editing the other ~12 pages' Feeds tab links** — out (A4: bare links default to `ipv4`).
- **The broader "official AdGuard-style feeds / settings reorg" (GH issue #45)** — out; this
  ADR is the tab split + load smoke only (it is plausibly a first step toward #45).
- **Splitting the Feeds top tab into two top tabs** — out; one Feeds top tab + a sub-tab row,
  matching IP/DNSBL/Reports.

---

## 3. Consequences

**Positive**

- Feeds gains the same clear IPv4/IPv6/DNSBL organization as IP/DNSBL/Reports — less scrolling,
  type-scoped editing.
- The **type-scoped save** removes a latent foot-gun (the type-blind `?: ''` reset) and is the
  thing that makes the split safe.
- **Closes a real test gap:** the HTTP feed-fetch path (curl over the network into the matcher)
  finally has live coverage, across representative formats — and validates the curl contract
  (gzip/redirects/no-304) end-to-end.
- **Reuses existing infra** (the mock server, the load/assert helpers, `CaseContext`) → small new
  surface, consistent with the ADR-04/12 harness.
- Part A and Part C are **independently valuable**: Part A ships even if Part C is later demoted.

**Negative / risks**

- **HTTP-mock-fetch reliability in CI** (Context 5 caveat) — the Part-C kill-gate; mitigated by
  falsifying with one case first + the demote-to-dispatch switch (§7).
- **PHP refactor risk** in a 849-line procedural page — mitigated by the behaviour-preserving
  extraction (Phase 1) + the pinned save oracle (Phase 2) before the split (Phase 3).
- **No automated oracle for the PHP rendering itself** (runs only in pfSense) → a human eyeballs
  the 3 tabs (manual smoke, §7).
- **Sample-feed realism** — generated from the format catalogue, not live feeds; mitigated by
  matching real line shapes (Context 7) and the maintainer optionally seeding real samples.

---

## 4. Requirements (acceptance)

1. **UI split:** `pfblockerng_feeds.php?type=ipv4|ipv6|dnsbl` renders a second sub-tab row + only
   that type's Feed Settings + predefined feeds; bare URL defaults to `ipv4`; the Feeds top tab
   stays active; breadcrumb shows the type.
2. **Type-scoped save (no clobber):** saving one type's tab persists that type's renames/alt-URLs
   and leaves the other types' nodes **unchanged** — pinned by a cross-type non-clobber test.
3. **Render parity:** each `?type` view passes the Tier-A oracle with a type-specific marker.
4. **Sample feeds:** representative fixtures exist for the supported IP + DNSBL body formats.
5. **HTTP-feed load smoke:** an IP feed and a DNSBL feed served over the mock load via Force
   Update and are asserted on the box (pfctl table / dns_probe), reliably (§7 bar) — or Part C is
   demoted with the gap recorded.
6. **Default suite unchanged; lint-clean:** `python -m pytest` unchanged; `ruff`/`php -l`/
   ShellCheck clean; the ADR-14 UI tiers updated to the typed URLs stay green.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code, pfSense fns via stubs; keep
  `Form_Section` ids / field names / config keys stable for display-only edits (only the
  type-scoping changes save behaviour). PHPStan must stay green (the page has baseline entries).
- **Python (smoke):** 4-space, 3.11+, type hints, no bare except; reuse the existing fixtures/
  helpers — do **not** add a second VM boot path or a second HTTP server. Tests carry the right
  marker (`ui_*` for Part A, `smoke` for Part C) and stay out of default collection.
- **Test coverage rule:** every flow is a transition test (assert the before-state, prove the
  POST/update caused the change) with branch coverage (accept **and** reject / each type), and
  leaves the session VM clean (restore in `finally` / `CaseContext` reset).
- **Investigation rigor:** assert effective state — `config.xml` via `helpers.config_get`, the pf
  table via `pfctl`, DNS via on-box `drill` — never the HTTP response alone.
- Commit style `<scope>: <imperative summary>`; **work in this ADR's `adr/16` worktree (reuse it
  across phases; create off the latest `origin/devel` if absent), one commit per phase**; `git
  fetch` + rebase onto the latest `origin/devel` before every push. Phases that touch `src/` or
  `tests/` land on `devel` via a **rebase-only PR** (the ADR docs themselves push direct to
  `devel`, no PR — the CLAUDE.md carve-out); the UI/smoke PRs carry the `ui-tests` label so the
  live-VM suite validates them. PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md updated when the Feeds-page UX / the smoke feed-set changes (final phase).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` unchanged/green and the tree lint-clean. The
**behaviour-preserving prep (Phases 1–2)** lands before the **split + save fix (Phase 3)**; Part A
(Phases 1–3) ships independently of Part C (Phases 4–5), whose HTTP-feed premise is **falsified at
the head of Phase 5** before the format matrix.

### Phase 1 — PREP (behaviour-preserving): extract per-type rendering helpers

Prompt: `01_Extract_Render_Helpers.txt`

- Refactor `pfblockerng_feeds.php` so the Feed Settings alias-name section and the predefined-feeds
  table are produced by **functions keyed by type** (a `$type` parameter), with the page still
  rendering all three types (call them for ipv4+ipv6+dnsbl). **No UX change, no save change** —
  pinned by the existing Tier-A render entry. Makes Phase 3's type-filtering a one-line argument.

### Phase 2 — PREP (test-first): pin the CURRENT save semantics

Prompt: `02_Pin_Save_Oracle.txt`

- Extend `tests/smoke/ui/test_feeds.py` to assert the **current** per-type save persists — a DNSBL
  rename and an IPv6 rename round-trip to `config.xml` on the single page (paired valid/invalid),
  the oracle Phase 3's type-scoped save must keep green. (The cross-type non-clobber case is added
  in Phase 3 — it only exists once the split makes a partial POST possible.)

### Phase 3 — The split + type-scoped save + test retarget

Prompt: `03_Split_And_Scoped_Save.txt`

- Add `?type` + the second sub-tab row (copy `category.php`) + type-filtered sections (call the
  Phase-1 helpers for the active type only); **type-scope the save** (hidden `type` field; loop
  only `$pfb['feeds_list'][$type]`); self-links preserve `?type` (A4). Update
  `test_render_smoke.py` PAGE_TABLE → `feeds_ipv4`/`feeds_ipv6`/`feeds_dnsbl` (+ markers) and the
  coverage guard; retarget `test_feeds.py`/`test_browser_misc.py` to the typed URLs; **add the
  cross-type non-clobber `ui_e2e` test** (save IPv4 tab → DNSBL renames intact, and vice-versa).
  **Part A ships here.**

### Phase 4 — Sample feeds (fixtures)

Prompt: `04_Sample_Feeds.txt`

- Author representative inert sample feeds for the supported body formats: IP {plain+CIDR, range,
  IPv6}, DNSBL {plain-domain, hosts, ABP/EasyList}. Place under `tests/smoke/fixtures/` (served by
  `_MockFeedServer`). Document each file's format. No test wiring yet.

### Phase 5 — Live HTTP-feed load smoke (falsify first, then expand)

Prompt: `05_Feed_Load_Smoke.txt`

- **Kill-gate first:** one IP + one DNSBL feed served via `mock_feeds.register()` (or the
  `fixtures/` dir) → `IpCase`/`DnsblCase(feed_url=<mock URL>)` → Force Update → assert load
  (`pfctl_table_members`/`rule_references`; `dns_probe` block-shape). Confirm it's reliable (§7
  bar). **Only then** extend to the remaining representative formats. If the HTTP path can't hit
  the bar, **demote** Part C to dispatch-only and record it (local-file load coverage already
  exists). New `tests/smoke/test_smoke_feeds.py`, marker `smoke`.

### Phase 6 — Docs + DoD + manual smoke

Prompt: `06_Docs_DoD.txt`

- Update README/CLAUDE.md (the Feeds-page tabs; the smoke feed-set + how to add a format).
  Finalise §7 manual smoke + reject criteria; set Status after the maintainer confirms.

---

## 7. Definition of done

- `python -m pytest` unchanged; `ruff`/`php -l`/ShellCheck/PHPStan clean; the ADR-14 UI tiers
  (retargeted to the typed URLs) green.
- `pfblockerng_feeds.php` serves IPv4/IPv6/DNSBL sub-tabs; the save is type-scoped; the cross-type
  non-clobber test + the 3 `?type` render entries are green on the live VM.
- The HTTP-feed load smoke is green for the representative formats (or Part C is demoted to
  dispatch-only with the gap recorded).
- Status flips **Proposed → Implemented (pending smoke test)** once the above hold on `adr/16`; it
  flips to **Accepted** only after the maintainer completes the manual smoke below.

### Reject / demote criteria (decide on evidence)

- **Save can't be type-scoped cleanly** (the shared `alt_selected`/`feed_alt` logic resists
  scoping) → reconsider the UI approach (e.g. keep a single shared Feed Settings section, split
  only the predefined-feeds table) before committing Phase 3. Settle by reading + the Phase-2 oracle.
- **HTTP-feed load smoke too flaky/slow** (the Context-5 caveat realised): if the Phase-5 kill-gate
  case can't reach **≥ 4/5 clean** at a sane per-leg budget, **demote** `test_smoke_feeds.py` to
  **dispatch-only** (drop it from the gated smoke set) — Part A still ships and local-file load
  coverage remains. Record the numbers + decision in `RESULTS/05_Results.txt`.
- **`_MockFeedServer` can't serve a needed format faithfully** (curl rejects it) → drop that format
  from the smoke set with a note; keep the rest.

### Manual smoke (owner: maintainer) — required before Accept

> CI asserts rendering/state/load but not *visual* correctness. Confirm on a live pfSense box.

- [ ] **Tabs render.** `Firewall ▸ pfBlockerNG ▸ Feeds` shows a second row `[IPv4 | IPv6 | DNSBL]`;
  each tab lists only that type's predefined feeds; the bare URL lands on IPv4; the breadcrumb
  shows the type.
- [ ] **No clobber.** Rename a feed on the IPv4 tab + Save; switch to DNSBL, rename one + Save;
  return to IPv4 → the IPv4 rename is **still there** (and vice-versa). Confirms the type-scoped save.
- [ ] **Custom feed loads (the Part-C journey, by hand).** Add a custom group/feed pointing at a
  reachable URL (or the mock), Force Update → the IP alias table populates (`pfctl -t <alias> -T
  show`) / the DNSBL name blocks (`drill @127.0.0.1`). Spot-check one IP and one DNSBL format.
- [ ] **No regressions.** Existing predefined feeds still save/rename/alt-URL as before on their tab.
