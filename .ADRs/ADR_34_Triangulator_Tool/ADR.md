# ADR-34: Add a read-only Block Triangulator (Why-Blocked diagnostics)

- **Status:** **Proposed** (2026-06-20; facts + anchors refreshed 2026-07-03 against `devel` —
  the DNSBL-matching design targets the legacy CSV view and must be redesigned around the
  manifest-built matcher + allow layer before implementation: see the **§2.0 open fork**,
  which also re-scopes Phase 1)
- **Date:** 2026-06-20
- **Branch:** `adr/34-triangulator-tool` (off `devel`)
- **Folds in:** issue #294 ("Add Triangulator Tool")
- **Component(s):** new `src/usr/local/pkg/pfblockerng/pfblockerng_diagnostics.inc` (engine),
  `src/usr/local/www/pfblockerng/pfblockerng_alerts.php` (per-row entry point) + a new
  Diagnostics page under Reports, `src/etc/inc/priv/` (ACL)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8)
- **Test suite:** `tests/php/` (PHPUnit, off-appliance), `tests/smoke/` + `tests/smoke/ui/`
  (live-VM, ADR-04/14)

## 1. Context

pfBlockerNG blocks at **two independent layers** and users routinely confuse them:

- **DNSBL** (Unbound, resolver level) — a domain (or a **CNAME** in its chain, or a **TLD
  wildcard**) matches a feed; Unbound returns the DNSBL VIP / NULL / block page.
- **IP firewall** (post-resolution) — a resolved IP matches a `pfB_*` urltable alias and pf
  blocks it.

Whitelisting the wrong layer has **no effect** (the canonical support question). The Alerts
page already has strong, reusable foundations (confirmed symbols):

- `pfblockerng_alerts.php` — `dnsbl_log_details()` (`:1976`, TLD/CNAME mode detection),
  `dnsbl_whitelist_type()` (`:2011`), `convert_dnsbl_log()` (`:2162`), unified log view,
  per-row whitelist/suppress icons, threat-lookup links.
- DNS resolution helper `pfb_ss_resolve_target()` (`pfblockerng.inc` ~`:5467`) using `drill`
  with `$pfb['extdns']` (~`:2125`) — the live-lookup pattern to reuse.
- DNSBL match data: `pfb_dnsbl_parse()` (`pfblockerng.inc` ~`:11703`); the Python data/zone
  files (`$pfb['unbound_py_data']` exact, `…_zone` wildcard/TLD). **Correction (2026-07-03,
  verified on `devel`): these CSVs are NOT the effective matcher** — they are a fallback the
  Python module uses "only when no manifest is present" and are slated for removal; **ABP
  feeds are excluded from them entirely**, and `pfb_py_data.txt` is only written when TLD
  mode is off. The **manifest-built Python structures are the source of truth**, and the
  allow layer (user whitelist `unbound_py_wh`, ADR-31 **permit feeds** → `whiteDB`,
  allow-regex) sits above every block verdict. See the §2.0 open fork.
- IP alias inspection: `pfctl -t <table> -T test <ip>` + the alias dir files.

Load-bearing facts:

- **Unbound runs chrooted at `/var/unbound`** — any file the resolver-side data lives in is
  chroot-relative; a host-absolute path silently fails (read the data via the existing
  helpers, not by re-deriving paths).
- **No live Unbound in CI** — engine logic is unit-tested against fixtures; the end-to-end
  "resolve + block + triangulate" is a live-VM smoke (ADR-04).
- The tool performs **on-demand DNS lookups for user-entered input** — an abuse/SSRF-shaped
  surface that must be validated + bounded (input filtering, CNAME-depth + timeout limits).

## 2. Decision

Add a **read-only "Triangulator" (Why-Blocked) diagnostics** feature. **v1 is read-only**
(maintainer's call): the analysis engine + an educational report + entry points + **contextual
links** to the existing whitelist/config pages. **In-place whitelisting is deferred to v2.**

### 2.0 OPEN DESIGN FORK (recorded 2026-07-03 — blocks Phases 1/3; maintainer's call)

The §2.1 matching design targets the legacy `unbound_py_data`/`unbound_py_zone` CSVs. As
corrected in §1, those do not represent the effective matcher: a domain blocked by an **ABP
feed**, a **feed regex**, or `$important` triangulates as *no match*, and a
**whitelisted/permitted** domain (user whitelist, ADR-31 permit feeds, allow-regex) that also
appears in a block feed is misreported as *blocked* — precisely the support cases the tool
exists to answer, violating §2.2 "correct layer attribution". The matching source of truth
must be redesigned around the **manifest-built matcher state incl. the allow layer**. Two
defensible mechanisms diverging in ways the maintainer must pick: (a) a **PHP parity
re-implementation** reading the manifest + raw feeds, pinned against the Python parser as the
test oracle; or (b) **querying the live Python module/state** (a dump/control-channel
interface). Until decided, Phase 1's "extract the classifier" premise is also wrong — there
is **no pure name-vs-data function to extract**: `dnsbl_log_details()` is a **log-field**
parser (usable only for the Alerts-row entry path), and `pfb_dnsbl_parse()` is a
grep-over-CSV + SQLite-cache routine. The classification vocabulary gains an
**`allowed/whitelisted`** verdict either way. Additionally, the SafeSearch / DoH-DoT-DoQ /
IDN verdicts are computed **query-time in Python** — for free-text input PHP cannot derive
them from data files; they are reliably attributable only on the Alerts-row path (scope each
verdict per entry path when resolving this fork).

### 2.1 Per-area decision

| Area | Decision |
| --- | --- |
| Engine location | new `pfblockerng_diagnostics.inc` (keeps logic out of the 14k-line core) |
| DNS resolution | `pfb_diag_resolve($domain)` → A/AAAA + full **CNAME chain** (reuse `pfb_ss_resolve_target`/`drill`/`extdns`); **depth limit ~10** + timeout; validate input first |
| DNSBL matching | `pfb_diag_dnsbl($domain, $cname_chain)` → **mechanism per the §2.0 fork** (manifest-built matcher state incl. ABP + the allow layer — NOT the legacy CSVs); classify **exact / parent-wildcard / TLD / CNAME / allowed** ; `dnsbl_log_details()` reuse is valid only for the Alerts-row entry path |
| IP matching | `pfb_diag_ip($ips)` → `pfctl -t <table> -T test` over active `pfB_*` urltable aliases; identify the feed/alias |
| Orchestrator | `pfb_triangulate($input)` → auto-detect IP / domain / URL; run the relevant checks; return a **structured report** |
| Classification | block mechanism summary: pure-DNSBL / pure-IP / hybrid / via-CNAME / via-TLD / **allowed-whitelisted** / SafeSearch / DoH-DoT-DoQ / IDN / TLD-Allow (the last four are query-time Python verdicts — per-entry-path scope per §2.0) |
| Explanation | plain-English text per classification (e.g. "DNSBL block — whitelisting the IP has no effect; whitelist at the DNSBL level") |
| Entry points | a Diagnostics sub-tab under Reports (free-text IP/domain/URL form) **and** a per-row "🔍 Triangulate" icon in Alerts that pre-fills context |
| Remediation (v1) | **contextual links** to the right existing whitelist/config page, pre-filled where possible — NOT in-place writes |

### 2.2 Semantics that MUST be preserved / hold (the contract — pin with tests)

- **Strictly read-only** — the engine performs **no** `config_set_path`/`write_config` and
  **no** DNSBL cache writes. Assert no config mutation across a triangulate run.
- **Input is validated before any shell/DNS use** — `pfb_filter(PFB_FILTER_DOMAIN)` /
  `is_ipaddr()` / URL parse; reject malformed input (PFBL-01). No unfiltered value reaches
  `drill`/`pfctl`.
- **Bounded** — CNAME chain depth-limited (~10) and timed out; no unbounded recursion/loops.
- **Existing Alerts behaviour unchanged** — the new icon is additive; `convert_dnsbl_log()` /
  `dnsbl_log_details()` outputs are not altered (reused, not modified).
- **Correct layer attribution** — a DNSBL-only block is reported as DNSBL (not IP), and the
  CNAME/TLD cases are distinguished from an exact match (branch-tested).

### 2.3 Explicitly kept / out of scope

- **In-place whitelisting** (type-aware buttons that POST to whitelist handlers) — **v2**.
  v1 links to the existing pages instead.
- **A top-level menu item** separate from Reports — out; entry is the Reports sub-tab + the
  Alerts per-row icon.
- **Modifying `convert_dnsbl_log`/`dnsbl_log_details`** beyond read-only reuse — out.
- **Caching diagnostic results** — out (read-only, per-query).

## 3. Consequences

**Positive**

- Directly answers "why is X blocked?" and "I whitelisted the IP but it's still blocked",
  attributing the correct layer and the responsible feed/alias.
- Educational; reduces false-positive reports and support load.
- Builds on proven Alerts/DNSBL-mode code; read-only v1 keeps the blast radius small.

**Negative / risks**

- On-demand DNS lookups for arbitrary user input is an abuse surface — mitigated by input
  validation, depth/timeout bounds, and read-only operation.
- Chroot/path subtleties for resolver-side data — mitigated by reusing the existing helpers
  rather than re-deriving paths.
- Engine correctness across exact/wildcard/TLD/CNAME has many branches — needs thorough
  fixture-based unit tests; full end-to-end needs the live-VM smoke (no Unbound in CI).

## 4. Requirements (acceptance)

- `pfblockerng_diagnostics.inc` with `pfb_diag_resolve` / `pfb_diag_dnsbl` / `pfb_diag_ip` /
  `pfb_triangulate`, returning a structured report; read-only.
- Classification + plain-English explanation covering the documented mechanisms.
- A Reports → Diagnostics page (form) + an Alerts per-row Triangulate icon (pre-filled).
- Contextual links to existing whitelist/config pages (no in-place writes in v1).
- Input validated + bounded; no config/cache mutation (asserted).
- All gates green (§5); live-VM smoke proves a real DNSBL block triangulates correctly.

## 5. Constraints (from CLAUDE.md)

- PHP tabs, PHP 8.3; no `die()`/`exit()` in library code; new pfSense fns stubbed + doubled.
- PFBL-01: validate before any `exec`/`pfctl`/`drill`/path build; add new input-handling fns to
  the PHPCS `scopeFunctions` allow-list; honour the URL-encoding gate if any HTTP client is used.
- Read-only: the engine must not touch `config_*_path`/`write_config` or DNSBL cache.
- Unbound is chrooted (`/var/unbound`) — reach resolver data via existing helpers; no
  host-absolute path assumptions.
- ADR-14 `ui_render` is the PR gate for the new page; ADR-04 smoke for the end-to-end.

## 6. Action plan

### Phase 1 — Prep: extract reusable match/classify helpers (BLOCKED on the §2.0 fork)

- Prompt: `01_Extract_Helpers.txt`
- **Premise corrected 2026-07-03:** there is **no pure "classify a name against
  exact/wildcard/TLD data" function to extract** — `dnsbl_log_details()` parses **log
  fields** (usable only for the Alerts-row path) and `pfb_dnsbl_parse()` is a grep-over-CSV +
  SQLite-cache routine over the removal-slated legacy view. As written, an implementer would
  write **new** logic and pin it as a fake "behaviour-preserving oracle" (coverage-theater).
  Re-scope this phase after the §2.0 fork is decided: either extract the genuinely reusable
  Alerts-row log-field parsing (real oracle) and frame the matcher as **new code with
  red→green tests**, or (fork option b) skip extraction entirely.
- Tests: per the re-scope — a real oracle only where existing behaviour is genuinely reused.

### Phase 2 — Engine: DNS resolution chain (`pfb_diag_resolve`)

- Prompt: `02_Resolve_Chain.txt`
- New `pfblockerng_diagnostics.inc`; `pfb_diag_resolve($domain)` → A/AAAA + CNAME chain via the
  `pfb_ss_resolve_target`/`drill`/`extdns` pattern; validate input (PFBL-01) before shell;
  depth limit ~10 + timeout. **Read `docs/misc/external-process-waits.md` before writing the
  timeout mechanics** (FreeBSD `timeout(1)` is a process reaper by default — pick the mode
  deliberately).
- Tests: parse fixture `drill` outputs → chain + final IPs; depth-limit + loop guard; malformed
  input rejected (no shell reached).

### Phase 3 — Engine: DNSBL + IP matching (`pfb_diag_dnsbl`, `pfb_diag_ip`)

- Prompt: `03_Match_Engine.txt`
- `pfb_diag_dnsbl($domain,$chain)` reusing the Phase-1 classifier over exact/wildcard/TLD data
  for the domain + every CNAME; `pfb_diag_ip($ips)` via `pfctl -t <table> -T test` over active
  `pfB_*` aliases, identifying the feed. Read-only.
- Tests: DNSBL match types (exact/parent/TLD/CNAME-in-chain) on fixtures; IP match maps to the
  right alias/feed; validate IPs before `pfctl`.

### Phase 4 — Orchestrator + report model (`pfb_triangulate`) + explanations

- Prompt: `04_Orchestrator.txt`
- `pfb_triangulate($input)` auto-detects IP/domain/URL, runs the relevant checks, and builds the
  structured report with a **classification** (pure-DNSBL / pure-IP / hybrid / via-CNAME /
  via-TLD / SafeSearch / DoH-DoT-DoQ / IDN / TLD-Allow) and a plain-English explanation map.
- Tests: each classification branch from a fixtured combination of resolve/dnsbl/ip results;
  assert NO config/cache mutation across a run.

### Phase 5 — UI: Diagnostics page + Alerts entry + contextual links + ACL

- Prompt: `05_UI.txt`
- A Reports → Diagnostics sub-tab (free-text form + structured, colour-coded results panel +
  "copy report"); an Alerts per-row "Triangulate" icon pre-filling context; contextual **links**
  to the existing whitelist/config pages; a `.priv.inc` ACL entry. Server-side validation
  (PFBL-01). No in-place whitelist writes (v2).
- **Ports lockstep (added 2026-07-03 — missing from the original plan):** the two new shipped
  files (`pfblockerng_diagnostics.inc` + the new `www/` page) need pkg-plist + `do-install`
  entries in **all three** ports (`pfSense-pkg-pfBlockerNG{,-devel,-nightly}`) or the smoke
  `.pkg` omits them and Tier A 404s on the live VM; verify with
  `build-pkg-portable.py --dry-run`.
- Tests: PHPUnit for the input-detect/decider; ADR-14 `ui_render` for the new page (200; no
  Fatal/Parse/Warning/Notice/Uncaught; marker; no new php_error.log line — register it in
  `test_render_smoke.py` `PAGE_TABLE`); **plus Tier B `ui_e2e` — REQUIRED per CLAUDE.md test
  principle 4** (new page + multi-step flow): submit the form → report renders; Alerts icon →
  page pre-filled. Alerts page still renders.

### Phase 6 — Smoke + DoD + docs

- Prompt: `06_Smoke_DoD_Docs.txt`
- Live-VM smoke: list a `uuid-*.com` in a DNSBL feed, resolve it (blocked), triangulate →
  report classifies it as a DNSBL block naming the feed and states the IP-whitelist-has-no-effect
  guidance; an IP-side case; a CNAME-chain case; an **allowed/whitelisted** case (§2.0). Green
  on the **CE + Plus fan-out** — the default ADR-acceptance validation; non-CI residuals are
  documented out-of-CI limitations, not the gate.

## 7. Definition of done

- [ ] `pfblockerng_diagnostics.inc` engine (resolve/dnsbl/ip/orchestrator) read-only + branch
      tested; no config/cache mutation (asserted).
- [ ] Input validated + bounded (depth/timeout); malformed input never reaches a shell.
- [ ] Classification + plain-English explanations cover the documented mechanisms.
- [ ] Reports → Diagnostics page + Alerts per-row icon + contextual links + ACL; Alerts
      behaviour unchanged.
- [ ] All gates green: `vendor/bin/phpunit`, PHPStan, PHPCS (PFBL-01), `php -l`,
      `python -m pytest`, ADR-14 `ui_render` **+ `ui_e2e`**; live-VM smoke triangulates a real
      DNSBL block on the **CE + Plus fan-out**.

**Manual smoke (owner: maintainer):**

- [ ] Real CNAME-cloaked domain → tool shows the chain + the blocked CNAME + correct guidance.
- [ ] CDN case: domain clean in DNSBL but a resolved IP in a reputation feed → tool attributes
      the IP layer.
- [ ] TLD-wildcard case → tool explicitly calls out the TLD match.

**Reject criteria:** if read-only on-demand DNS lookups for arbitrary input cannot be bounded
safely (abuse/timeout), or correct layer attribution can't be achieved without live Unbound
(making CI/manual validation infeasible), **reduce** (Alerts-context-only, no free-text input)
or **reject**, recording the evidence.
