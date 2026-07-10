# ADR-62: Unify DNSBL feed line parsing — retire PHP feed-level ABP classification, make Python the single per-line authority

- **Status:** **Accepted** (2026-07-10, on the green CE+Plus live-VM smoke fan-out — GitHub
  Actions run 29069638831, both legs + the AND gate green over §7 rows 1–7
  (`-k "adr62 or test_dnsbl_http_hosts_feed_loads"`, scope=full), corroborated by a local
  box-pool run of the same module (7/7). Revised 2026-07-09 after an evidence audit of the
  design handoff — the audit corrected the realization plan, see §2 "The realization fork" and
  §1.5). All 7 phases landed (`RESULTS/01–07_Results.txt`, `RESULTS/01–07_Gate.txt`); the
  byte-identity corpus oracle is green with exactly D1–D5 flipped; full
  PHPUnit/pytest/PHPStan/PHPCS are green; Phase 6's benchmark is PASS (see §3).
  Acceptance note: the §7 row-7a smoke case shipped by Phase 7 was rewritten post-fan-out-red
  before acceptance — the original drove a Force-DNSBL trigger, which structurally cannot reach
  the reuse fork (`$pfbreuse == ''`), and a no-change pass skips the DNSBL rebuild entirely; the
  accepted design loads two feed rows, changes only the sibling (forcing the rebuild), and
  proves the unchanged row's staged old-dialect `.txt` is consumed as-is (staged domain blocked,
  original domain released, sibling re-ingested, stale `.abp` marker swept).

  **As-built summary (Phase 7, 2026-07-10):**
  - **Delta table (§2), the user-facing behaviour changes for the next release's notes:** D1 —
    a bare hosts/plain line in a feed that *was* header-classified ABP: a registrable-parent
    line stays a wildcard ZONE block (unchanged); a deeper sub-domain line becomes an exact
    DATA block instead of an always-wildcard ZONE. D2 — `/re/`/`@@/re/`/`@@…`/`##…` lines in a
    feed that was *never* ABP-classified are now captured and honoured (regex rules activate;
    element-hiding is silently skipped instead of a `#`-truncation false-positive block). D3 —
    `[…]`-non-IPv6 and `##…` lines stop being parse-error-logged (diagnostics-only). D4 —
    element-hiding lines in a permit-mode feed (ADR-31) no longer produce an accidental
    band-2 allow. D5 — `.txt` line counts / "No Domains Found" may shift slightly (newly
    captured verbatim lines count where drops did before) — a UI statistic, not a blocking
    contract.
  - **Carried deviations from prior phases** (none silently dropped): P3's corpus-fixture
    non-flip rationale (`RESULTS/03_Results.txt`); P5's re-scoped commit 1, discharged by the
    reconciliation notes in §1.5/§6 above; P6's kept `$format` ternary in
    `pfb_unbound_python_sources()` (the corpus's `format='abp'` tagging assertion still
    exercises it, `RESULTS/06_Results.txt` DEVIATIONS item 1).
  - **Discovered during this phase, NOT fixed here (out of Phase 7's docs/smoke scope):**
    issue #1105 — `pfb_unbound_python_sources()` silently drops a bare-domain line inside an
    OLD-dialect (pre-ADR-62 `$easylist`-verbatim) `.txt` file the first time a feed is REUSED
    (not re-downloaded) after upgrading past this ADR — contradicts Semantics #7's literal
    claim for that one sub-case (the `reused_manifest_abp` corpus fixture never exercised a
    bare-domain line, only `\|\|reused.example^`). Verified by direct execution against the
    real function (not reasoned from memory); reproduction, impact, and a fix direction are in
    the issue. `tests/smoke/test_smoke_adr62.py`'s row-7a reuse test deliberately covers only
    the SAFE 6-col-dialect sub-case (unaffected by this gap) and documents the exclusion inline.
- **Date:** 2026-07-09
- **Branch:** `adr/62-dnsbl-unified-line-parsing` (off `devel`; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming") / **Component(s):** `pfblockerng.inc` (the DNSBL feed
  parse loop inside `sync_package_pfblockerng()`, the feed-manifest writer, the TLD-analysis
  pass, the ABP header sniff), `pfb_unbound.py` (`build()`'s per-line routing, `parse`/
  `parse_abp`), `tests/php/`, `tests/` (pytest), `tests/smoke/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); Python 3.11+, stdlib only (chrooted in Unbound's
  Python loader — `parse_abp`/`parse` already live there).
- **Test suite:** `tests/php/` (PHPUnit — the extracted PHP helpers + byte-identity staging
  oracles), `tests/` (pytest — the Python per-line routing parity oracle), `tests/smoke/`
  (ADR-04 live VM — feed-format fan-out; the §7 acceptance rows are AUTOMATED smoke tests, per
  CLAUDE.md "ADR acceptance") + `tests/smoke/ui/` (only if any `www/` surface moves; none
  currently planned).

All `file:line` anchors are measured on `origin/devel` @ `8563ac5d` and drift as `devel`
advances — re-grep before relying on one.

---

## 1. Context — today

### 1.1 The DNSBL feed parse loop and its feed-level ABP classifier

`sync_package_pfblockerng()` (`src/usr/local/pkg/pfblockerng/pfblockerng.inc`, **14832–19311 =
4480 lines**) contains the DNSBL feed download+parse loop (`while (($line = @fgets(...)))`
@**16262**, ends ~**16715**). Per line it classifies, strips, and extracts a domain (or an IP)
and writes the result to a per-feed `.bk` staging file (renamed to `{$header}.txt` @16830).

The loop maintains a **feed-level** notion of "is this an ABP/EasyList feed?" in `$easylist`,
set by a one-shot header sniff:

```php
// inc:16283-16294 — the $validate_header scan window (quoted verbatim)
if (!$validate_header) {
    if (pfb_dnsbl_is_abp_header($line)) {
        $easylist = $validate_header = TRUE;
        continue;
    }
    elseif (str_starts_with($line, '!')) {
        continue;
    }
    else {
        $validate_header = TRUE;
    }
}
```

`pfb_dnsbl_is_abp_header()` (`inc:6547`, ADR-21) prefix-matches `[Adblock` / `[uBlock` /
`! Title:` (BOM-tolerant). The window's `!`-skip is **not** a mere duplicate of the body
`!`-skip (`inc:16412`): it keeps the scan window **open** across a feed's leading `!`-comment
block so a `! Title:` / `[Adblock` header on a *later* line still classifies the feed (the body
comment at `inc:16409-16411` states exactly this). It is only redundant once the whole
classifier is deleted — which is what this ADR does.

`$easylist` sites (complete, from grep — the handoff's list of three was incomplete): init
@16251, set @16285, verbatim-capture guard @**16317**, ABP branch @**16324** (IP-extract + write
raw ABP lines verbatim), host-format extraction guard @**16572**, manifest-row format tag
@**16817**, and the `.abp` marker write/unlink @**16823-16827**.

### 1.2 The staging dialects and the manifest boundary

A feed's `.txt` staging file has **two per-line dialects**, and every downstream consumer
depends on which one a line uses:

- **plain rows** — the 6-col CSV `,{domain},,{logging_type},{header},{alias}` (`inc:16712-16714`),
  written after the full PHP extraction pipeline: tab/`%20` munging, `#`-classifier, `!`/`//`
  skip, inline `' #'` strip, CSV column pick, hosts-prefix strip, ADR-22 scheme strip
  (strict/lenient + per-line parse-error log, issue #1004, + per-feed WARNING), `/`/`#`/`?`
  truncation, `;`-`parse_url`, trailing-port strip, bracketed-IPv6 unwrap, IP collection, IDN
  `idn_to_ascii` (@16673-16690), `pfb_filter(PFB_FILTER_DOMAIN)` validation with parse-fail
  logging, and `strtolower`.
- **verbatim ABP lines** — written raw, no extraction: the whole body of an `$easylist` feed
  (@16324, comment/control lines pre-dropped so the raw is dense), and — ADR-21 — any
  `||`/`@@||`-prefixed line in a *plain* feed (@16317-16322).

PHP tags each feed in `pfb_feed_manifest_row()` (`inc:6946`); `pfb_unbound_python_sources()`
(`inc:6975`) writes the per-feed `.raw` the Python build consumes, handling **both dialects
per line**: an `'abp'` feed copies raw lines; a `'plain'` feed passes `||`/`@@||` lines raw
(@7030) and extracts col 1 from 6-col rows. The production `format_hint` vocabulary is exactly
`{'abp', 'plain'}` (`inc:7000`) — `parse()`'s `csv:pon` branch is currently **unreachable from
production manifests** (CSV extraction is PHP-side; CSV feeds are tagged `plain`). The reuse
path (a feed not re-downloaded) derives the hint from the persisted `{$header}.abp` marker
(@16182).

### 1.3 Python already routes ABP-shaped lines per line — partially

`build()` (`pfb_unbound.py:4869`) is the consumer: `format_hint == 'abp'` feeds stream every
raw line through `parse_abp()` (@5039-5043); **`plain` feeds already get per-line ABP routing**
(ADR-21, @5045-5058): a line starting `||`/`@@||` goes to `parse_abp()`, everything else takes
`parse()` (@4050) → `_normalise_verdict()`. Permit-mode feeds (ADR-31) take their own loop
(@4993) that *skips* `@@`/`||`/`!`/`[` lines and allows the rest.

So the "per-line dispatcher" this ADR needs **mostly exists**; the gap is the *shape set*: the
per-line capture (PHP @16317, manifest writer @7030, Python routing @5054) recognises only
`||`/`@@||`. `parse_abp()` (`pfb_unbound.py:3869`; regex helper `_dnsbl_parse_abp_regex:3841`)
also owns `/re/` (block-regex), `@@/re/` (allow-regex), `$important`/`$badfilter` options, and
skips element-hiding (`##`/`#@#`/`#?#`/`#%#`/`#$#`) — shapes that today reach Python **only**
from an `$easylist`-classified feed. `parse()` and `parse_abp()` are NOT interchangeable: the
plain branch of `parse()` drops `@@`/regex/`$options` (`:4062-4064`); `parse_abp` keeps and
bands them.

One semantic split matters for this ADR: a **bare hosts/plain domain line** is `wildcard=True`
through `parse_abp` (a ZONE at any depth, #718, `:4009/:4031`) but goes through `classify()` on
the plain path (registrable parent → wildcard ZONE; deeper sub-domain → exact DATA). The same
line produces a **different zone/data classification** depending on which path it takes — the
core reason "route everything through `parse_abp`" is not behaviour-preserving.

### 1.4 IP extraction stays in PHP

"IP extraction is NOT Python's job — it stays in PHP" (`pfb_unbound.py:3510-3511`, `:4057`).
ABP-anchored IPs (`||1.2.3.4^`, via `pfb_dnsbl_abp_extract_ip` `inc:6361`) and hosts-line IPs
are collected to the firewall/DNSBLIP aliases (`$domain_data_ip`/`_ip6`, six copies:
`inc:16343/16349`, `16495/16504`, `16654/16665`). Bracketed IPv6 literals `[2604:2dc0::]`
(issue #938) are unwrapped by `pfb_dnsbl_unbracket_ip6()` (`inc:6486`, iff `is_ipaddrv6(inner)`)
and collected as IPs — **they are addresses, not ABP `[section]` comments.**

### 1.5 The 6-col dialect is a cross-feature contract (why raw-passthrough was rejected)

The handoff's Decision D5/Option realization ("PHP stops extracting plain-feed domains; raw
lines pass through to Python") was **rejected by this revision**: the plain 6-col rows are not
just Python's input — they are a contract consumed by:

- the **PHP TLD-analysis pass** (`inc:7709-7860`): parses the concatenated `pfb_dnsbl.raw`
  6-col rows into the `pfb_py_zone`/`pfb_py_data` files; it *skips* ABP-feed lines via a glob
  of the `.abp` markers (@7723-7726) — a second `.abp`-marker consumer the handoff missed.
  (Latent pre-existing bug found during this audit: the skip is gated on
  `!empty($abp_feeds)` @7738, so a *plain* feed's ADR-21 verbatim `||x^` line is CSV-mangled
  by this pass when **no** ABP feed is configured — tracked as issue #1060; Phase 5 makes
  the skip unconditional on an empty feed column, fixing it structurally.)
  **[2026-07-10 reconciliation, Phase 7]** This paragraph predates `devel` PR #1066 (merged
  2026-07-09, independent of this ADR's phase work), which already made the comma-prefix guard
  itself unconditional and closed issue #1060 — its own words: "the marker-based skip by feed
  name stays for marked feeds (full marker retirement remains ADR-62 Phase 5's)". What actually
  shipped in Phase 5's own commit 1 is narrower than this paragraph originally scoped: only the
  SURVIVING `$abp_feeds` marker-glob gate (@7872-7875) and its `isset($abp_feeds[$lfeed])` arm
  (@7891-7896) — the part PR #1066 explicitly left for this ADR. See `RESULTS/05_Results.txt`
  "PLANNER RE-SCOPE" for the verified live-tree state at session start.
- the **Alerts feed-attribution greps** (`inc:13477`, `13504`) and the **prefetch** helper
  (`inc:13316`) — they grep `pfb_py_data`/`pfb_py_zone` (6-col rows) to answer "which feed
  listed this domain".
- the **legacy Python zone/data CSV loaders** (`pfb_unbound.py:909`, `:951`).
- **feed line counts** (`grep -c ^ {$header}.txt` @16843 → `$alias_cnt` → widget/report
  counts) and the **diagnostics surface** (#1004 per-line parse-error sink, ADR-22 strict-skip
  warnings, IDN-conversion log lines) — all live in the PHP extraction pipeline.

Additionally, Python's plain path has **no** scheme/URL stripping and **no** IDN conversion
(`_normalise_verdict` `:4130` is an ASCII-only label gate) — raw-passthrough would silently
drop every `http://…`-bearing and every IDN line, a blocklist regression. The known
PHP↔Python divergences (#752 undotted-254, #753 wire caps, `pfb_unbound.py:4159-4167`,
`:4122`) apply only to lines Python actually parses — under this ADR's realization that is the
verbatim-captured ABP shapes, whose handling does not change; they stay corpus rows, not
blockers.

### 1.6 Recent related work

Commit `8563ac5d` (#993/#995) extracted three **coverage-only** pure helpers (no dedup):
`pfb_dnsbl_hash_line_classify()` (`inc:6564`, the `#`-marker classifier), and — in the
*separate* generic IP-list loop — `pfb_ip_is_opposite_family()` (`inc:4535`) and
`pfb_ip_parse_fail_warn()` (`inc:4502`). Reuse the `#`-classifier; the other two are out of
this ADR's loop. `tests/fixtures/feed_corpus/` (ADR-49) already holds committed first-8-KiB
snapshots of every catalogue feed (real EasyList headers, CSV headers) — raw material for the
Phase-1 corpus. `tests/test_adr07_decision_spec.py` is the `parse_abp` reference oracle.

---

## 2. Decision

**Retire PHP's feed-level ABP classification; make the per-line shape of a line — not the feed
it came from — decide its parser, with Python's `parse_abp` the single ABP authority.**
Concretely:

1. **Delete `$easylist`, `pfb_dnsbl_is_abp_header()`, and the `$validate_header` scan block.**
   No feed-level "is this ABP?" state; no header expectation. (`DnsblIsAbpHeaderTest.php` is
   deleted with its helper.)
2. **Broaden the per-line ABP capture from `||`/`@@||` to the full self-identifying set** that
   `parse_abp` accepts or deliberately skips: `||…`, `@@…` (covers `@@||` and `@@/re/`),
   `/…/`-regex (with optional `$options` tail), and the element-hiding marker family
   (`##`/`#@#`/`#?#`/`#%#`/`#$#` — captured so Python's existing skip, not PHP's host
   extraction, decides them). ONE new pure PHP predicate (e.g. `pfb_dnsbl_is_abp_rule_line()`)
   used at **all three capture sites** — the download-loop verbatim capture (@16317), the
   manifest writer (@7030), and mirrored by the Python routing predicate in `build()` (@5054).
   This is a *capture guard*, not a parser: PHP never interprets the shapes; Python remains the
   sole ABP parse authority. Cross-language predicate agreement is corpus-pinned on both sides.
3. **The PHP plain extraction pipeline stays** (scheme/IDN/filter/6-col rows/counts/
   diagnostics) — explicitly **NOT** raw-passthrough, because of the §1.5 consumer contract.
   CSV column extraction stays in PHP (unchanged).
4. **Universal comment/control skip.** The plain path gains the ABP branch's `''`/`!`/`[…]`
   skip (the `[…]` skip excludes a bracketed IPv6 literal: unbracket/collect **first** via
   `pfb_dnsbl_unbracket_ip6()`, then any surviving `[…]` line — `starts '[' && ends ']' &&
   !is_ipaddrv6(inner)` — is an ABP marker → skip). `!`/`//` skips already exist; the `#`
   classifier keeps its side effects.
5. **`format_hint` collapses to `'plain'` for every domain feed** (nothing sets `'abp'` any
   more); Python **keeps accepting `'abp'`** from a stale on-disk manifest (a pkg upgrade can
   reload against a manifest written by the previous version — mixed-state tolerance, same
   rule ADR-31 applied to `mode`). The `.abp` marker is **retired**: the reuse path stops
   branching on it (@16182), the writer sites (@16823-16827) are deleted, and its second
   consumer — the TLD-pass skip (§1.5) — is rewritten to skip on an empty/unset feed column
   **unconditionally** (also fixing the latent gate bug). Stale markers are swept
   opportunistically.

### The realization fork (revised after the evidence audit)

The handoff posed Option A (per-line routing, PHP keeps host-parsing) vs Option B (route all
domain feeds through `parse_abp`, PHP stops extracting). The original draft of this ADR
committed to "A" but adopted B's raw-passthrough staging — internally inconsistent and, per
§1.5, a multi-consumer regression. **This ADR commits to Option A as realized above** (broaden
the existing per-line capture; keep the PHP extraction pipeline). **Option B is rejected, not
fallback:** it breaks the §1.5 consumers, loses the scheme/IDN/diagnostics behaviour Python
does not implement, and re-types every bare hosts line (§1.3 zone/data split) — a behaviour
change on the biggest, most common feed class. If Phase 3 cannot make the broadened capture
reproduce today's output for ABP feeds, the reject path is §7 criterion 1 — not a silent
fallback to B.

### Accepted semantic deltas (enumerated — the ONLY permitted output changes)

Deleting feed-level classification necessarily re-types a few line classes. Each delta below
is deliberate, carries a corpus row proving OLD → NEW, and is asserted in the §7 smoke rows.
Anything outside this table is a regression (§7 criterion 1/3).

| # | Line class | Today | After | Why accepted |
| - | ---------- | ----- | ----- | ------------ |
| D1 | bare hosts/plain domain line in a feed that *was* header-classified ABP | `parse_abp`: wildcard ZONE at any depth (#718), banded/reconciled | plain path: `classify()` — registrable parent → ZONE, deeper sub → exact DATA; band 1 direct | a bare line is genuinely ambiguous once feeds are unclassified; plain treatment is the canonical one (bare lines are rare in real ABP feeds — `\|\|` dominates) |
| D2 | `/re/`, `@@/re/`, `@@…`, `##…` lines in a feed that was *never* ABP-classified | host-mangled: dropped via `pfb_filter` + parse-fail log — except `example.com##.ad`, whose `#`-truncation extracts `example.com` as a live **false-positive block** | captured verbatim → `parse_abp` (regex rules become active; element-hiding skipped) | the false-positive class is fixed; regex rules in plain feeds now honoured (self-identifying per line — the ADR's thesis) |
| D3 | `[…]`-non-IPv6 and `##…` lines (any feed) | plain path error-logs them (#1004) | skipped/captured silently | diagnostics-only; the parse-error log loses noise, not signal |
| D4 | element-hiding lines in a **permit-mode** feed (ADR-31) | `#`-truncation can extract a domain → accidental band-2 **allow** | captured verbatim → the permit loop skips ABP-shaped lines; captured `##` lines are skipped by Python | accidental allows from cosmetic rules are a defect, not a behaviour to preserve |
| D5 | `.txt` line counts / "No Domains Found" emptiness check | counts reflect extraction results | newly captured verbatim lines count where drops did before (small shift) | counts are a UI statistic, not a blocking contract |

### Semantics that MUST be preserved (the contract — pin with tests before any swap)

1. **Byte-identical domain set, modulo the delta table.** For every §"Coverage matrix" format,
   the set of domains loaded into the DNSBL block dicts (and their log/exact-vs-wildcard
   classification) matches `origin/devel` exactly, except where a delta row applies — proven by
   the Phase-1 corpus oracle, before any wiring change.
2. **Byte-identical firewall IP set.** The DNSBLIP `$domain_data_ip`/`_ip6` set per feed is
   unchanged (IP extraction stays in PHP, §1.4) — including ABP-anchored IPs and bracketed
   IPv6 literals.
3. **Bracketed IPv6 is never skipped as a comment** (Decision 4): `[2604:2dc0::]` collects as
   an IP; only a non-IPv6 `[…]` is dropped.
4. **ABP rule semantics preserved for ABP-shaped lines:** `||`, `@@` allow, `/regex/`,
   `$important`, `$badfilter`, provenance and banding are unchanged (still via `parse_abp`,
   whatever feed the line sits in).
5. **Comment/blank skip is output-neutral on the domain/IP sets** (log-noise change is D3).
6. **hpHosts stop-marker, Spamhaus `$rev_format`, h3x CSV-header** (the `#`-classifier) and the
   whole CSV switch keep their current effect — untouched.
7. **Reuse and upgrade tolerance.** A reused (not re-downloaded) feed's `.txt` — written by
   EITHER dialect generation (old 6-col, old raw-ABP, new mixed) — produces the same Python
   input; a stale manifest still naming `format_hint='abp'` still parses. The retired `.abp`
   marker's two consumers (§1.5) behave identically after retirement.
8. **The §1.5 consumer contract holds:** TLD-analysis output, Alerts attribution, prefetch,
   and the legacy loaders see unchanged input for plain rows; verbatim lines are skipped by
   the TLD pass via the unconditional empty-feed-column rule.

### Coverage matrix (feed formats/line classes — Phase 1 re-derives from source)

Each row is a byte-identity axis the Phase-1 corpus must include and every later phase must
keep green (delta rows assert OLD → NEW per the delta table): **plain hosts feed** (`0.0.0.0
domain` / bare `domain` / mixed-case → lowercase); **URL/scheme lines** (`http://d/path`,
`d/path`, `d#frag`, `d?q`, `d;x`, trailing `:8080`) under ADR-22 **lenient AND strict**;
**whitespace mutations** (tab, `%20`, inline `' #'` comment, CRLF, leading/trailing dots);
**yHost `@`-prefix** line; **ABP/EasyList feed** (`||domain^`, `@@||`, `! Title:` header,
`[Adblock]`, `/regex/`, `@@/re/`, `$important`, `$badfilter`, element-hiding `##`-family,
mid-body `!#if`/`!#endif`, **bare hosts/plain line** — delta D1); **mixed plain feed** (stray
`||domain^`, `/re/` — delta D2, `##` — delta D2/D3); **permit-mode feed** (ADR-31 — delta D4);
**Spamhaus rev_format**; **hpHosts** end-marker; **CSV types** `pt(8) · bbc(4) · h3x(8) ·
otx(3) · pon(9) · et(3)` + header-sniff feeds `phishtank · bambenek · otx · ponomocup · et`;
**custom (`$liteparser`) list**; **IDN/punycode** line; **bare IPv4 / IPv6 / bracketed-IPv6**
line; **ABP-anchored IP** (`||1.2.3.4^`); **oversized/#752 undotted** name; **wire-cap (#753)**
name; empty / whitespace-only / BOM-led first line; **reused feed with old-dialect `.txt`**
(both generations); **TLD-analysis-enabled run** over a corpus containing verbatim lines.

### Explicitly kept / out of scope

- **CSV column extraction stays in PHP.** The 6-type CSV switch (`inc:16426–16562`) and the
  `#`-header classifier are untouched. A future ADR may lift CSV into Python.
- **The IP-collection triplication (R2)** is de-tangled as behaviour-preserving prep (Phase 2)
  because Phases 4–5 touch those sites — pure extraction, not a behaviour change.
- **The generic IP-list loop** (`pfb_ip_is_opposite_family` etc.) — different loop, untouched.
- **Raw-passthrough / Option B** — rejected (§2 fork), not deferred.
- **The `pfb_py_data`/`pfb_py_zone` 6-col dialect** and its consumers — unchanged.

## 3. Consequences

**Positive**

- Deletes the entire feed-level ABP classification + header-detection state machine
  (`$easylist`, `pfb_dnsbl_is_abp_header`, `$validate_header`) — no header expectation, no
  cross-language ABP-detection drift (one parse authority: `parse_abp`; one shared capture
  predicate, corpus-pinned on both sides).
- Collapses the doubled verbatim paths (16317/16324) into one; the per-line flow reads
  linearly.
- **Fixes two real defect classes found during this audit:** the `##`-element-hiding
  false-positive block in plain feeds (D2), and the TLD-pass skip gate bug (§1.5).
- ABP rules become honoured wherever they occur (the owner's thesis): a `/re/` or `@@` rule in
  an unclassified feed now works instead of being host-mangled.

**Negative / risks**

- **Predicate drift is the new risk surface:** the capture predicate exists in PHP (helper) and
  Python (routing) — two implementations of one shape set. Mitigated: single PHP helper reused
  at both PHP sites, a Python-side mirror pinned by the same corpus rows on both sides, and the
  Phase-3 parity oracle.
- The delta table is a **behaviour contract with users** — each delta is small and defensible,
  but it must be stated in release notes (Phase 7) and pinned by OLD → NEW tests, or it will
  read as a regression report.
- Per-line cost on the plain hot path grows by a few `str_starts_with` checks (PHP) and prefix
  checks (Python) — expected ~0; Phase 6 measures against a kill-threshold anyway.
  **[2026-07-10, Phase 6 closing evidence]** Measured on a synthetic 1M-line 'plain' feed
  (97% bare-domain / 2% `\|\|` / 1% `@@\|\|`, `scripts/bench_dnsbl_line_parsing.py`): PHP
  `pfb_unbound_python_sources()` wall +6.12% / peak RSS −0.25%; Python `dnsbl_build_from_manifest()`
  wall +12.74% / peak RSS −1.67% — both well under the >25% kill-threshold (§7 criterion 2). PASS,
  not REJECT. The Python-side delta traces to a genuine, expected cost: the broadened
  `_dnsbl_is_abp_rule_line()` predicate runs a 5-substring element-hiding scan on every bare-domain
  line that clears the `\|\|`/`@@` fast path — i.e. the 97% majority case. Full methodology,
  reproducibility run, and dead-code perf-neutrality proof: `RESULTS/06_Results.txt`.

## 4. Requirements (acceptance)

1. For every §"Coverage matrix" row, the DNSBL domain set and the DNSBLIP IP set built from a
   fixed corpus match `origin/devel` **byte-identically, modulo the delta table** (each delta
   row asserted OLD → NEW); the Phase-1 oracle is still green at the final phase.
2. `$easylist`, `pfb_dnsbl_is_abp_header()`, `$validate_header`, and the `.abp` marker
   read/write sites are **deleted** — `grep -n '\$easylist\|pfb_dnsbl_is_abp_header\|\$validate_header\|\.abp' src/`
   finds no live reference (NB: the literal substring `easylist` legitimately survives in the
   MIME-exception hostnames @`inc:1581` and the `pfblockerngdnsbleasylist` config-section
   name — anchor the grep to the symbols, not the substring). `DnsblIsAbpHeaderTest.php` is
   removed with its helper.
3. A bracketed IPv6 literal collects as an IP; a non-IPv6 `[…]` line is skipped everywhere;
   both pinned by tests (Semantics #3).
4. ABP-shape semantics (`@@`/regex/`$important`/`$badfilter`/banding) unchanged for ABP-shaped
   lines in any feed (Semantics #4); element-hiding lines never produce a block or an allow.
5. The TLD-analysis pass skips verbatim lines unconditionally (empty feed column ⇒ skip, no
   marker-glob gate); TLD output for plain rows is byte-identical.
6. On the live-VM CE+Plus fan-out, the §7 automated smoke rows are green.

## 5. Constraints (from CLAUDE.md)

- **DNSBL/ABP pipeline is architecturally significant** — read `docs/misc/architecture-notes.md`
  "DNSBL/ABP pipeline" (ADR-06/07/10/12/21/22) before each phase; this ADR sits on the ADR-06/07
  parser boundary.
- PHP 8.3, tabs, uppercase `TRUE`/`FALSE`; PFBL-01 `RequirePfbFilter` /
  `RequireConfigGateway` / `UppercaseBooleanLiteral` sniffs stay green. `str_*` over `preg_*` in
  per-line paths.
- Python: **stdlib only** (chrooted in Unbound's loader); `pfb_unbound.py` self-comparisons use
  `hashlib.md5`, never a cross-language digest (ADR-42).
- Locale (ADR-26): any `sort -u`/`uniq`/`comm` over the resulting domain/IP data keeps inline
  `LC_ALL=C`.
- Test-coverage mandate: behaviour-**preserving** phases pin the current behaviour as an
  **oracle** (green before *and* after); the byte-identity corpus IS that oracle. Delta rows are
  behaviour-**changing** and get red→green (OLD asserted on `devel`, NEW after). No phase
  without tests; no coverage theater.
- The `pfb_py_data`/`pfb_py_zone` staging dialect and the per-feed 6-col `.txt` dialect are
  cross-feature contracts (§1.5) — no phase may change them.

## 6. Action plan (phases — early ones are behaviour-preserving prep / de-risk)

### Phase 1 — Byte-identity corpus + coverage matrix (behaviour-preserving; THE de-risk)

- Prompt: `01_Byte_Identity_Corpus.txt`
- Re-derive the §"Coverage matrix" from a fresh grep of the live loop; assemble a fixture corpus
  (one small feed per matrix row; inert data — RFC 5737/3849 IPs, `uuid-*.com` — for anything a
  smoke test will resolve; the committed ADR-49 `tests/fixtures/feed_corpus/` samples are
  legitimate raw material for offline capture). Capture, from **`origin/devel`**, the exact
  domain set + DNSBLIP IP set each corpus feed produces, as golden fixtures — including the
  TLD-analysis output for a TLD-enabled row and the delta-table line classes (their OLD
  behaviour is the red half of the later red→green). This is the falsification harness every
  later phase is gated on — and a permanent regression net with standalone value even if the
  ADR is rejected.
- **Capture surfaces are PINNED (not the implementer's choice):** Python side via pytest
  (`build()`/`parse`/`parse_abp` with a hand manifest); manifest writer via PHPUnit driving
  `pfb_unbound_python_sources()` (mirror the existing `UnboundPythonSourcesTest.php`); TLD pass
  via PHPUnit driving `tld_analysis()` (standalone function, `inc:7570` — temp dirs + a
  `pfb_dnsbl.raw` fixture). The download loop itself has **no off-appliance driver** (nothing
  drives `sync_package_pfblockerng()`): loop-level rows are DEFERRED smoke rows with their
  exact live-VM command recorded per row — never a re-implementation of the loop inside a test
  (an oracle of a copy is coverage theater).
- Tests: a PHPUnit/pytest oracle that runs the corpus through today's parse path and asserts the
  captured golden output; a **vacuity check** (mutate one golden domain → oracle goes red).

### Phase 2 — De-tangle prep: IP collector + pure predicates (behaviour-preserving)

- Prompt: `02_Detangle_Prep.txt`
- Extract `pfb_dnsbl_collect_feed_ip(...)` (collapse the 6 IP-collection copies, §1.4);
  add `pfb_dnsbl_is_skippable_control_line($line): bool` (= `''`/`!`/`//`/`[…]`-non-IPv6,
  reusing `pfb_dnsbl_unbracket_ip6`/`is_ipaddrv6` for the carve-out); add
  `pfb_dnsbl_is_abp_rule_line($line): bool` (the Decision-2 capture shape set). All three are
  pure functions with oracle tests. **Wiring discipline:** the IP collector replaces its six
  call sites like-for-like; the two predicates are **NOT wired into the loop in this phase**
  beyond replacements that are provably exact-equivalent to an existing site's check — the
  universal application and the broadened capture are Phase 4, the classifier deletion Phase 5
  (a broader predicate at an existing site is NOT like-for-like).
- Tests: fail-on-mutation oracle for each helper; the Phase-1 corpus stays byte-identical.

### Phase 3 — Extend Python's per-line routing + parity oracle (the premise PROOF or REJECT)

- Prompt: `03_Python_Line_Dispatcher.txt`
- **Extend the existing ADR-21 routing in `build()` (@5045-5058)** — do NOT add a parallel
  dispatcher — so the plain-feed loop routes the full Decision-2 shape set (`||`, `@@…`,
  `/re/…`, element-hiding) to `parse_abp`, mirroring `pfb_dnsbl_is_abp_rule_line()`. Verify the
  permit-mode loop's skip set (@4993) stays consistent. Prove parity against the Phase-1 corpus
  (**parity oracle**): the routing's domain set == the golden set per format, delta rows
  asserting their NEW outcome. This phase is where byte-identity (modulo deltas) is PROVEN; a
  format it cannot reproduce triggers the §7 reject path.
- Hostile-input rows (REQUIRED test data, implementer fills results): IDN/punycode, #752
  undotted-254, #753 wire-cap, empty/whitespace/BOM-led, `@@||`, `@@/re/`, `/regex/`,
  `$important`, `$badfilter`, `[Adblock]`, element-hiding family (`##`, `#@#`, `#?#`, `#%#`,
  `#$#`, and `example.com##.ad`), `||1.2.3.4^`, bracketed-IPv6, bare-domain line (zone/data
  split, D1), mixed plain+`||`.
- Tests: parity oracle per format; the hostile-input table; red-run proof the oracle catches a
  deliberately wrong dispatch.

### Phase 4 — Broaden the capture + universal skip (behaviour-changing; deltas D2–D5 ONLY)

- Prompt: `04_Broaden_Capture.txt`
- Wire `pfb_dnsbl_is_abp_rule_line()` at the download-loop capture (@16317) and the manifest
  writer (@7030); apply the universal control-line skip in the plain path (Decision 4,
  unbracket-first ordering). **The classifier is NOT touched:** the loop guard is
  `!$easylist && (…)`, so this phase changes only unclassified (plain/permit) feeds — the
  delta set it may flip is exactly **D2/D3/D4/D5**; D1 must NOT move (ABP feeds still take the
  `$easylist` branch). The Phase-1 corpus oracle stays byte-identical outside those rows;
  D2–D5 rows get their red→green (OLD pinned by Phase 1, NEW asserted here).
- Tests: Phase-1 corpus green with exactly D2–D5 flipped; Semantics #2/#3 IP tests (bracketed
  IPv6 vs `[…]` skip); the manifest-writer golden reflecting the broadened passthrough.

### Phase 5 — Delete the classifier + retire the `.abp` marker (behaviour-changing; delta D1 ONLY)

- Prompt: `05_Delete_Classifier.txt`
- **First commit: the issue #1060 TLD-pass gate fix** — skip on an empty/unset feed column
  unconditionally (drop the `!empty($abp_feeds)` gate + marker glob, @7723-7744), red→green
  (the marker retirement below depends on it). **[2026-07-10 reconciliation, Phase 7]** As
  actually landed: `devel` PR #1066 (merged the day before this phase ran) had already made the
  comma-prefix guard unconditional and closed issue #1060; commit 1 delivered the SURVIVING
  piece PR #1066 left for this ADR — dropping the `$abp_feeds` marker-glob gate and its
  `isset($abp_feeds[$lfeed])` arm, so the empty-feed-column skip is unconditional on BOTH
  fronts. See `RESULTS/05_Results.txt` for the verified pre-edit state and the red→green proof.
  Then delete `$easylist` (all sites),
  `pfb_dnsbl_is_abp_header()` (+ `DnsblIsAbpHeaderTest.php`), the `$validate_header` block;
  collapse 16317/16324 into one verbatim path (the ABP branch's `pfb_dnsbl_abp_extract_ip`
  IP-extract survives the collapse, Semantics #2). Retire the `.abp` marker: reuse path
  (@16182) stops branching, writer sites (@16823-16827) deleted, stale markers swept.
  Collapse `format_hint` to `'plain'`; Python tolerates stale `'abp'` manifests (Semantics
  #7). The delta set this phase may flip is exactly **D1** (former-ABP feeds' bare lines);
  everything else — including the D2–D5 rows Phase 4 flipped — stays put.
- Tests: Phase-1 corpus green with exactly D1 flipped; symbol-anchored grep proof
  (Requirement 2); the #1060 red→green; reused old-dialect `.txt` + stale-manifest rows.

### Phase 6 — Perf validation + delete dead code

- Prompt: `06_Perf_And_Cleanup.txt`
- Benchmark a large hosts feed (≥1M lines) through the new path vs `origin/devel` — PHP parse
  loop and Python `build()` — with a stated methodology and the kill-threshold (default:
  **>25% wall-clock or >25% peak-RSS** regression on the 1M-line parse+build → §7 reject
  criterion 2). Expected result ~0 (the plain hot path gains only prefix checks); the benchmark
  exists to prove that, not to explore. Remove now-dead code surfaced by the Phase-4/5 diffs.
- Tests: the benchmark harness + its recorded numbers in the handoff; full suite green.

### Phase 7 — Docs, release-notes deltas, automated smoke rows

- Prompt: `07_Docs_Dod_Smoke.txt`
- Update `docs/misc/architecture-notes.md` "DNSBL/ABP pipeline" for the retired classifier +
  the per-line capture boundary; record the delta table where release notes are drafted from;
  add/extend the **automated** `tests/smoke/` feed cases so every §7 row runs in the ADR-04
  CE+Plus fan-out (CLAUDE.md "ADR acceptance": automated tests, not a manual sign-off); update
  this ADR's Status.

## 7. Definition of done

- All phases landed (`RESULTS/01–07_Results.txt` + gate records); full PHPUnit + pytest green;
  PHPCS/PHPStan clean; the **Phase-1 byte-identity corpus oracle green at the final phase**
  (delta rows asserting their NEW outcome).
- **Automated live-VM smoke rows (CE + Plus fan-out, ADR-04; per CLAUDE.md "ADR acceptance"
  these are `tests/smoke/` tests, not a manual checklist).** Each names a falsifiable
  observable; fixtures are inert (`helpers.unique_domain()`, RFC 5737/3849; never RFC 6761 or
  HSTS-preload):
  1. **Plain hosts feed**: a listed name → NOERROR + VIP/NULL per the list's `logging`; an
     unlisted name resolves. Same verdicts as the `origin/devel` baseline.
  2. **ABP feed content** (`||domain^`, `@@||exception^`, `! Title:` header, `[Adblock]`,
     `/regex/`, element-hiding line): `||` blocks, `@@` resolves, header/`[…]`/`##` lines
     produce no spurious domain — with NO `.abp` marker present.
  3. **Mixed plain feed** (hosts lines + stray `||domain^` + `/re/`): all block (D2 asserted).
  4. **Bracketed IPv6 (`[…]`) line** lands in the DNSBLIP alias; a genuine `[Adblock]` marker
     does not.
  5. **CSV feed** (one representative type): extracted domain blocks; detection unchanged.
  6. **IDN/punycode name** blocks under its punycode form.
  7. **Reused feed with old-dialect `.txt`** (no re-download) resolves the same verdicts
     (Semantics #7), and a **TLD-enabled** update run produces unchanged TLD classification
     for plain rows (Semantics #8).
- **Accepted** flips on the CE **and** Plus fan-out green (rows 1–7). Genuinely out-of-CI
  items (none currently identified) are documented limitations, not acceptance blockers.
- **Reject criteria (make the premise falsifiable — the ADR-01 discipline):**
  1. **Phase 3 parity fails** — the extended routing cannot reproduce `origin/devel`'s domain
     set (modulo the delta table) for some format, and no bounded, documented reconciliation
     closes the gap → **REJECT** the unification (retain Phases 1–2 prep, which are
     behaviour-preserving and independently valuable). Option B is NOT the fallback (§2 fork).
  2. **Phase 6 perf regresses** past the kill-threshold (>25% wall-clock or >25% peak-RSS on
     the 1M-line parse+build) → reject the capture-broadening approach.
  3. Any Semantics test that cannot pass without weakening its assertion, or any output change
     **outside the delta table** → REJECT (a weakened byte-identity assertion is coverage
     theater, not a pass).
