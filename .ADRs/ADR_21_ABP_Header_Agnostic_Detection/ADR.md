# ADR-21: ABP Header-Agnostic Detection

- **Status:** **Proposed** (2026-06-09)
- **Date:** 2026-06-09
- **Branch:** `adr/21-abp-header-agnostic-detection` (off `devel`)
- **Component(s):**
  `src/usr/local/pkg/pfblockerng/pfb_unbound.py` (Python `build()` loop),
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (PHP download loop + manifest builder)
- **Target runtime:** Python 3.11+ (Unbound pythonmod, stdlib only); PHP 8.3
- **Test suite:** `tests/` (pytest), `tests/php/` (PHPUnit)

## 1. Context

### 1.1 Today — feed classification

The current feed pipeline classifies entire feeds as either ABP or plain at download time:

- **ABP feed** (`$easylist = TRUE`): triggered when the download loop encounters one of the
  four known header strings (`[Adblock Plus` prefix, `[Adblock Plus]`, `[uBlock Origin`, `! Title:
  AdGuard`). Every line is then passed through verbatim to the `.txt` staging file; PHP
  extracts no domains. The manifest writer copies these verbatim lines to the per-feed `.raw`
  file with `format_hint = 'abp'`. Python's `build()` routes `fmt == "abp"` feeds to
  `parse_abp()` for every line.

- **Plain feed** (`$easylist = FALSE`): every domain line goes through PHP's plain-domain
  parser (`pfblockerng.inc:9646–9777`), is validated by `pfb_filter($line, PFB_FILTER_DOMAIN)`
  at line 9757, and written as a 6-column CSV (`,domain,,logging,header,alias`) to the `.txt`
  file. The manifest writer extracts column 1 (bare domain) into the per-feed `.raw` with
  `format_hint = 'plain'`. Python's `build()` routes `fmt != "abp"` feeds to `parse()`.

### 1.2 Today — plain-domain sub-paths

Within the plain-domain path PHP has two sub-paths (NOT ABP-related):

- **Lite** (`$lite = TRUE`, `pfblockerng.inc:9659–9669`): the line is already a bare
  alphanumeric+dots domain — no stripping needed.
- **Non-lite** (`$lite = FALSE`, lines 9672–9707): strips `://`, paths, `#`/`?`/`;` fragments,
  trailing port numbers. Used when the raw line contains a URL or other decorated form.

### 1.3 The gap — ABP entries in untagged / mixed feeds

Some curated block-lists ship without an ABP header but contain ABP-syntax entries
(`||domain^`, `@@||domain^`, `||domain^$important`, `||domain^$badfilter`). Currently:

1. PHP's lite/non-lite stripping leaves `||domain^` intact (no strippable chars present).
2. `pfb_filter($line, PFB_FILTER_DOMAIN)` at line 9757 rejects the line — `|` and `^` are
   not valid domain characters.
3. PHP logs it as a parse error and skips it — the entry is permanently lost.
4. Python never sees it.

The result: a list that mixes plain domains with `||domain^` (e.g., `@@||allow.me^`) silently
discards the ABP entries and never applies their semantics (block, allow, `$important`,
`$badfilter`).

### 1.4 Load-bearing constraints

- `pfb_unbound.py` runs inside Unbound's chroot — stdlib only, no new deps.
- PHP download loop runs at feed-refresh time on the pfSense appliance.
- The ABP-header path (whole-feed `$easylist = TRUE`) is **unchanged** — this ADR adds
  per-line detection inside the existing non-ABP path only.
- `parse_abp()` (`pfb_unbound.py:2997`) is already the authoritative ABP parser with full
  `@@`, `$important`, `$badfilter`, regex support. It is NOT modified in this ADR.
- `_dnsbl_parse_abp_line()` (`pfb_unbound.py:2873`) is the old basic-ABP token-strip (block
  only, ignores `@@`). It is referenced by `parse()` for `format_hint="abp"` feeds. After
  ADR-21, new per-line detection uses `parse_abp()` — not `_dnsbl_parse_abp_line()`.

## 2. Decision

### 2.1 Per-line detection rule

A line in a **non-ABP feed** that starts with `||` or `@@||` is an ABP-anchored entry.
It is detected and processed by `parse_abp()` — NOT by the plain-domain validator —
while every other line in the feed continues through the existing plain pipeline unchanged.

The feed-level `format_hint` remains `'plain'`; the per-line check is an internal routing
decision in `build()`, not a feed-mode switch.

### 2.2 Decision table

| Area | Current behaviour | New behaviour |
| ---- | ----------------- | ------------- |
| PHP download loop (non-ABP feed) | `\|\|domain^` → dropped at `pfb_filter()` (line 9757) | `startswith("\|\|")` or `startswith("@@\|\|")` before `pfb_filter()` → write verbatim to `.txt`; `continue` |
| PHP manifest builder (plain path) | reads col 1 from CSV | detect `startswith("\|\|")` / `startswith("@@\|\|")` → write verbatim to `.raw`; else CSV col-1 as before |
| Python `build()` (non-ABP loop) | `parse(fmt, raw_line)` for every line | if `raw_line.startswith("\|\|")` or `raw_line.startswith("@@\|\|")` → `parse_abp(raw_line, ...)` → append to `abp_rules` and `continue`; else unchanged |
| ABP-header feed | `fmt == "abp"` → `parse_abp()` for every line | **unchanged** |
| `parse_abp()` | unchanged | **unchanged** |
| `_dnsbl_parse_abp_line()` | called by `parse()` for `format_hint="abp"` | **unchanged** (not used by the new per-line path) |

### 2.3 Semantics that MUST be preserved (the contract — pinned by tests before changing)

1. **ABP-header feeds are unchanged:** `format_hint='abp'` feed → all lines through
   `parse_abp()` → no plain-domain processing. Per-line detection does NOT run.
2. **Plain domain entries in non-ABP feeds are unchanged:** a line that does NOT start
   with `||` or `@@||` follows the existing pipeline exactly (PHP stripping, validation,
   CSV, manifest builder col-1 extraction, Python `parse()`).
3. **`@@||domain^` in a non-ABP feed acts as an allow rule:** it reaches `parse_abp()`,
   which returns a `Rule` with kind `DNSBL_KIND_ALLOW`, which `reconcile()` places in
   the allow/white DB — even when the same domain is also blocked by a plain entry in
   the same or another feed.
4. **`||domain^$important` escalates to band 3:** `parse_abp()` returns `important=True`;
   `reconcile()` assigns `band=PRIO_IMPORTANT`.
5. **`||domain^$badfilter` cancels an existing block:** `reconcile()` removes the matching
   block from `data_db`/`zone_db`.
6. **`||domain.com^` yields `domain.com` blocked (wildcard=True):** the anchor is stripped
   by `parse_abp()` and the domain passes `normalise()`.
7. **Lines starting with `||` but containing `/` or `*` are skipped:** `parse_abp()` returns
   `None` for path/wildcard anchors; they are silently dropped.
8. **IP anchors (`||1.2.3.4^`) are skipped by Python:** `parse_abp()` returns `None` for
   IP-valued anchors (ADR-06 no-leak contract); the IP goes to the firewall path via the
   PHP `pfb_dnsbl_abp_extract_ip()` in the ABP block — but since this is a non-ABP feed
   the IP is already handled by PHP's IP collection at lines 9710–9731. No double-handling.

### 2.4 Explicitly kept / out of scope

- The whole-feed ABP mode (`$easylist`) and its PHP verbatim-write path are NOT touched.
- `_dnsbl_parse_abp_line()` is NOT modified or removed (still used by `parse()` for
  `format_hint="abp"` feeds).
- Regex ABP rules (`/re/`, `@@/re/`) in non-ABP feeds: supported by `parse_abp()` and will
  work correctly once the per-line routing is in place.
- The `format_hint` field in the manifest is NOT changed — `'plain'` feeds stay `'plain'`.
- The `$liteparser` PHP variable and lite/non-lite path are NOT changed.
- PHP DNSBL-IP extraction for non-ABP feeds (lines 9710–9731) is NOT changed.

## 3. Consequences

**Positive**

- ABP entries in untagged/mixed feeds are no longer silently discarded.
- `@@||allow.me^` allow-rules work as expected in mixed feeds.
- `$important` and `$badfilter` modifiers are honoured in mixed feeds.
- No new feed format or configuration key is needed.
- `parse_abp()` is reused unchanged — no risk of parser drift.

**Negative / risks**

- Feeds that accidentally contain `||` at the start of a non-ABP line (unlikely, but possible
  in malformed feeds) are now routed to `parse_abp()` instead of being dropped. A malformed
  `||` line that `parse_abp()` cannot parse returns `None` and is silently skipped — same
  observable outcome as today (dropped) but via a different code path.
- Slight per-line overhead in `build()` for non-ABP feeds: one `startswith` check per line.
  Negligible given feeds are processed offline, not per-query.

## 4. Requirements (acceptance)

1. A non-ABP feed `.raw` containing `||domain.com^` produces a DNSBL block for `domain.com`.
2. A non-ABP feed `.raw` containing `@@||domain.com^` produces an allow that overrides a
   block for `domain.com` from a plain entry in the same feed.
3. `||domain.com^$important` → `important=True` in the reconciled result (band 3).
4. `||domain.com^$badfilter` alongside a block for `domain.com` → the block is cancelled.
5. Plain domain lines in the same feed continue to be blocked normally (no regression).
6. ABP-header feeds produce identical results before and after this change (no regression).
7. PHP: `||domain^` in a non-ABP feed's `.txt` file is written verbatim (no leading comma).
8. PHP manifest builder: verbatim `||domain^` in `.txt` is passed verbatim to `.raw`.

## 5. Constraints (from CLAUDE.md)

- `pfb_unbound.py`: stdlib only; 4-space indent; type hints; no bare `except:`; runs in
  Unbound's chroot (no filesystem access to the host-absolute `/etc/inc/` path).
- PHP: tabs; PHP 8.3; no `die()`/`exit()` in library code.
- All new Python tests: typed, named for intent, branch-covering, before/after state asserted.
- `python -m pytest` + `ruff check .` + `ruff format .` + `mypy tests/` must stay green.
- PHP: `php -l` + PHPStan on each modified file; PHPUnit for the PHP test additions.

## 6. Action plan

### Phase 1 — Python per-line detection in `build()` + unit tests

Prompt: `01_Python_Per_Line_Detection.txt`

- In `pfb_unbound.py` `build()` at the start of the non-ABP feed loop (~line 3899):
  add a `startswith("||") or startswith("@@||")` guard before `parse(fmt, raw_line)`;
  route matching lines to `parse_abp()` → `abp_rules`; `continue`.
- New test file `tests/test_adr21_abp_per_line.py`:
  fixture `.raw` strings with mixed plain + ABP lines; BDD-style scenarios for all §4
  acceptance requirements; before-state assertions (plain feed without `||` lines →
  no such block in the result).

### Phase 2 — PHP companion: download loop + manifest builder

Prompt: `02_PHP_Companion.txt`

- `pfblockerng.inc` download loop (~line 9754): insert `startswith("||") or "@@||"` guard
  before `pfb_filter()` domain validation; write verbatim to `.txt`; `continue`.
- `pfblockerng.inc` manifest builder (~line 3600): insert same guard before CSV col-1
  extraction; write verbatim to `.raw`; `continue`.
- PHPUnit tests (or Python integration test) proving: verbatim pass-through to `.txt`
  and to `.raw`; existing plain CSV path unaffected; ABP-header feed unaffected.

### Phase 3 — Smoke + DoD

Prompt: `03_Smoke_DoD.txt`

- Smoke case: deploy a mixed custom-list feed containing `||domain^` + `@@||allow^` + plain
  domains; assert correct block/allow resolution on the live VM.
- Update inline documentation comments at the modified call sites.
- Record DoD evidence in `RESULTS/03_Results.txt`.

## 7. Definition of done

All criteria must be met and evidence recorded in `RESULTS/03_Results.txt`:

- `python -m pytest` → green (all new tests pass; no regressions in `test_adr07_*`).
- `ruff check . && ruff format .` → clean.
- `mypy tests/` → clean.
- `php -l src/usr/local/pkg/pfblockerng/pfblockerng.inc` → no syntax error.
- PHPUnit → green (existing + new PHP tests).
- Phase 3 smoke: `||domain^` in a custom-list produces a DNSBL block on the live VM.
- Phase 3 smoke: `@@||domain^` in a custom-list cancels a plain-entry block.

**Manual smoke checklist** (maintainer, live pfSense box):

1. Create a DNSBL Group with a Custom_List entry containing:
   - `||block-me-abp.com^`
   - `@@||allow-me-abp.com^`
   - `plain-block.com` (plain entry)
   - `@@||plain-block.com^` (allow overrides the plain block)
2. Run pfBlockerNG → DNSBL update; verify no parse errors in the log.
3. `drill @127.0.0.1 block-me-abp.com` → NXDOMAIN or sinkhole VIP (blocked).
4. `drill @127.0.0.1 allow-me-abp.com` → NOERROR + real IP (allowed).
5. `drill @127.0.0.1 plain-block.com` → NOERROR + real IP (allow overrides plain block).
6. Add `||block-me-abp.com^$important` to a second Custom_List entry; run update; confirm
   `block-me-abp.com` is still blocked (important flag preserved, no regression).

**Reject criteria:**

- Any of requirements §4.1–§4.8 fails in tests after Phase 1 or Phase 2.
- The ABP-header feed regression test fails (§4.6).
- Smoke checklist items 3–5 fail on a live CE box.
- `pfb_filter()` drop-rate on legitimate domains increases (parse-error count in
  diagnostics rises on feeds that previously had 0 errors).
