# ADR-21: ABP Header-Agnostic Detection

- **Status:** **Accepted** (2026-06-15 — validated end-to-end on live pfSense CE 2.8 and
  Plus 26.03 VMs by the §6 smoke cases `test_abp_perline_detection_in_plain_feed`,
  `test_abp_bom_header_still_detected`, `test_abp_perline_path_anchor_not_overblocked`;
  2026-06-09 proposed; amended 2026-06-12 — per-feed `auto`/`abp` format selector dropped in
  favour of a broadened header sniff, see §2.4)
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

A second face of the same gap is the header sniff itself: it matches only four magic strings
(the `[Adblock Plus` prefix / `[Adblock Plus]` / `[uBlock Origin` / `! Title: AdGuard`, scanned only in
the leading `!`-comment block — `pfblockerng.inc:9506–9521`). A conventionally-authored ABP
list led by any *other* `! Title:` (e.g. HaGeZi's ABP-format DNS lists) is not detected and
falls to the plain path, where today its `||` entries are dropped (item 2 above), its regex
rules are dropped, and any cosmetic rule (`x.com##.ad`) is mangled by the `#`-fragment strip
into a false plain-domain block of `x.com`.

### 1.4 Load-bearing constraints

- `pfb_unbound.py` runs inside Unbound's chroot — stdlib only, no new deps.
- PHP download loop runs at feed-refresh time on the pfSense appliance.
- The ABP-header *path* (whole-feed `$easylist = TRUE`) is **unchanged** — only its
  *trigger* broadens (the header sniff, §2.4). The per-line detection is added inside the
  existing non-ABP path only.
- `parse_abp()` is a **superset** parser: besides `||`/`@@||`/regex it KEEPS hosts lines
  (`<ip> domain`) and bare plain domains as blocks (`pfb_unbound.py:3011–3016`). A feed
  flipped to whole-feed ABP therefore still blocks its plain-domain entries — this is what
  makes broadening the sniff safe.
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
| Header sniff (download loop, leading `!`-block only) | 4 magic strings (`[Adblock Plus` prefix, `[Adblock Plus]`, `[uBlock Origin`, `! Title: AdGuard`) | generic prefixes: line starts with `[Adblock`, `[uBlock`, or `! Title:` → `$easylist = TRUE`; scan window unchanged |
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
5. **`||domain^$badfilter` cancels a matching SAME-STREAM ABP block:** `$badfilter` is a
   feed-only, signature-matched prune performed inside `reconcile()` over the `abp_rules`
   stream (ADR-07 Stage-B step 1). It cancels a matching ABP `Rule` — a `||domain^` block
   that was also routed to the stream (whether from a whole-feed ABP feed or, post-ADR-21,
   from a per-line-detected `||domain^` in a non-ABP feed). It does NOT prune a plain-path
   block: a bare-domain line is materialised straight into `data_db`/`zone_db` and is never
   a `Rule`, so `reconcile()` has no signature to match against it. Cross-pipeline
   cancellation (a plain block pruned by an ABP `$badfilter`) is out of scope — it would
   require modifying the frozen `reconcile()`/`build()`.
6. **`||domain.com^` yields `domain.com` blocked (wildcard=True):** the anchor is stripped
   by `parse_abp()` and the domain passes `normalise()`.
7. **Lines starting with `||` but containing `/` or `*` are skipped:** `parse_abp()` returns
   `None` for path/wildcard anchors; they are silently dropped.
8. **IP anchors (`||1.2.3.4^`) are skipped by Python:** `parse_abp()` returns `None` for
   IP-valued anchors (ADR-06 no-leak contract); the IP goes to the firewall path via the
   PHP `pfb_dnsbl_abp_extract_ip()` in the ABP block — but since this is a non-ABP feed
   the IP is already handled by PHP's IP collection at lines 9710–9731. No double-handling.
9. **The four legacy magic strings stay detected:** every feed flipped to ABP by today's
   sniff is still flipped after broadening (the generic prefixes are a superset of the
   four strings). The scan window is unchanged — only the leading `!`-comment block is
   sniffed; a `! Title:`-like token after the first data line does NOT flip the feed.

### 2.4 Broadened header detection (no per-feed selector, no new config key)

There is **no per-feed format selector and no new configuration key**. An earlier draft
proposed a per-feed `'auto'`/`'abp'` selector; it was dropped — the residual case it
covered is near-empty (see below) and a config key is forever. Instead the existing header
sniff is broadened from four magic strings to the generic ABP header convention:

- A line in the leading `!`-comment block starting with **`[Adblock`**, **`[uBlock`**, or
  **`! Title:`** sets `$easylist = TRUE`. The three prefixes cover all four legacy magic
  strings. The scan window is exactly today's (`$validate_header` flips on the first
  non-`!`, non-header line and sniffing stops); the check is a **prefix** match
  (`str_starts_with`), not today's mid-line `strpos`, so a `! Title:` token inside a data
  line cannot flip the feed.

Why this is safe and sufficient:

- Every conventionally-authored ABP list ships a `[Adblock …]` and/or `! Title:` header —
  the four magic strings were the brittle part, not the convention.
- `parse_abp()` is a superset parser (§1.4): a false-positive flip on a mixed or
  mostly-plain list still blocks its bare-domain entries correctly. The only line shapes
  whole-feed ABP handles *worse* than the plain path are URL/CSV-decorated lines
  (`http://x/path`, 6-col CSV) — and those do not co-occur with `! Title:` headers in
  practice.
- **Residual uncovered case:** a headerless, title-less ABP feed containing regex or
  cosmetic rules. Accepted gap — anchored `||`/`@@||` entries in such a feed are still
  caught by per-line detection (§2.1); a per-feed selector can be revisited later on real
  demand.

One behavioural delta vs today worth naming: the legacy check used `strpos(...) !== FALSE`
(mid-line match anywhere in a header-window line); the new check is a leading-whitespace-
tolerant prefix match. Within the `!`-comment window this is equivalent for real feeds
(headers start their line); the prefix form is strictly safer.

**Why a feed-level ABP bit must exist at all — pure per-line routing considered and
rejected.** "Route every line to the right parser by its own shape" was examined as the
simpler alternative (no header sniff, no feed mode). It cannot work, because several line
shapes demand *opposite* correct handling depending on what the feed is, and that context
is not reconstructible line-locally:

- `x.com/path` — in a plain/URL feed the non-lite stripper recovers `x.com` and blocks it;
  in an ABP list it is a URL-path rule that must NOT DNS-block `x.com` (overblock).
  Same bytes, opposite outcomes.
- `/ads/` — junk to drop in a plain feed; a live regex rule in an ABP list. Routing it
  per-line would turn path-like junk into a regex matching every name containing "ads".
- `x.com##.ad` — cosmetic rule to drop in an ABP list; under the plain stripper it
  degrades to a block of `x.com`.
- The plain path additionally owns the CSV dialects (`pt`/`bbc`/`h3x`/`otx`/`pon`/`et`,
  `pfblockerng.inc:9649+`) and bare-IP collection — shapes `parse_abp()` correctly refuses.

Per-line detection therefore covers exactly the *self-identifying* subset — `||`/`@@||`
anchors, which are not valid in any plain dialect — and everything context-dependent rides
the feed-level bit. The feed's header is the only signal available for that bit, which is
why the (pre-existing) sniff stays and is merely broadened, not why new machinery is added.
Unifying the two pipelines so PHP passes every feed verbatim and Python owns all parsing
would dissolve the split for real, but that is a rework of the whole download/manifest
contract (CSV dialects, IP extraction, IDN) — out of ADR-21's scope; a candidate future ADR.

### 2.5 Explicitly kept / out of scope

- `_dnsbl_parse_abp_line()` is NOT modified or removed (still used by `parse()` for
  `format_hint="abp"` feeds).
- Regex ABP rules (`/re/`, `@@/re/`) in **undetected** (headerless, title-less) feeds are
  **deliberately dropped**, exactly as today. The per-line guard matches only `||`/`@@||`:
  a leading `/` is ambiguous in a plain feed (a path-like line `/ads/` must NOT become a
  regex rule blocking every name containing "ads"), and PHP's `pfb_filter()` rejects such
  lines before Python ever sees them. Regex rules work only in feeds detected as whole-feed
  ABP (magic string, `[Adblock`, or `! Title:`).
- Cosmetic rules (`x.com##.ad`) in undetected feeds keep today's behaviour (the
  `#`-fragment strip yields a plain block for `x.com`). The broadened sniff shrinks this
  pre-existing hazard to title-less feeds; a per-line cosmetic guard is out of scope.
- The `$liteparser` PHP variable and lite/non-lite path are NOT changed.
- PHP DNSBL-IP extraction for non-ABP feeds (lines 9710–9731) is NOT changed.
- **Existing `test_adr07_*` tests are a frozen regression oracle:** no existing test
  function in any `test_adr07_*.py` file is modified, renamed, deleted, re-parametrized,
  or split. They must pass byte-for-byte identical (functionally unmodified) after every
  phase. The only tests that may be written, updated, or removed are ones that were
  explicitly probing behavior that changes in this ADR (e.g., a test that asserted a
  mixed-feed `||` line is NOT blocked — that before-state assertion is valid to keep and
  becomes the BEFORE half of a transition test).

## 3. Consequences

**Positive**

- ABP entries in untagged/mixed feeds are no longer silently discarded.
- `@@||allow.me^` allow-rules work as expected in mixed feeds.
- `$important` and `$badfilter` modifiers are honoured in mixed feeds.
- `! Title:`-led ABP lists (HaGeZi-class) are whole-feed detected with zero configuration —
  regex + cosmetic rules in them handled correctly by `parse_abp()` instead of mangled.
- No new feed format, per-feed selector, UI field, or configuration key is needed.
- `parse_abp()` is reused unchanged — no risk of parser drift.

**Negative / risks**

- Feeds that accidentally contain `||` at the start of a non-ABP line (unlikely, but possible
  in malformed feeds) are now routed to `parse_abp()` instead of being dropped. A malformed
  `||` line that `parse_abp()` cannot parse returns `None` and is silently skipped — same
  observable outcome as today (dropped) but via a different code path.
- Slight per-line overhead in `build()` for non-ABP feeds: one `startswith` check per line.
  Negligible given feeds are processed offline, not per-query.
- The broadened sniff flips any feed whose leading `!`-comment block carries `! Title:`
  (or `[Adblock`) to whole-feed ABP. For a genuinely plain list with such a header the
  outcome is equivalent (`parse_abp()` keeps bare domains); only URL/CSV-decorated lines
  in such a feed would regress — judged not to occur in practice (`!` headers are an ABP
  convention; hosts/URL feeds comment with `#`).
- A headerless, title-less ABP feed with regex/cosmetic rules remains imperfect (regex
  dropped, cosmetics mangled — pre-existing behaviour). Accepted; revisit a per-feed
  selector only on real demand.

## 4. Requirements (acceptance)

1. A non-ABP feed `.raw` containing `||domain.com^` produces a DNSBL block for `domain.com`.
2. A non-ABP feed `.raw` containing `@@||domain.com^` produces an allow that overrides a
   block for `domain.com` from a plain entry in the same feed.
3. `||domain.com^$important` → `important=True` in the reconciled result (band 3).
4. `||domain.com^$badfilter` alongside a SAME-STREAM ABP block `||domain.com^` (both routed
   to `abp_rules`) → the ABP block is cancelled. (A plain-path block of `domain.com` is NOT
   cancelled — `$badfilter` prunes only matching `abp_rules`; see §2.3.5.)
5. Plain domain lines in the same feed continue to be blocked normally (no regression).
6. ABP-header feeds produce identical results before and after this change (no regression).
7. PHP: `||domain^` in a non-ABP feed's `.txt` file is written verbatim (no leading comma).
8. PHP manifest builder: verbatim `||domain^` in `.txt` is passed verbatim to `.raw`.
9. Broadened header sniff: a feed whose leading `!`-comment block contains a line starting
   `! Title:` (any title), `[Adblock`, or `[uBlock` → `$easylist = TRUE`, manifest
   `format_hint = 'abp'` — identical outcome to a magic-string-detected ABP feed today.
   All four legacy magic strings still detect (regression).
10. Sniff scope unchanged: a `! Title:`-like token appearing only AFTER the first
    non-comment line does NOT flip the feed; a feed with no recognizable header stays
    `'plain'` and gets per-line detection only.
11. **Red→green proof (no coverage theater):** every test pinning changed behaviour
    (§4.1–§4.4, §4.7–§4.9) demonstrably FAILS against the pre-change code and passes
    after it. A new test that passes pre-change pins nothing and must be fixed.
    Deliberate regression pins (§4.5, §4.6, §4.10 — freezing unchanged behaviour) pass
    on both sides by design and are named as such in RESULTS.

## 5. Constraints (from CLAUDE.md)

- `pfb_unbound.py`: stdlib only; 4-space indent; type hints; no bare `except:`; runs in
  Unbound's chroot (no filesystem access to the host-absolute `/etc/inc/` path).
- PHP: tabs; PHP 8.3; no `die()`/`exit()` in library code.
- All new Python tests: typed, named for intent, branch-covering, before/after state asserted.
- **Regression testing is explicit (red→green):** tests must prove the solution, not
  merely execute it. Each phase writes its behaviour-pinning tests FIRST, runs them
  against the unmodified source, and records the RED output in its RESULTS handoff;
  only then applies the change and records the GREEN run. Tests that cannot go red
  (deliberate regression pins; off-appliance simulations of PHP logic) are exempt but
  must be named as such in RESULTS.
- `python -m pytest` + `ruff check .` + `ruff format .` + `mypy tests/` must stay green.
- PHP: `php -l` + PHPStan on each modified file; PHPUnit for the PHP test additions.
- **ABP test-suite freeze:** every existing test function in `test_adr07_*.py` (and every
  other pre-existing test file) must pass completely functionally unmodified after every
  phase. Do not modify, rename, delete, re-parametrize, or split any existing test
  function. The new `tests/test_adr21_abp_per_line.py` file is the only permitted
  addition. This rule applies unconditionally — even if refactoring appears convenient.

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

### Phase 2 — PHP companion: download loop + manifest builder + broadened header sniff

Prompt: `02_PHP_Companion.txt`

- `pfblockerng.inc` download loop (~line 9754): insert `startswith("||") or "@@||"` guard
  before `pfb_filter()` domain validation; write verbatim to `.txt`; `continue`.
- `pfblockerng.inc` manifest builder (~line 3600): insert same guard before CSV col-1
  extraction; write verbatim to `.raw`; `continue`.
- **Broadened header sniff:** replace the four magic-string tests (~lines 9508–9511) with
  generic prefix checks (`[Adblock`, `[uBlock`, `! Title:`) inside the same
  `$validate_header` window. No manifest change needed — `format_hint` already follows
  `$easylist`.
- PHPUnit/Python tests: verbatim pass-through to `.txt` and `.raw`; `! Title:` feed flips
  to whole-feed ABP; each legacy magic string still flips; a `! Title:` after the first
  data line does NOT flip; headerless plain feed unchanged.

### Phase 3 — Smoke + DoD

Prompt: `03_Smoke_DoD.txt`

- Smoke case: deploy a mixed custom-list feed containing `||domain^` + `@@||allow^` + plain
  domains; assert correct block/allow resolution on the live VM.
- Update inline documentation comments at the modified call sites.
- Record DoD evidence in `RESULTS/03_Results.txt`.

## 7. Definition of done

All criteria must be met and evidence recorded in `RESULTS/03_Results.txt`:

- `python -m pytest` → green (all new tests pass; no regressions in `test_adr07_*`).
- Red→green evidence: RESULTS record each behaviour-pinning test FAILING pre-change
  (exact output) and passing post-change; regression pins and exempt simulations named.
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
7. Point a DNSBL feed at a `! Title:`-led ABP list carrying none of the four legacy magic
   strings (e.g. a HaGeZi ABP-format list); run update; verify the feed is detected as ABP
   (no parse errors, `||` entries block).

**Reject criteria:**

- Any of requirements §4.1–§4.10 fails in tests after Phase 1 or Phase 2.
- The ABP-header feed regression test fails (§4.6).
- Smoke checklist items 3–5 fail on a live CE box.
- `pfb_filter()` drop-rate on legitimate domains increases (parse-error count in
  diagnostics rises on feeds that previously had 0 errors).
