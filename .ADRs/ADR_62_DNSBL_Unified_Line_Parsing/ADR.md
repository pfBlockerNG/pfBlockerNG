# ADR-62: Unify DNSBL feed line parsing — retire PHP feed-level ABP classification, make Python the single per-line authority

- **Status:** **Proposed** (2026-07-09)
- **Date:** 2026-07-09
- **Branch:** `adr/62-dnsbl-unified-line-parsing` (off `devel`; `{slug}` = sanitised ADR-title
  slug per CLAUDE.md "Branch naming") / **Component(s):** `pfblockerng.inc` (the DNSBL feed
  parse loop inside `sync_package_pfblockerng()`, the feed-manifest writer, the ABP header
  sniff), `pfb_unbound.py` (`parse`/`parse_abp` and a new per-line dispatcher), `tests/php/`,
  `tests/` (pytest), `tests/smoke/`.
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); Python 3.11+, stdlib only (chrooted in Unbound's
  Python loader — `parse_abp`/`parse` already live there).
- **Test suite:** `tests/php/` (PHPUnit — the extracted PHP helpers + byte-identity staging
  oracles), `tests/` (pytest — the Python per-line dispatcher parity oracle), `tests/smoke/`
  (ADR-04 live VM — feed-format fan-out) + `tests/smoke/ui/` (only if any `www/` surface moves;
  none currently planned).

---

## 1. Context — today

### 1.1 The DNSBL feed parse loop and its feed-level ABP classifier

`sync_package_pfblockerng()` (`src/usr/local/pkg/pfblockerng/pfblockerng.inc`, **14832–19311 =
4480 lines** on `origin/devel` @ `8563ac5d`) contains the DNSBL feed download+parse loop
(`while (($line = @fgets(...)))` @**16262**, ends ~**16715**). Per line it classifies, strips,
and extracts a domain (or an IP) and writes the result to a per-feed `.bk` staging file.

The loop maintains a **feed-level** notion of "is this an ABP/EasyList feed?" in `$easylist`, set
by a one-shot header sniff:

```php
// inc:16283-16294 — the $validate_header scan window
if (!$validate_header) {
    if (pfb_dnsbl_is_abp_header($line)) { $easylist = $validate_header = TRUE; continue; }
    elseif (str_starts_with($line, '!')) { continue; }   // redundant with the body '!' skip
    else { $validate_header = TRUE; }
}
```

`pfb_dnsbl_is_abp_header()` (`inc:6547`, ADR-21) prefix-matches `[Adblock` / `[uBlock` /
`! Title:` (BOM-tolerant). **Its sole unique effect is flipping `$easylist`**; the `!`-skip inside
the block duplicates the body `!`-skip (16412). `$easylist` then drives three body branches:
`!$easylist && (|| / @@||)` verbatim-capture @**16317**; `if ($easylist)` block @**16324**
(IP-extract + write raw ABP lines verbatim); `if (!$easylist)` host-format extraction @**16572**.

### 1.2 The manifest boundary: `format_hint` = 'abp' | 'plain' | 'csv:*'

PHP tags each feed's format in `pfb_feed_manifest_row()` (`inc:6946`): `$format =
($feed['format'] === 'abp') ? 'abp' : 'plain'` (`inc:6990`); the loop derives 'abp' from the
persisted `{$header}.abp` marker (`inc:16182`) and tags ABP feeds 'abp' (`inc:16810`). `$easylist`
is what sets that tag. Per `inc:6966-6967`: **'plain' feeds' `.raw` is the PHP-extracted
bare-domain output of the parsed `.txt`; 'abp' feeds copy their RAW lines verbatim** for Python.
So today PHP does the domain extraction for plain feeds; Python re-parses only ABP feeds.

Python dispatches on the hint: `parse(format_hint, line)` (`pfb_unbound.py:4050`) and the build
loop `if fmt == "abp": rule = parse_abp(...)` (`pfb_unbound.py:5039`).

### 1.3 Python is already architected to be the single per-line parser

`parse(format_hint, line)` (`pfb_unbound.py:4050`) has `abp` / `csv:pon` / `hosts-plain`
branches and its docstring (`:4053-4064`) states it **"subsumes the current basic-ABP token-strip
and reproduces today's per-format behaviour, including which lines are IGNORED."** It drops `!` /
`[` / `#` control lines and drops bare IPv4 (IP extraction is a PHP concern, `:4057`, `:4102`).

`parse_abp()` (`pfb_unbound.py:3869`; line helper `_dnsbl_parse_abp_line` `:3746`, regex helper
`_dnsbl_parse_abp_regex` `:3838`) is the ADR-07 Stage-A parser: it handles **every** ABP shape —
`||domain^`, `@@||`, `/regex/`, `@@/re/`, `$important`, `$badfilter`, and hosts/plain (Rule model
docstring `:3536-3542`, `:3567`) — emitting typed banded `Rule`s (block/allow, important, badfilter,
provenance). **`parse()` and `parse_abp()` are NOT interchangeable:** the plain branch of `parse()`
*drops* `@@`/regex/`$options` (`:4062-4064`); `parse_abp` keeps and bands them.

### 1.4 IP extraction stays in PHP

"IP extraction is NOT Python's job — it stays in PHP" (`pfb_unbound.py:3510-3511`, `:4057`). ABP-
anchored IPs (`||1.2.3.4^`, via `pfb_dnsbl_abp_extract_ip` `inc:6361`) and hosts-line IPs are
collected to the firewall/DNSBLIP aliases (`$domain_data_ip`/`_ip6`, six copies: `inc:16343/16349`,
`16495/16504`, `16654/16665`). Bracketed IPv6 literals `[2604:2dc0::]` (issue #938) are unwrapped
by `pfb_dnsbl_unbracket_ip6()` (`inc:6486`, iff `is_ipaddrv6(inner)`) and collected as IPs — **they
are addresses, not ABP `[section]` comments.**

### 1.5 Known PHP↔Python parse divergences (the byte-identity risk surface)

The Python side documents places it deliberately differs from the PHP gate — each is a byte-
identity falsification target for this ADR, not a blocker assumed away:

- `normalise()` (`pfb_unbound.py:4152`) rejects a bare 254-char **undotted** name that PHP's
  `strlen < 255` tolerates (#752, `:4159-4167`).
- Wire-caps (#753): `_dnsbl_within_wire_caps` (`:4122`) enforces ≤253 total / ≤63 per label; the
  PHP path's caps must be checked for exact parity.
- IDN/punycode: PHP converts non-ASCII via `idn_to_ascii` (`inc:16641-16657`); the Python
  per-line path's IDN handling must be confirmed equivalent.

### 1.6 Recent related work

Commit `8563ac5d` (#993/#995) extracted three **coverage-only** pure helpers (no dedup):
`pfb_dnsbl_hash_line_classify()` (`inc:6564`, the `#`-marker classifier), and — in the *separate*
generic IP-list loop — `pfb_ip_is_opposite_family()` (`inc:4535`) and `pfb_ip_parse_fail_warn()`
(`inc:4502`). Reuse the `#`-classifier; the other two are out of this ADR's loop.

---

## 2. Decision

**Retire PHP's feed-level ABP classification and make the Python side the single per-line
authority for turning a raw feed line into a domain rule.** Concretely:

1. **Delete `$easylist`, `pfb_dnsbl_is_abp_header()`, and the `$validate_header` scan block.** No
   feed-level "is this ABP?" state; no header expectation.
2. **Add a Python per-line dispatcher** that, for one raw line, routes to `parse_abp` (ABP-shaped)
   or the plain/hosts path, reproducing today's per-format output — the ABP-shape detection lives
   **only** in Python (`parse_abp`'s existing recognition), never re-implemented in PHP, so there
   is no cross-language drift.
3. **PHP passes raw domain lines through to Python** for the domain build (as ABP feeds already do
   today) instead of PHP-extracting bare domains for plain feeds. PHP retains **IP extraction**
   (§1.4) and **CSV column extraction** (§2.4 out of scope).
4. **Universal comment/control skip** in PHP's remaining IP-scan pass: skip `^\s*!` and `^\s*\[…\]`
   lines everywhere — **except** a bracketed IPv6 literal, which is an IP to collect (§1.4). Order:
   unbracket/collect IPv6 first via `pfb_dnsbl_unbracket_ip6()`, then any surviving `[…]` is an ABP
   marker → skip. Predicate: `starts '[' && ends ']' && !is_ipaddrv6(inner)`.

### The realization fork (the design decision this ADR commits to)

Two ways to make Python the authority; this ADR commits to **Option A** and keeps **Option B** as
the documented fallback triggered by the §7 reject criteria:

- **Option A — per-line dispatch, two parsers kept (COMMITTED).** A raw line flows to a Python
  dispatcher that recognises ABP-shaped lines (`||`/`@@`/`/re/`/`$options`, via `parse_abp`'s own
  recogniser) and routes them to `parse_abp`; everything else takes the existing `parse()` plain/
  hosts path. Plain feeds keep the cheap `parse()` path (no band/reconcile cost); ABP rules keep
  their banded semantics. `format_hint` for domain feeds collapses to a single "domain" hint (CSV
  hints stay); the abp/plain split disappears from PHP. **Lowest behaviour-change surface** — a
  plain feed's lines still go through the same `parse()` path they effectively do today, and ABP
  rules still go through `parse_abp`.
- **Option B — one parser (`parse_abp`) for all domain feeds (FALLBACK).** Route every domain line
  through `parse_abp` (it handles hosts/plain too). Simplest conceptually, but every plain feed
  then pays the reconcile/band cost and gains ABP semantics — a perf and behaviour risk on giant
  hosts feeds. Only taken if Option A's dispatcher cannot reproduce today's output.

### Semantics that MUST be preserved (the contract — pin with tests before any swap)

1. **Byte-identical domain set.** For every feed format in the §"Coverage matrix", the set of
   domains loaded into the DNSBL block dicts (and their log/exact-vs-wildcard classification) is
   **byte-identical** to `origin/devel` — proven by the Phase-1 corpus oracle, before any wiring
   change. This is the ADR's load-bearing claim; §7 rejects the ADR if it fails.
2. **Byte-identical firewall IP set.** The DNSBLIP `$domain_data_ip`/`_ip6` set collected per feed
   is unchanged (IP extraction stays in PHP, §1.4) — including ABP-anchored IPs and bracketed IPv6
   literals.
3. **Bracketed IPv6 is never skipped as a comment** (§1.4 / Decision 4): `[2604:2dc0::]` collects
   as an IP; only a non-IPv6 `[…]` is dropped.
4. **ABP rule semantics preserved:** `@@` allow, `/regex/`, `$important`, `$badfilter`, provenance
   and banding for genuine ABP feeds are unchanged (still via `parse_abp`).
5. **Comment/blank handling is a superset-safe no-op on output:** dropping `!`/`#`/`[…]`-non-IPv6
   lines anywhere yields the same domain/IP set as today's scattered skips.
6. **hpHosts stop-marker, Spamhaus `$rev_format`, h3x CSV-header** (the `#`-classifier,
   `pfb_dnsbl_hash_line_classify`) keep their current effect — this ADR does not alter the CSV or
   rev-format paths (§2.4).
7. **A `.abp` on-disk marker / a reused (not re-downloaded) feed** still resolves to the same parse
   routing after `$easylist` is gone (the marker's role in `format_hint` is migrated, not dropped).

### Coverage matrix (feed formats — enumerated from the loop; Phase 1 re-derives from source)

Each row is a byte-identity axis the Phase-1 corpus must include and every later phase must keep
green: **plain hosts feed** (`0.0.0.0 domain` / `domain`); **ABP/EasyList feed** (`||domain^`,
`@@||`, `! Title:` header, `[Adblock]`, `/regex/`, `$important`, `$badfilter`); **mixed feed**
(plain feed carrying stray `||domain^`); **Spamhaus rev_format**; **hpHosts** end-marker; **CSV
types** `pt(8) · bbc(4) · h3x(8) · otx(3) · pon(9) · et(3)` + header-sniff feeds `phishtank ·
bambenek · otx · ponomocup · et`; **custom (`$liteparser`) list**; **IDN/punycode** line; **bare
IPv4 / IPv6 / bracketed-IPv6** line; **ABP-anchored IP** (`||1.2.3.4^`); **oversized/#752 undotted**
name; **wire-cap (#753)** name; empty / whitespace / BOM-led first line.

### Explicitly kept / out of scope

- **CSV column extraction stays in PHP.** The 6-type CSV switch (`inc:16426–16562`, R4 in the
  design notes) and the `#`-header classifier are not moved to Python here — PHP still extracts the
  domain column and feeds it to the Python domain path. A future ADR may lift CSV into Python
  (`parse()` already has `csv:pon`). This ADR touches CSV only where `$easylist` removal forces it.
- **The IP-collection triplication (R2)** is de-tangled as behaviour-preserving prep (Phase 2)
  because this ADR's IP-scan pass touches those sites — but it is a pure extraction, not a
  behaviour change.
- **The generic IP-list loop** (`pfb_ip_is_opposite_family` etc.) — different loop, untouched.
- **Option B** unless the reject criteria trigger it.

## 3. Consequences

**Positive**

- Deletes the entire feed-level ABP classification + header-detection state machine
  (`$easylist`, `pfb_dnsbl_is_abp_header`, `$validate_header`) — no header expectation, no
  cross-language ABP-detection drift (one authority: `parse_abp`).
- Collapses the doubled ABP-verbatim paths (16317/16324) into one raw-passthrough.
- Shrinks `sync_package_pfblockerng()` and makes the per-line flow linear and testable.
- Sets up (does not do) the later CSV-into-Python lift by proving the raw-passthrough boundary.

**Negative / risks**

- **Byte-identity across the PHP↔Python boundary is the whole risk** (§1.5). If the Python per-
  line path diverges from PHP's extraction on any format (IDN, #752 undotted, wire-caps, a CSV
  edge), a feed silently loses or gains domains — a blocklist regression. Mitigated by the Phase-1
  corpus oracle gating every later phase, and the §7 reject criteria.
- **Perf** (Option B only): routing plain feeds through `parse_abp`'s band/reconcile path adds
  per-line cost on giant hosts feeds — a §7 kill-threshold. Option A avoids this by keeping the
  cheap `parse()` path for non-ABP lines.
- Moving domain extraction off PHP shifts per-update work to the Python loader (chrooted, single-
  threaded) — measured in Phase 5.

## 4. Requirements (acceptance)

1. For every §"Coverage matrix" format, the DNSBL domain set and the DNSBLIP IP set built from a
   fixed corpus are **byte-identical** to `origin/devel` (the Phase-1 oracle, still green at the
   final phase).
2. `$easylist`, `pfb_dnsbl_is_abp_header()`, and the `$validate_header` block are **deleted** —
   `grep` finds no residual reference in `src/`.
3. A bracketed IPv6 literal collects as an IP; a non-IPv6 `[…]` line is skipped everywhere; both
   pinned by tests (Semantics #3).
4. ABP feed semantics (`@@`/regex/`$important`/`$badfilter`/banding) unchanged (Semantics #4).
5. On the live-VM CE+Plus fan-out, a representative feed of each format resolves the same block
   verdicts as before (NOERROR+VIP/NULL for a match; correct IP collection).

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
- Test-coverage mandate: behaviour-**preserving** phases pin the current behaviour as an **oracle**
  (green before *and* after); the byte-identity corpus IS that oracle. No phase without tests; no
  coverage theater.
- No live Unbound in CI — the Python dispatcher parity oracle runs off-appliance (pytest, stdlib);
  end-to-end resolution is the live-VM smoke fan-out (§7).

## 6. Action plan (phases — early ones are behaviour-preserving prep / de-risk)

### Phase 1 — Byte-identity corpus + coverage matrix (behaviour-preserving; THE de-risk)

- Prompt: `01_Byte_Identity_Corpus.txt`
- Re-derive the §"Coverage matrix" from a fresh grep of the live loop; assemble a fixture corpus
  (one small feed per format row, inert data — RFC 5737/3849 IPs, `uuid-*.com`, never RFC 6761
  TLDs or HSTS-preload names). Capture, from **`origin/devel`**, the exact domain set + DNSBLIP IP
  set each corpus feed produces, as golden fixtures. This is the falsification harness every later
  phase is gated on — and a permanent regression net with standalone value even if the ADR is
  rejected.
- Tests: a PHPUnit/pytest oracle that runs the corpus through today's parse path and asserts the
  captured golden output; a **vacuity check** (mutate one golden domain → oracle goes red).

### Phase 2 — De-tangle prep: IP collector + universal comment predicate (behaviour-preserving)

- Prompt: `02_Detangle_Prep.txt`
- Extract `pfb_dnsbl_collect_feed_ip(...)` (collapse the 6 IP-collection copies, §1.4) and a
  universal `pfb_dnsbl_is_skippable_control_line($line): bool` (= `!`/`//`/`[…]`-non-IPv6, reusing
  `pfb_dnsbl_unbracket_ip6` for the IPv6 carve-out; the `#`-classifier stays separate). Pure
  functions, oracle tests, no behaviour change. Standalone value if the ADR is rejected (ADR-01
  lesson: prep is retained).
- Tests: fail-on-mutation oracle for each helper; the Phase-1 corpus stays byte-identical.

### Phase 3 — Python per-line dispatcher + parity oracle (the premise PROOF or REJECT)

- Prompt: `03_Python_Line_Dispatcher.txt`
- Add the Python per-line dispatcher (Option A): recognise ABP-shaped lines and route to
  `parse_abp`, else the `parse()` plain/hosts path — reproducing today's per-format output. Prove
  it against the Phase-1 corpus (**parity oracle**): the dispatcher's domain set == the golden set,
  per format. This phase is where byte-identity is PROVEN; a format it cannot reproduce triggers
  the §7 reject path (fall back to Option B for that format, or reject the ADR).
- Hostile-input rows (REQUIRED test data, implementer fills results): IDN/punycode, #752 undotted-
  254, #753 wire-cap, empty/whitespace/BOM-led, `@@||`, `/regex/`, `$important`, `$badfilter`,
  `[Adblock]`, `||1.2.3.4^`, bracketed-IPv6, mixed plain+`||`.
- Tests: parity oracle per format; the hostile-input table; red-run proof the oracle catches a
  deliberately wrong dispatch.

### Phase 4 — Wire PHP to raw-passthrough + delete the classifier (behaviour-changing)

- Prompt: `04_Wire_And_Delete.txt`
- PHP stops PHP-extracting plain-feed domains; passes raw domain lines to the Python domain path
  (as ABP feeds already do). Delete `$easylist`, `pfb_dnsbl_is_abp_header()`, the `$validate_header`
  block; collapse 16317/16324 into one raw-passthrough; apply the universal control-line skip in
  the IP-scan pass (Phase-2 predicate). Migrate the `.abp` marker's `format_hint` role (Semantics
  #7). The Phase-1 corpus oracle MUST stay byte-identical (this is the fail-before/pass-after gate:
  the new path reproduces the golden output; a red is a real regression).
- Tests: Phase-1 corpus still green; `grep` proves the deleted symbols are gone; Semantics #2/#3
  IP tests.

### Phase 5 — Perf validation + delete dead code

- Prompt: `05_Perf_And_Cleanup.txt`
- Benchmark a large hosts feed (≥1M lines) through the new path vs `origin/devel`, with a stated
  methodology and a **kill-threshold** (e.g. >X% wall-clock or >Y MB RSS regression on the Python
  loader → reject Option A's approach / revisit). Remove now-dead PHP branches surfaced by the diff.
- Tests: the benchmark harness + its recorded numbers in the handoff; full suite green.

### Phase 6 — Docs, DoD, live-VM smoke checklist

- Prompt: `06_Docs_Dod_Smoke.txt`
- Update `docs/misc/architecture-notes.md` "DNSBL/ABP pipeline" for the retired classifier + the
  single-authority boundary; update this ADR's Status; author the §7 live-VM smoke checklist.

## 7. Definition of done

- All phases landed (`RESULTS/01–06_Results.txt` + gate records); full PHPUnit + pytest green;
  PHPCS/PHPStan clean; the **Phase-1 byte-identity corpus oracle green at the final phase**.
- **Live-VM manual smoke checklist (CE + Plus fan-out, per CLAUDE.md "ADR acceptance").** Each step
  names a falsifiable observable:
  1. **Plain hosts feed** (`helpers.unique_domain()` entries): install, update, `drill
     @127.0.0.1` a listed name on-box → NOERROR + VIP/NULL block (per the list's `logging`); an
     unlisted name → normal resolution. Same verdicts as a `origin/devel` baseline run.
  2. **ABP/EasyList feed** with `||domain^`, `@@||exception^`, a `! Title:` header and an
     `[Adblock]` line: the `||` name blocks; the `@@` name resolves (allow); the header/`[…]` lines
     produce no spurious domain. Byte-identical to baseline.
  3. **Mixed feed** (plain hosts lines + a stray `||domain^`): both the plain name and the `||`
     name block.
  4. **Bracketed IPv6 (`[…]`) line**: confirm the address lands in the DNSBLIP alias (not dropped
     as a comment) and a genuine `[Adblock]` marker does NOT.
  5. **CSV feed** (one representative of pt/bbc/h3x/otx/pon/et): the extracted domain blocks;
     format detection unchanged (this ADR does not move CSV — regression check only).
  6. **IDN/punycode name**: blocks under its punycode form, byte-identical to baseline.
  7. **Force reload / reused (`.abp` marker) feed**: a not-re-downloaded feed resolves the same
     routing after `$easylist` removal (Semantics #7).
- **Accepted** requires steps 1–7 green on CE **and** Plus.
- **Reject criteria (make the premise falsifiable — the ADR-01 discipline):**
  1. **Phase 3 parity fails** — the Python per-line dispatcher cannot reproduce `origin/devel`'s
     domain set byte-for-byte for some format, and no bounded, documented reconciliation closes the
     gap → **REJECT** the unification (retain Phases 1–2 prep, which are behaviour-preserving and
     independently valuable) or scope that format to Option B only.
  2. **Phase 5 perf regresses** past the stated kill-threshold on giant hosts feeds → reject the
     approach that caused it (Option A stands if it is the cheap path; Option B is rejected).
  3. Any Semantics-#1/#2/#3 test that cannot be made to pass without weakening its assertion →
     REJECT (a weakened byte-identity assertion is coverage theater, not a pass).
