# ADR-22: DNSBL Parser Scheme-Anchored Host Extraction

- **Status:** **Proposed** (2026-06-09)
- **Date:** 2026-06-09
- **Branch:** `adr/22-dnsbl-parser-scheme-anchored-host` (off `devel`; depends on ADR-21)
- **Tracks:** GitHub issue [#46](https://github.com/pfBlockerNG/pfBlockerNG/issues/46)
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (non-lite scheme strip,
  `pfblockerng.inc:9674–9676`; new helper function)
- **Target runtime:** PHP 8.3
- **Test suite:** `tests/php/` (PHPUnit)

## 1. Context

### 1.1 Today — the non-lite scheme strip

In the download loop's non-ABP, non-lite path (`pfblockerng.inc:9672–9707`), a line that
is NOT already a clean alphanumeric+dots domain is normalized before domain validation. The
scheme strip at line 9675 is:

```php
// If 'http|https|telnet|ftp://' found, remove
if (strpos($line, '://') !== FALSE) {
    $line = substr($line, strpos($line, '://') + 3);
}
```

`strpos` finds the first `://` **anywhere** in the token and strips everything up to and
including `//`. This means:

- `http://evil.com` → `evil.com` ✓
- `telnet://evil.com` → `evil.com` (scheme stripped silently; not rejected)
- `garbage://evil.com` → `evil.com` (any scheme stripped silently; not rejected)
- `evil.com://stuff` → `stuff` (pathological: `://` mid-token, scheme extraction wrong)

The comment says `http|https|telnet|ftp://` — the intent was to handle those four — but
the implementation is far more permissive.

### 1.2 The safety net

`pfb_filter($line, PFB_FILTER_DOMAIN)` is the unconditional final gate (line 9757). It
requires a `.`, no `..`, length `< 255`, valid label lengths, charset `^[a-zA-Z0-9_.-]+$`.
So a non-domain value extracted from a malformed line is always caught and logged. **This
is not a security or garbage-acceptance bug** — the output is always a syntactically valid
hostname. The issue is that `garbage://evil.com` produces `evil.com` when it arguably
should be skipped (or the scheme should trigger a parse warning), because the feed author's
intent for a `garbage://` line is ambiguous.

### 1.3 What changed with ADR-21

ADR-21 Phase 2 inserts an `||`/`@@||` guard at line ~9754 (after dot trim, before domain
validation) in the same download loop. ADR-22 modifies the non-lite block at lines 9672–9707
— a different code region. Because both phases modify the same function in the same file,
ADR-22 must be applied **after** ADR-21 Phase 2 is merged to `devel`, to avoid merge
conflicts.

### 1.4 Load-bearing facts

- The non-lite block runs only when `$lite == FALSE` (the line is NOT already a clean
  alphanumeric+dots domain). A plain `evil.com` never reaches this code.
- `pfb_strip_trailing_port()` (line 9706) is the existing pattern for extracting a sub-task
  into a named helper — the same pattern is used here.
- The path/query/fragment/port strips at lines 9679–9706 are NOT changed by this ADR.
- ABP feeds (`$easylist = TRUE`) never reach the non-lite block — they are fully excluded.
- The lite path (`$lite = TRUE`) never reaches the non-lite block either.

## 2. Decision

### 2.1 Tightening rule

Replace the scheme strip at `pfblockerng.inc:9675–9676` with a helper function
`pfb_dnsbl_strip_scheme(string $line): string|false`:

- Returns the line with the scheme stripped **if** the scheme is `http://` or `https://`
  anchored at the start of the token. `ftp://` is also accepted.
- Returns **`false`** if a `://` is present but the scheme is NOT one of the accepted ones,
  or the `://` is not at the start. The caller logs via `pfb_parsed_fail()` and skips.
- Returns the line unchanged if no `://` is present at all.

The accepted schemes are `http`, `https`, `ftp` — matching the comment's original intent.
`telnet://` and all other schemes → `false` → skip.

### 2.2 Decision table

| Input | Current output | New output |
| ----- | -------------- | ---------- |
| `http://evil.com/path` | `evil.com/path` (then `/` stripped) | `evil.com/path` (unchanged) |
| `https://evil.com` | `evil.com` | `evil.com` |
| `ftp://evil.com` | `evil.com` | `evil.com` |
| `telnet://evil.com` | `evil.com` (silently peeled) | `false` → skip + log |
| `garbage://evil.com` | `evil.com` (silently peeled) | `false` → skip + log |
| `evil.com` | `evil.com` (unchanged) | `evil.com` (unchanged) |
| `evil.com://junk` | `junk` (mid-token `://` mangled) | `false` → skip + log |

### 2.3 Semantics that MUST be preserved (the contract — pinned by oracle tests in Phase 1)

1. **`http://evil.com`** → `evil.com` blocked (scheme stripped; path stripping unchanged).
2. **`https://evil.com/path`** → `evil.com` blocked (scheme + path stripped).
3. **`ftp://evil.com`** → `evil.com` blocked (ftp is accepted).
4. **`evil.com`** → `evil.com` blocked (no scheme present — unchanged).
5. **`0.0.0.0 evil.com`** → `evil.com` blocked (hosts format; whitespace-token selection
   at lines 9649–9655 runs before the non-lite block; the non-lite block sees only `evil.com`
   — which has no scheme, so it exits the non-lite block unchanged).
6. **`pfb_filter()` gate is unchanged** — all extracted values must still pass domain validation.

### 2.4 Explicitly kept / out of scope

- Path/query/fragment/port stripping at lines 9679–9706 is NOT changed.
- The lite path (`$lite = TRUE`) is NOT changed.
- The ABP-header path (`$easylist = TRUE`) is NOT changed.
- ADR-21's `||`/`@@||` guard (inserted at ~line 9754) is NOT changed.
- `pfb_filter()` domain validation gate is NOT changed.

## 3. Consequences

**Positive**

- `weird://evil.com` in a feed is now skipped + logged instead of silently producing `evil.com`.
- The comment at line 9674 (`http|https|telnet|ftp://`) and the implementation now agree
  (telnet dropped intentionally; ftp kept).
- The helper is independently testable in PHPUnit without mocking the full download loop.

**Negative / risks**

- A feed that genuinely uses `telnet://` as a quirky prefix for domain names would now be
  skipped. In practice no such feeds exist; the parse-fail log surfaces it if they do.
- Slightly increased code surface (one new helper function).

## 4. Requirements (acceptance)

1. `http://evil.com` → `evil.com` blocked (no regression).
2. `https://evil.com` → `evil.com` blocked (no regression).
3. `ftp://evil.com` → `evil.com` blocked (no regression).
4. `evil.com` → `evil.com` blocked (no scheme present; no regression).
5. `telnet://evil.com` → skipped; `pfb_parsed_fail()` called.
6. `garbage://evil.com` → skipped; `pfb_parsed_fail()` called.
7. `evil.com://junk` → skipped (mid-token `://` is not a recognised leading scheme).
8. `python -m pytest` → unchanged (no regressions in any suite).
9. PHPUnit → green (new + existing PHP tests).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; tabs; no `die()`/`exit()` in library code.
- `str_starts_with()` is available (PHP 8.0+; target is PHP 8.3). Use it.
- The new helper `pfb_dnsbl_strip_scheme()` follows the naming convention of existing
  helpers (`pfb_strip_trailing_port`, `pfb_dnsbl_abp_extract_ip`).
- `php -l` + PHPUnit on every modified file.
- ADR-21 Phase 2 must be merged to `devel` before this branch is opened — the two phases
  touch the same function.

## 6. Action plan

### Phase 1 — Extract helper + oracle tests

Prompt: `01_Extract_And_Oracle.txt`

Behaviour-preserving prep. Extract the scheme-strip logic at lines 9675–9677 into
`pfb_dnsbl_strip_scheme(string $line): string` (returns string only — the current API,
where `false` is not yet returned). Add PHPUnit oracle tests that pin the CURRENT behavior
(`weird://evil.com` → `'evil.com'`; `http://evil.com` → `'evil.com'`; etc.). The download
loop calls the new helper in place of the two-line inline. End state: behaviour-preserving,
all existing tests green.

### Phase 2 — Tighten: anchor scheme + reject unrecognised

Prompt: `02_Tighten_Scheme.txt`

Change the return type of `pfb_dnsbl_strip_scheme()` to `string|false`. Non-http(s)/ftp
`://` → return `false`. Update the download loop caller: `false` → `pfb_parsed_fail()` +
`continue`. The Phase 1 oracle tests become the before-state; add after-state tests
(`weird://evil.com` → `false`). All §4 acceptance requirements proven. `php -l`, PHPUnit,
and `python -m pytest` all green.

### Phase 3 — DoD

Prompt: `03_DoD.txt`

Smoke case: deploy a feed with a `telnet://evil.com` line; confirm it is skipped (not
blocked) and logged as a parse failure on the live VM. Record DoD evidence.

## 7. Definition of done

All criteria met and evidence recorded in `RESULTS/03_Results.txt`:

- `php -l src/usr/local/pkg/pfblockerng/pfblockerng.inc` → no syntax errors.
- PHPUnit → green (new oracle + tightened tests; existing PHP tests unaffected).
- `python -m pytest` → unchanged (no regressions).
- `ruff check . && ruff format .` → clean.
- Phase 3 smoke: `telnet://evil.com` in a feed → not blocked, parse-fail logged.
- Phase 3 smoke: `http://evil.com` → still blocked (no regression).

**Manual smoke checklist** (maintainer, live pfSense box):

1. Add a DNSBL Group Custom_List entry containing:
   - `http://should-be-blocked.com`
   - `telnet://should-be-skipped.com`
   - `garbage://also-skipped.com`
2. Run pfBlockerNG → DNSBL update; check the pfBlockerNG log for parse-fail entries for
   `telnet://should-be-skipped.com` and `garbage://also-skipped.com`.
3. `drill @127.0.0.1 should-be-blocked.com` → sinkhole VIP or NULL (blocked).
4. `drill @127.0.0.1 should-be-skipped.com` → NOERROR (not blocked).
5. `drill @127.0.0.1 also-skipped.com` → NOERROR (not blocked).

**Reject criteria:**

- `http://` or `https://` feeds produce regressions (any domain blocked before is not
  blocked after).
- PHPUnit reveals the oracle tests don't match actual current behavior (fix oracle first).
- `python -m pytest` test count changes (adds/drops non-PHP tests unexpectedly).
