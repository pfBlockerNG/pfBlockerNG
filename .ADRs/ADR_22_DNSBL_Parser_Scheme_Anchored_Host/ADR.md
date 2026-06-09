# ADR-22: DNSBL Parser Scheme-Validated Host Extraction

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
- `evil://evil.com` → `evil.com` ✓ (any scheme accepted — fine)
- `pkg+https://evil.com` → `evil.com` ✓ (compound scheme — fine)
- `123://evil.com` → `evil.com` — **WRONG**: `123` is not a valid RFC 3986 scheme
  (starts with a digit). The line is extracted and blocked when it should be rejected.
- `://evil.com` → `evil.com` — **WRONG**: empty scheme prefix; `strpos` finds `://` at
  position 0 and strips it. Same problem.

The root issue is not which specific schemes are allowed — **any** scheme is fine — but
that the code does not validate whether the text before `://` is a syntactically valid RFC
3986 scheme before stripping it.

### 1.2 RFC 3986 scheme syntax

Per [RFC 3986 §3.1](https://datatracker.ietf.org/doc/html/rfc3986#section-3.1):

```text
scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
```

A scheme must:

- Start with an ASCII letter (`[a-zA-Z]`).
- Continue with zero or more ASCII letters, digits, `+`, `-`, or `.`.

Examples of **valid** schemes: `http`, `https`, `ftp`, `telnet`, `evil`, `goat`,
`pkg+https`, `s3`, `git+ssh`. Examples of **invalid** schemes: `123` (digit start),
`` (empty), `!!bad` (special chars), `evil com` (space).

### 1.3 The safety net

`pfb_filter($line, PFB_FILTER_DOMAIN)` is the unconditional final gate (line 9757). It
validates charset `^[a-zA-Z0-9_.-]+$`, presence of `.`, label lengths, etc. Any non-domain
value extracted from a malformed line is caught here. **This is not a security bug** — the
output is always a syntactically valid hostname if it passes this gate. The scheme issue is
a correctness gap: `123://evil.com` produces `evil.com`, which passes `pfb_filter` and gets
blocked — but the feed line is malformed and should arguably be flagged + skipped.

### 1.4 What changed with ADR-21

ADR-21 Phase 2 inserts an `||`/`@@||` guard at line ~9754 (after dot trim, before domain
validation) in the same download loop. ADR-22 modifies the non-lite block at lines 9672–9707
— a different code region. Both modify the same function in the same file, so ADR-22 must be
applied **after** ADR-21 Phase 2 is merged to `devel`, to avoid merge conflicts.

### 1.5 Load-bearing facts

- The non-lite block runs only when `$lite == FALSE`. A plain `evil.com` never reaches it.
- `pfb_strip_trailing_port()` (line 9706) is the existing pattern for extracting a sub-task
  into a named helper — the same pattern applies here.
- The path/query/fragment/port strips at lines 9679–9706 are NOT changed by this ADR.
- ABP feeds (`$easylist = TRUE`) and the lite path never reach the non-lite block.
- **`pfb_filter()` remains the domain validity gate, unchanged.**

## 2. Decision

### 2.1 Rule

Replace the scheme strip at `pfblockerng.inc:9675–9676` with a helper function
`pfb_dnsbl_strip_scheme(string $line): string|false`:

- If no `://` is present → return the line unchanged.
- If `://` IS present, validate that the text **before** `://` is a valid RFC 3986 scheme
  (`^[a-zA-Z][a-zA-Z0-9+\-.]*$` anchored at the start of the token). If valid → return
  the line with `scheme://` stripped (same as today for any valid scheme).
- If `://` is present but the preceding text is NOT a valid RFC 3986 scheme → return
  `false`. The caller calls `pfb_parsed_fail()` and skips the line.

**Any syntactically valid RFC 3986 scheme is accepted, regardless of semantics.** The fix
is scheme syntax validation, not a whitelist of specific scheme names.

### 2.2 Decision table

| Input | Current output | New output | Reason |
| ----- | -------------- | ---------- | ------ |
| `http://evil.com/path` | `evil.com/path` | `evil.com/path` | valid scheme, unchanged |
| `https://evil.com` | `evil.com` | `evil.com` | valid scheme, unchanged |
| `ftp://evil.com` | `evil.com` | `evil.com` | valid scheme, unchanged |
| `telnet://evil.com` | `evil.com` | `evil.com` | valid scheme, unchanged |
| `evil://evil.com` | `evil.com` | `evil.com` | valid scheme, unchanged |
| `goat://meeeh.com` | `meeeh.com` | `meeeh.com` | valid scheme, unchanged |
| `pkg+https://evil.com` | `evil.com` | `evil.com` | valid scheme (`+` allowed), unchanged |
| `s3://bucket.evil.com` | `bucket.evil.com` | `bucket.evil.com` | valid scheme, unchanged |
| `evil.com` | `evil.com` | `evil.com` | no `://`, unchanged |
| `123://evil.com` | `evil.com` (WRONG) | `false` → skip + log | digit-start → invalid scheme |
| `://evil.com` | `evil.com` (WRONG) | `false` → skip + log | empty scheme → invalid |
| `!!bad://evil.com` | `evil.com` (WRONG) | `false` → skip + log | non-alpha-start → invalid |

Note: `evil.com://junk` — scheme `evil.com` is syntactically valid (`.` is allowed); it
extracts `junk`, which then fails `pfb_filter` (no `.`). Behavior unchanged from today.

### 2.3 Semantics that MUST be preserved (the contract — pinned by oracle tests in Phase 1)

1. **Any valid RFC 3986 scheme is accepted:** `http://`, `https://`, `ftp://`, `telnet://`,
   `evil://`, `goat://`, `pkg+https://`, `s3://` all produce the same extracted host as today.
2. **No scheme present:** line returned unchanged (no `://` → falls through to path strip etc.).
3. **`pfb_filter()` gate is unchanged:** every extracted host still passes through domain
   validation; a non-domain result (e.g., extracting `junk` from `evil.com://junk`) is caught
   and logged there, not in this helper.
4. **`123://evil.com`** → `false` → `pfb_parsed_fail()` + skip (changed from today).
5. **`://evil.com`** → `false` → `pfb_parsed_fail()` + skip (changed from today).

### 2.4 Explicitly kept / out of scope

- Path/query/fragment/port stripping at lines 9679–9706 is NOT changed.
- The lite path (`$lite = TRUE`) is NOT changed.
- The ABP-header path (`$easylist = TRUE`) is NOT changed.
- ADR-21's `||`/`@@||` guard (inserted at ~line 9754) is NOT changed.
- `pfb_filter()` domain validation gate is NOT changed.
- No scheme whitelist is introduced — this ADR validates scheme SYNTAX, not semantics.

## 3. Consequences

**Positive**

- `123://evil.com` and `://evil.com` in a feed are now skipped + logged instead of silently
  producing a host that passes domain validation (a correctness fix, not a security fix).
- The helper is independently testable in PHPUnit without mocking the full download loop.
- The implementation now matches the comment at line 9674 in spirit (arbitrary valid schemes
  are accepted, as originally intended by `http|https|telnet|ftp://`).

**Negative / risks**

- Feeds with `123://evil.com`-style malformed lines currently silently produce a blocked
  domain; after this change they are skipped + logged. Practically: no legitimate feed uses
  a digit-start scheme. The parse-fail log surfaces any affected lines.
- Slightly increased code surface (one new helper function + regex).

## 4. Requirements (acceptance)

1. `http://evil.com` → `evil.com` blocked (no regression).
2. `https://evil.com` → `evil.com` blocked (no regression).
3. `ftp://evil.com` → `evil.com` blocked (no regression).
4. `telnet://evil.com` → `evil.com` blocked (valid scheme, no regression).
5. `evil://evil.com` → `evil.com` blocked (valid scheme, no regression).
6. `goat://meeeh.com` → `meeeh.com` blocked (valid scheme, no regression).
7. `pkg+https://evil.com` → `evil.com` blocked (valid scheme with `+`, no regression).
8. `evil.com` → `evil.com` blocked (no scheme, no regression).
9. `123://evil.com` → skipped; `pfb_parsed_fail()` called (digit-start scheme).
10. `://evil.com` → skipped; `pfb_parsed_fail()` called (empty scheme).
11. `python -m pytest` → unchanged (no regressions in any suite).
12. PHPUnit → green (new + existing PHP tests).

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; tabs; no `die()`/`exit()` in library code.
- `preg_match()` is appropriate for the RFC 3986 scheme validation.
- The new helper `pfb_dnsbl_strip_scheme()` follows the naming convention of existing
  helpers (`pfb_strip_trailing_port`, `pfb_dnsbl_abp_extract_ip`).
- `php -l` + PHPUnit on every modified file.
- ADR-21 Phase 2 must be merged to `devel` before this branch is opened.

## 6. Action plan

### Phase 1 — Extract helper + oracle tests

Prompt: `01_Extract_And_Oracle.txt`

Behaviour-preserving prep. Extract the scheme-strip logic at lines 9675–9676 into
`pfb_dnsbl_strip_scheme(string $line): string` (string return only — current behavior,
no `false` yet). Add PHPUnit oracle tests pinning the CURRENT behavior, including:
`evil://evil.com` → `'evil.com'`; `pkg+https://fakepkg.com` → `'fakepkg.com'`;
`123://evil.com` → `'evil.com'` (the BEFORE-state that Phase 2 changes);
`://evil.com` → `'evil.com'` (same). End state: behaviour-preserving, all tests green.

### Phase 2 — Validate scheme per RFC 3986; reject invalid

Prompt: `02_Tighten_Scheme.txt`

Change return type to `string|false`. Add `preg_match('/^[a-zA-Z][a-zA-Z0-9+\-.]*$/',
$scheme)` validation before stripping. Invalid scheme → `false`. Caller: `false` →
`pfb_parsed_fail()` + `continue`. Oracle tests for Phase 1 become before-state;
add after-state tests (`123://evil.com` → `false`; `://evil.com` → `false`). All
§4 requirements proven. `php -l`, PHPUnit, `python -m pytest` green.

### Phase 3 — DoD

Prompt: `03_DoD.txt`

Smoke case: deploy a feed containing `123://evil.com` (invalid scheme) alongside
`http://valid.com` (valid). Confirm: `123://evil.com` skipped + logged; `valid.com`
still blocked. Record DoD evidence.

## 7. Definition of done

All criteria met and evidence recorded in `RESULTS/03_Results.txt`:

- `php -l src/usr/local/pkg/pfblockerng/pfblockerng.inc` → no syntax errors.
- PHPUnit → green (oracle + tightened tests; existing PHP tests unaffected).
- `python -m pytest` → unchanged.
- `ruff check . && ruff format .` → clean.
- Phase 3 smoke: `123://evil.com` → not blocked, parse-fail logged.
- Phase 3 smoke: `http://evil.com` → still blocked (no regression).
- Phase 3 smoke: `evil://evil.com` → still blocked (valid scheme, no regression).

**Manual smoke checklist** (maintainer, live pfSense box):

1. Add a DNSBL Group Custom_List entry containing:
   - `http://should-be-blocked.com`
   - `evil://also-blocked.com` (valid RFC 3986 scheme)
   - `pkg+https://blocked-too.com` (valid scheme with `+`)
   - `123://should-be-skipped.com` (invalid scheme: digit start)
   - `://also-skipped.com` (invalid scheme: empty)
2. Run pfBlockerNG → DNSBL update; check the log for parse-fail entries for
   `123://should-be-skipped.com` and `://also-skipped.com`.
3. `drill @127.0.0.1 should-be-blocked.com` → sinkhole VIP or NULL (blocked).
4. `drill @127.0.0.1 also-blocked.com` → sinkhole VIP or NULL (valid scheme, blocked).
5. `drill @127.0.0.1 blocked-too.com` → sinkhole VIP or NULL (valid scheme, blocked).
6. `drill @127.0.0.1 should-be-skipped.com` → NOERROR (not blocked).
7. `drill @127.0.0.1 also-skipped.com` → NOERROR (not blocked).

**Reject criteria:**

- Any valid-scheme regression: a line that was blocked before is not blocked after
  (requirements §4.1–§4.8 fail).
- PHPUnit oracle tests don't match actual current behavior (fix oracle first).
- `python -m pytest` count changes.
