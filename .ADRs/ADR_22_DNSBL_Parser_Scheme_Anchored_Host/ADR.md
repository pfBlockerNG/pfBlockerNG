# ADR-22: DNSBL Parser Scheme-Validated Host Extraction

- **Status:** **Proposed** (2026-06-09; design revised 2026-06-15 — single global toggle)
- **Date:** 2026-06-09
- **Branch:** `adr/22-dnsbl-parser-scheme-anchored-host` (off `devel`; depends on ADR-21)
- **Tracks:** GitHub issue [#46](https://github.com/pfBlockerNG/pfBlockerNG/issues/46)
- **Component(s):**
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (scheme helper; global toggle; skip
  logging), `src/usr/local/pkg/pfblockerng/pfblockerng_install.inc` (migration),
  `src/usr/local/www/pfblockerng/pfblockerng_general.php` (DNSBL-tab toggle)
- **Target runtime:** PHP 8.3
- **Test suite:** `tests/php/` (PHPUnit) + `tests/smoke/`

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
- `evil://evil.com` → `evil.com` ✓ (valid RFC 3986 scheme — fine)
- `pkg+https://evil.com` → `evil.com` ✓ (compound scheme — fine)
- `123://evil.com` → `evil.com` — scheme starts with a digit; not a valid RFC 3986
  scheme. The line is silently extracted and blocked when it should be logged and skipped.
- `://evil.com` → `evil.com` — empty scheme prefix; same problem.

### 1.2 RFC 3986 scheme syntax

Per [RFC 3986 §3.1](https://datatracker.ietf.org/doc/html/rfc3986#section-3.1):

```text
scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
```

A scheme must start with an ASCII letter, followed by zero or more letters, digits, `+`,
`-`, or `.`. Examples of valid schemes: `http`, `https`, `ftp`, `telnet`, `evil`, `goat`,
`pkg+https`, `s3`, `git-ssh`. Examples of invalid schemes: `123` (digit start), `` (empty),
`!!bad` (non-alpha start).

### 1.3 The safety net

`pfb_filter($line, PFB_FILTER_DOMAIN)` is the unconditional final gate (line 9757). Any
non-domain value extracted from a malformed line is caught here. **This is not a security
bug** — the output is always a syntactically valid hostname if it passes the gate. The issue
is correctness: `123://evil.com` produces `evil.com`, which passes `pfb_filter` and gets
blocked, when the feed line is malformed and arguably should be flagged and skipped.

### 1.4 What changed with ADR-21

ADR-21 Phase 2 inserts an `||`/`@@||` guard at line ~9754 in the same function. ADR-22
modifies the non-lite block at lines 9672–9707 — a different code region. ADR-22 must be
applied after ADR-21 Phase 2 merges.

### 1.5 Load-bearing facts

- The non-lite block runs only when `$lite == FALSE`. A plain `evil.com` never reaches it.
- `pfb_strip_trailing_port()` (line 9706) is the pattern for named helpers — follow it.
- Path/query/fragment/port strips at lines 9679–9706 are NOT changed by this ADR.
- ABP feeds and the lite path never reach the non-lite block.
- `pfb_filter()` remains the domain validity gate, unchanged.

### 1.6 Why a single global toggle (2026-06-15 design revision)

An earlier draft proposed a global toggle **plus** a per-feed tri-state selector **plus** a
hardcoded "known-affected feeds" list that forced strict mode regardless of user choice. That
is more machinery than the problem warrants: the DNSBL feed grid offers no other per-feed
*parsing-behaviour* knob (only the `Auto`/`RSync` transport choice — see issue #46 discussion),
the three-way per-feed × global × known-affected precedence is hard to reason about, and the
known-affected list is an open-ended maintenance burden (it must be researched, confirmed, and
kept current). The revision replaces all of it with **one global toggle** whose default flips
correct-by-default for new installs, plus **clear skip logging** so a user who turns strict
parsing on can *see* exactly which feed lines it drops and decide for themselves — visibility
in place of a curated enforcement list.

## 2. Decision

### 2.1 A single "lenient parsing" toggle

One global setting controls scheme validation:

**`pfb_dnsbl_lenient`** — a checkbox ("Lenient feed parsing") in **General Settings → DNSBL
tab**. Stored `'on'` when checked; unchecked/absent is treated as off.

- **ON (`'on'`) = lenient — today's behavior, byte-identical.** Any `://` is stripped at its
  first occurrence; paths/query/port are stripped downstream (lines 9679–9706); a malformed
  scheme (digit-start, empty, special chars) is silently accepted. **No lines skipped, no new
  log output.**
- **OFF (unchecked) = strict.** `pfb_dnsbl_strip_scheme()` validates the scheme against RFC
  3986 and rejects non-root paths; a rejected line is **skipped and logged** (§2.3).

**Resolution is trivial — no cascade:**

```text
strict = (pfb_dnsbl_lenient !== 'on')
```

There is **no per-feed override** and **no known-affected-feeds list**.

**Defaults:**

- **New installs → OFF (strict).** A fresh checkbox is unchecked, so new users get correct
  RFC 3986 parsing from day one.
- **Existing installs → migrated to ON (lenient)** on upgrade (§2.2), preserving the behavior
  they already rely on. They can untick the box to adopt strict parsing and watch the skip log
  (§2.3) to learn what their feeds actually contain.

### 2.2 Existing-user migration

On package upgrade (`pfblockerng_install.inc`): if an **existing** pfBlockerNG config section
is present but has no `pfb_dnsbl_lenient` key, write it `'on'` (lenient). Rationale: these users
are upgrading from a version where malformed-scheme lines were silently accepted and blocked;
preserving that prevents surprise feed changes on upgrade.

- A **first-ever install** has no prior config section, so the migration does **not** fire and
  the new-install default (OFF / strict) stands. The migration must therefore key on an
  *already-populated* pfBlockerNG config that merely lacks this one key — follow the exact
  pattern of the adjacent migration blocks in `pfblockerng_install.inc`.
- Migration **only sets, never overwrites** an existing `pfb_dnsbl_lenient` value.

### 2.3 Skip logging (strict mode only)

When strict parsing skips a line, the user MUST be able to see what was dropped:

- **Per line** → `pfb_parsed_fail($header, $line, $oline, $pfb['dnsbl_parse_err'])`, the
  existing DNSBL parse-error log (CSV: timestamp, feed header, parsed line, original line).
  This is the established sink for parse failures; strict skips join it.
- **Per feed** → one clear, human-readable **WARNING** in the main pfBlockerNG log summarising
  the count, e.g.:

  ```text
  [ DNSBL ] <feed>: N line(s) skipped — strict parsing rejected an invalid scheme or URL path (see DNSBL parse-error log)
  ```

  A **per-feed summary** (not one main-log line per skipped entry) so a feed with many
  malformed lines can't flood the main log; the per-line detail lives in the parse-error log.

**Lenient mode (ON) emits no new log output** — behaviour is byte-identical to today.

### 2.4 Scheme validation rule (when strict)

`pfb_dnsbl_strip_scheme(string $line, bool $strict = false): string|false`:

- No `://` present → return `$line` unchanged.
- `://` present:
  1. **Lenient (`$strict === false`):** strip everything up to and including the first `://`
     and return the remainder (today's behaviour — paths handled downstream).
  2. **Strict (`$strict === true`):**
     a. Validate the text before `://` against `^[a-zA-Z][a-zA-Z0-9+\-.]*$`.
        Invalid → return `false`; caller calls `pfb_parsed_fail()` + logs + `continue`.
     b. Strip `scheme://` to get the remainder.
     c. Strip a single trailing `/` from the remainder if present (root-path slash is
        harmless and normalised away).
     d. If the remainder still contains `/` (actual path present) → return `false`; caller
        skips + logs as above.
     e. Return the remainder.

The `$strict` parameter **defaults to `false`** so the Phase-1 oracle tests call the helper
with no second argument and observe today's behaviour unchanged.

**Any syntactically valid RFC 3986 scheme is accepted** — the fix is scheme-syntax validation
plus path rejection, **not** a whitelist of specific scheme names. Path stripping at lines
9679–9706 is unchanged and continues to handle paths when lenient is ON.

### 2.5 Decision table

| Input | Lenient ON (today) | Strict (lenient OFF) | Reason |
| ----- | ------------------ | -------------------- | ------ |
| `http://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `evil://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `pkg+https://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `telnet://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `evil.com` | `evil.com` | `evil.com` | no `://`, unchanged |
| `http://evil.com/path` | `evil.com` | `false` → skip + log | path present |
| `ftp://ftp.evil.com/` | `ftp.evil.com` | `ftp.evil.com` | trailing `/` = root path, normalised |
| `123://evil.com` | `evil.com` | `false` → skip + log | digit-start invalid scheme |
| `://evil.com` | `evil.com` | `false` → skip + log | empty scheme |
| `!!bad://evil.com` | `evil.com` | `false` → skip + log | non-alpha-start |

### 2.6 Semantics that MUST be preserved (the contract — pinned by oracle tests in Phase 1)

1. Any valid RFC 3986 scheme with no path is accepted regardless of toggle state.
2. `pfb_filter()` remains the unconditional domain validity gate.
3. When lenient is **ON**, behaviour is byte-identical to today for **every** input
   (paths stripped downstream as before; nothing skipped; no new log output).
4. When strict (lenient **OFF**): `123://evil.com`, `://evil.com`, and `http://evil.com/path`
   → `false` → skipped + logged.
5. `ftp://ftp.evil.com/` (root-path slash only) → `ftp.evil.com` regardless of toggle state.
6. New installs default to strict (lenient OFF); an existing install lacking the key is
   migrated to lenient ON; migration never overwrites an existing value.

### 2.7 Explicitly kept / out of scope

- Path/query/fragment/port stripping at lines 9679–9706 is NOT changed (active when lenient
  is ON; never reached in strict mode since path lines are rejected first).
- Lite path, ABP-header path: NOT changed.
- ADR-21's `||`/`@@||` guard: NOT changed.
- `pfb_filter()`: NOT changed.
- No scheme whitelist — syntax validation only.
- **No per-feed selector and no known-affected-feeds list** (dropped in the 2026-06-15
  revision — see §1.6). One global toggle only.

## 3. Consequences

**Positive**

- `123://evil.com`, `://evil.com`, and `http://evil.com/path` are logged and skipped when
  strict — feeds must supply clean host-only lines, and the user sees exactly which lines were
  dropped (§2.3) instead of relying on a maintainer-curated list.
- New installs get correct RFC 3986 parsing by default; existing users keep prior behaviour and
  opt in on their own terms.
- One toggle, one predicate (`strict = lenient !== 'on'`) — trivial to reason about and test;
  no per-feed UI weight, no list to maintain.
- The helper is independently testable in PHPUnit.

**Negative / risks**

- Existing users migrated to lenient must consciously untick the box to get the corrected
  behaviour. Mitigation: the skip log makes the benefit visible the moment they try it.
- A feed legitimately relying on the permissive strip will drop those lines under strict mode;
  the per-feed/per-line skip logging is the diagnostic that surfaces this.

## 4. Requirements (acceptance)

1. `http://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
2. `evil://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
3. `pkg+https://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
4. `evil.com` → `evil.com` blocked, always (no scheme; unchanged).
5. `123://evil.com` when lenient **ON** → `evil.com` blocked (current behavior).
6. `123://evil.com` when strict (lenient **OFF**) → skipped + logged.
7. `://evil.com` when strict → skipped + logged.
8. `http://evil.com/path` when strict → skipped + logged (path present).
9. `http://evil.com/path` when lenient **ON** → `evil.com` blocked (path stripped downstream at
   lines 9679–9706; current behavior unchanged).
10. `ftp://ftp.evil.com/` (root-path slash only) → `ftp.evil.com` blocked regardless of toggle
    state (trailing `/` normalised away; not treated as a path).
11. Migration: an existing install lacking `pfb_dnsbl_lenient` → migrated to `'on'` (lenient);
    an existing `'on'`/`'off'` value is never overwritten.
12. New install (no migration trigger): `pfb_dnsbl_lenient` defaults to OFF (strict).
13. Strict-mode skip logging: each skipped line is recorded in the DNSBL parse-error log AND a
    per-feed summary WARNING appears in the main pfBlockerNG log; lenient mode logs nothing new.
14. `python -m pytest` → unchanged (no regressions in any suite).
15. PHPUnit → green.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; tabs; no `die()`/`exit()` in library code.
- `preg_match()` for RFC 3986 scheme validation.
- The helper `pfb_dnsbl_strip_scheme()` + the config key `pfb_dnsbl_lenient` follow naming
  conventions (check neighbouring DNSBL keys/fields before finalising).
- `php -l` + PHPUnit on every modified file.
- ADR-21 Phase 2 must be merged before this branch opens.

## 6. Action plan

### Phase 1 — Extract helper + oracle tests

Prompt: `01_Extract_And_Oracle.txt`

Behaviour-preserving extraction of the inline scheme-strip into `pfb_dnsbl_strip_scheme()`
(`string` return only, no toggle yet) + PHPUnit oracle tests pinning current behavior for
all inputs including the pathological ones that Phase 2 will change.

### Phase 2 — Toggle + validation + migration + skip logging

Prompt: `02_Toggle_Validation_Migration.txt`

Add the `pfb_dnsbl_lenient` config key + DNSBL-tab checkbox. Change `pfb_dnsbl_strip_scheme()`
return type to `string|false` with toggle-gated RFC 3986 validation (`$strict` param). Wire the
call site (`strict = lenient !== 'on'`), the per-line + per-feed skip logging (§2.3), and the
upgrade migration in `pfblockerng_install.inc` (existing install lacking the key → `'on'`).
Tests cover both toggle states, the migration (set + no-overwrite), and the skip-log emission.

### Phase 3 — DoD smoke

Prompt: `03_DoD.txt`

Live-VM smoke for both toggle states + the migration, asserting the skip log. Record DoD
evidence.

## 7. Definition of done

All criteria met and evidence recorded in `RESULTS/03_Results.txt`:

- `php -l` → clean on all modified files.
- PHPUnit → green (oracle + toggle + migration + skip-log tests).
- `python -m pytest` → unchanged.
- `ruff check . && ruff format .` → clean.
- Phase 3 smoke: lenient OFF (strict) → `123://` skipped, `http://host/path` skipped,
  `evil://host` blocked, `http://host` blocked, and the skipped lines appear in the parse-error
  log + a per-feed WARNING in the main log; lenient ON → `123://` and `http://host/path`
  blocked; migration confirmed (existing install upgraded → `pfb_dnsbl_lenient = 'on'`).

### Acceptance

Per CLAUDE.md "ADR acceptance — automated tests, not a manual maintainer sign-off": ADR-22
flips to **Accepted** on green automated coverage (PHPUnit for the helper/toggle/migration/
logging; live-VM smoke for both toggle states + migration) — no separate manual sign-off step.

**Reject criteria:**

- Any valid-scheme regression (requirements §4.1–§4.4 fail).
- Lenient-ON behavior not byte-identical to today (§4.5, §4.9 fail).
- Migration does not set `pfb_dnsbl_lenient = 'on'` for existing installs, or overwrites an
  existing value (§4.11 fails).
- New install does not default to strict (§4.12 fails).
- Strict-mode skips not logged per-line AND per-feed (§4.13 fails).
- `python -m pytest` count changes unexpectedly.
