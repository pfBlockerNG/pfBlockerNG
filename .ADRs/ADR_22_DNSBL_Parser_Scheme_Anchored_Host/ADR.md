# ADR-22: DNSBL Parser Scheme-Validated Host Extraction

- **Status:** **Proposed** (2026-06-09)
- **Date:** 2026-06-09
- **Branch:** `adr/22-dnsbl-parser-scheme-anchored-host` (off `devel`; depends on ADR-21)
- **Tracks:** GitHub issue [#46](https://github.com/pfBlockerNG/pfBlockerNG/issues/46)
- **Component(s):**
  `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (non-lite scheme strip; global toggle;
  migration), `src/usr/local/pkg/pfblockerng/pfblockerng_install.inc` (migration logic)
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

## 2. Decision

### 2.1 Toggle

The RFC 3986 scheme validation is gated by a **global DNSBL setting** `pfb_scheme_strict`
(value: `'on'` / `'off'`). The setting lives in the General Settings → DNSBL tab and
defaults to `'on'` for **new installs** — correct behavior out of the box.

- **When `off`:** behavior is identical to today — any `://` is stripped, including
  `123://evil.com`. No new parse errors.
- **When `on`:** `pfb_dnsbl_strip_scheme()` validates the scheme against RFC 3986;
  invalid schemes → `pfb_parsed_fail()` + skip.

### 2.2 Existing-user migration

On package upgrade (handled in `pfblockerng_install.inc`), if `pfb_scheme_strict` does not
exist in the saved config, it is written as `'off'`. Rationale: existing users are upgrading
from a version where invalid-scheme lines were silently accepted and blocked; preserving that
behavior on upgrade prevents unexpected feed failures. They can opt in to strict mode via the
UI once they have evaluated their feeds. New installs start with `'on'` since they have no
prior behavior to preserve.

### 2.3 Known-affected feeds (TBD — ask maintainer when implementing Phase 3)

Certain curated feed URLs are known to contain lines with invalid RFC 3986 schemes. For
these feeds, scheme validation runs unconditionally — regardless of the `pfb_scheme_strict`
global toggle — so their malformed lines are always logged. The definitive list of
known-affected feed URLs is **TBD** and must be confirmed with the maintainer before
implementing Phase 3. The Phase 3 prompt contains an explicit STOP instruction for this.

### 2.4 Scheme validation rule (when active)

`pfb_dnsbl_strip_scheme(string $line): string|false`:

- No `://` present → return `$line` unchanged.
- `://` present:
  1. Validate the text before `://` against `^[a-zA-Z][a-zA-Z0-9+\-.]*$`.
     Invalid → return `false`; caller calls `pfb_parsed_fail()` + `continue`.
  2. Strip `scheme://` to get the remainder.
  3. If the remainder contains `/` (path present) → return `false`; caller calls
     `pfb_parsed_fail()` + `continue`.
  4. Return the remainder.

**Any syntactically valid RFC 3986 scheme is accepted.** The fix is scheme syntax
validation + path rejection, not a whitelist of specific scheme names. Path stripping
at lines 9679–9706 is unchanged and continues to handle paths when strict is `'off'`.

### 2.5 Decision table (when `pfb_scheme_strict = 'on'` or feed is known-affected)

| Input | Current output | New output | Reason |
| ----- | -------------- | ---------- | ------ |
| `http://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `evil://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `pkg+https://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `telnet://evil.com` | `evil.com` | `evil.com` | valid scheme, no path |
| `evil.com` | `evil.com` | `evil.com` | no `://`, unchanged |
| `http://evil.com/path` | `evil.com` | `false` → skip + log | path present |
| `ftp://ftp.evil.com/` | `ftp.evil.com` | `false` → skip + log | trailing `/` is a path |
| `123://evil.com` | `evil.com` | `false` → skip + log | digit-start invalid scheme |
| `://evil.com` | `evil.com` | `false` → skip + log | empty scheme |
| `!!bad://evil.com` | `evil.com` | `false` → skip + log | non-alpha-start |

When `pfb_scheme_strict = 'off'` and feed is NOT known-affected: all rows produce the
current (left-column) output (path stripping at 9679–9706 handles paths downstream).

### 2.6 Semantics that MUST be preserved (the contract — pinned by oracle tests in Phase 1)

1. Any valid RFC 3986 scheme with no path is accepted regardless of toggle state.
2. `pfb_filter()` remains the unconditional domain validity gate.
3. When the toggle is `off` and the feed is not known-affected, behavior is byte-identical
   to today for every input (paths stripped downstream as before).
4. `123://evil.com`, `://evil.com`, and `http://evil.com/path` → `false` when toggle is `on`.

### 2.7 Explicitly kept / out of scope

- Path/query/fragment/port stripping at lines 9679–9706 is NOT changed (active when
  strict is `'off'`; never reached in strict mode since path lines are rejected first).
- Lite path, ABP-header path: NOT changed.
- ADR-21's `||`/`@@||` guard: NOT changed.
- `pfb_filter()`: NOT changed.
- No scheme whitelist — syntax validation only.

## 3. Consequences

**Positive**

- `123://evil.com`, `://evil.com`, and `http://evil.com/path` are logged and skipped when
  strict mode is on — feeds must supply clean host-only lines.
- New installs get strict mode by default; existing users preserve prior behavior and opt in.
- The helper is independently testable in PHPUnit.

**Negative / risks**

- Existing users migrated to `'off'` must consciously opt in to strict mode to get the
  corrected behavior. The known-affected feeds list is the mechanism that enforces strict mode
  for specific misbehaving feeds regardless of the global toggle.
- The known-affected feeds list is TBD; Phase 3 is blocked until the maintainer provides it.

## 4. Requirements (acceptance)

1. `http://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
2. `evil://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
3. `pkg+https://evil.com` → `evil.com` blocked, always (valid scheme, no path; toggle irrelevant).
4. `evil.com` → `evil.com` blocked, always (no scheme; unchanged).
5. `123://evil.com` when `pfb_scheme_strict='off'` and NOT known-affected → `evil.com`
   blocked (current behavior preserved when toggle is off).
6. `123://evil.com` when `pfb_scheme_strict='on'` OR known-affected → skipped + logged.
7. `://evil.com` when `pfb_scheme_strict='on'` → skipped + logged.
8. `http://evil.com/path` when `pfb_scheme_strict='on'` → skipped + logged (path present).
9. `http://evil.com/path` when `pfb_scheme_strict='off'` → `evil.com` blocked (path stripped
   downstream at lines 9679–9706; current behavior unchanged).
10. Migration: an existing install without `pfb_scheme_strict` in config → migrated to `'off'`.
11. New install without migration trigger: `pfb_scheme_strict` defaults to `'on'`.
12. `python -m pytest` → unchanged (no regressions in any suite).
13. PHPUnit → green.

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; tabs; no `die()`/`exit()` in library code.
- `preg_match()` for RFC 3986 scheme validation.
- The helper `pfb_dnsbl_strip_scheme()` follows naming conventions.
- `php -l` + PHPUnit on every modified file.
- ADR-21 Phase 2 must be merged before this branch opens.
- **Known-affected feeds list is TBD** — Phase 3 must not be implemented until the
  maintainer confirms the list. The Phase 3 prompt contains an explicit STOP.

## 6. Action plan

### Phase 1 — Extract helper + oracle tests

Prompt: `01_Extract_And_Oracle.txt`

Behaviour-preserving extraction of the inline scheme-strip into `pfb_dnsbl_strip_scheme()`
(`string` return only, no toggle yet) + PHPUnit oracle tests pinning current behavior for
all inputs including the pathological ones that later phases will change.

### Phase 2 — Toggle + conditional validation

Prompt: `02_Tighten_Scheme.txt`

Add `pfb_scheme_strict` config key + UI toggle. Change `pfb_dnsbl_strip_scheme()` return
type to `string|false` with RFC 3986 validation. Download loop checks the toggle (and the
known-affected-feed flag from Phase 3 — leave a `TODO` placeholder for that). Tests cover
both toggle states. Implementor must STOP before Phase 3 to confirm the known-affected list.

### Phase 3 — Migration + known-affected feeds

Prompt: `03_Migration_And_Known_Feeds.txt`

Migration logic in `pfblockerng_install.inc` (existing users → `'on'`). Hardcode the
known-affected feeds list (confirmed with maintainer). Wire the per-feed bypass of the
toggle into the download loop. Tests prove migration and per-feed override.

### Phase 4 — DoD

Prompt: `04_DoD.txt`

Smoke: `123://evil.com` with toggle on → skipped; with toggle off → blocked; `evil://`
always blocked. Migration smoke (simulate upgrade). Record DoD evidence.

## 7. Definition of done

All criteria met and evidence recorded in `RESULTS/04_Results.txt`:

- `php -l` → clean on all modified files.
- PHPUnit → green (oracle + toggle + migration + per-feed tests).
- `python -m pytest` → unchanged.
- `ruff check . && ruff format .` → clean.
- Phase 4 smoke: toggle=on → `123://` skipped, `http://host/path` skipped, `evil://host`
  blocked; toggle=off → `123://` and `http://host/path` blocked; migration confirmed.

**Manual smoke checklist** (maintainer, live pfSense box):

1. Upgrade from a previous version; confirm `pfb_scheme_strict = 'off'` in config (migration
   preserves permissive behavior for existing users).
2. Feed with `http://should-be-blocked.com` → blocked (always; valid scheme).
3. Feed with `evil://also-blocked.com` → blocked (always; valid scheme).
4. Feed with `123://should-be-skipped.com` → blocked (toggle off via migration — current
   behavior preserved).
5. Feed with `http://has-path.example.com/path` → blocked (toggle off — path stripped
   downstream as before).
6. Toggle `pfb_scheme_strict` to `on` via UI; re-run update; `123://...` now skipped + logged;
   `http://has-path.example.com/path` now skipped + logged (strict mode enabled).
7. Known-affected feed: confirm skipped + logged even when toggle is `'off'`.

**Reject criteria:**

- Any valid-scheme regression (requirements §4.1–§4.4 fail).
- Toggle-off behavior not byte-identical to today (§4.5 fails).
- Migration does not set `pfb_scheme_strict = 'off'` for existing installs (§4.10 fails).
- `python -m pytest` count changes.
