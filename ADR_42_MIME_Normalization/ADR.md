# ADR-42: Normalise MIME-type strings before the allow-list gate in pfb_filter()

- **Status:** **Proposed** (2026-06-25)
- **Date:** 2026-06-25
- **Branch:** `adr/42-mime-normalisation` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
- **Target runtime:** PHP 8.3, FreeBSD / pfSense; shell via `exec()` to `/usr/bin/file`
- **Test suite:** `vendor/bin/phpunit` (unit), `shellcheck` (shell fragments)

---

## 1. Context

`pfb_filter()` in `pfblockerng.inc` validates downloaded feed files by running:

```sh
/usr/bin/file -b --mime-type "$path"
```

and checking the result against a fixed PHP allow-list (`$pfb['mime_types']`):

```php
$pfb['mime_types'] = array_flip([
    'inode/x-empty', 'text/x-file',
    'text/plain', 'text/html', 'text/xml', 'text/csv',
    'application/csv', 'application/json', 'application/x-ndjson',
    'application/x-tar',
    'application/gzip', 'application/x-gzip',
    'application/x-bzip2',
    'application/zip'
]);
```

Constants involved:
- `PFB_FILTER_FILE_MIME` (17) — outer MIME check, raw `file -b --mime-type`
- `PFB_FILTER_FILE_MIME_COMPRESSED` (18) — inner MIME via `file -bZ --mime-type`
- `PFB_FILTER_FILE_MIME_COMPARE` (16) — strict exact-match variant

**The problem:** Different archive creators (Info-ZIP, 7-Zip, Windows Explorer,
Python `zipfile`, .NET, Go, Rust) and ZIP options (extra fields, ZIP64 on small
files, Unicode filename flags, store vs. deflate) cause `file(1)` to return
`application/x-zip-compressed`, `application/x-zip`, or occasionally
`application/octet-stream` for structurally valid ZIPs. Only `application/zip`
is in the allow-list, so valid blocklist ZIPs from some maintainers are rejected
before the ZIP dispatch branch is reached. Similar (lower-frequency) variant
strings exist for gzip variants. This is the direct cause of the existing TODO
comment and the commented-out `PFB_FILTER_FILE_MIME_COMPRESSED` call in the ZIP
branch.

**Semantics that MUST be preserved (the contract — pin with tests before swapping):**
- Files whose raw `file` output is not a known archive variant string must never
  be promoted through normalisation (e.g. `application/octet-stream` → nothing).
- Existing hostname-based exceptions in `pfb_filter()` are unchanged.
- The allow-list itself (`$pfb['mime_types']`) is not modified; normalisation
  happens before the lookup, not inside it.
- `PFB_FILTER_FILE_MIME_COMPARE` (constant 16) is unaffected — it performs
  exact-match comparisons and must continue to do so.

**Explicitly kept out of scope:**
- Structural integrity tests for archives (ADR-43).
- ZIP path-traversal hardening (ADR-44).
- Logging format standardisation (ADR-45).
- Plain-text heuristic scanning (ADR-46).

---

## 2. Decision

Inside the `PFB_FILTER_FILE_MIME` (17) branch of `pfb_filter()`, after the raw
`file` output is obtained and before the allow-list lookup, apply a normalisation
pass using a small, explicit map:

| Raw string (from `file`) | Normalised to |
|---|---|
| `application/x-zip-compressed` | `application/zip` |
| `application/x-zip` | `application/zip` |
| any string containing `zip` (case-insensitive) | `application/zip` |
| `application/x-gzip` | `application/gzip` (already in allow-list; make explicit) |

Rules:
- Normalisation is a **string-rewrite** applied only when the raw value matches a
  known variant pattern. It never promotes `application/octet-stream` or any
  other non-archive string.
- Every normalisation event is logged at pfBlockerNG debug level, recording both
  the original and normalised string.
- All existing hostname exceptions are preserved without change.
- `PFB_FILTER_FILE_MIME_COMPARE` (16) is not modified.

### Per-area decision table

| Area | Decision |
|---|---|
| `pfb_filter()` constant 17 | Add `pfb_mime_normalise()` helper; call before allow-list lookup |
| `pfb_filter()` constant 18 | No change |
| `pfb_filter()` constant 16 | No change (exact-match; must stay exact) |
| `$pfb['mime_types']` array | No change |
| Hostname exceptions | Preserved unchanged |
| Logging | Debug-level log of raw → normalised, only when normalisation fires |

---

## 3. Consequences

### Positive
- Eliminates false rejections of valid ZIP feeds packaged by non-canonical tools.
- Normalisation is isolated to a single named helper — easy to audit and extend.
- No new external tool dependencies; no allow-list changes.
- Unblocks ADR-44 (ZIP inner-content validation), which was deferred because ZIPs
  were being rejected before reaching the validation branch.

### Negative / Risks
- **Risk:** A too-broad `zip`-substring match promotes a misidentified file.
  **Mitigation:** Normalisation fires only when `file` already returned something
  containing `zip` — random `octet-stream` is never promoted. Oracle tests
  enumerate the exact variant strings; any new variant requires an explicit entry.
- **Risk:** Normalisation masks a real format change in a feed.
  **Mitigation:** Debug-level logging records the raw string; always visible when
  investigating a download.
- The normalisation table must be maintained as new creators or magic-db changes
  surface (expected to be low frequency; low burden).

---

## 4. Requirements (acceptance)

- `pfb_mime_normalise()` is a pure PHP function (string in → string out; no I/O).
- Unit tests cover: all listed variant strings → correct canonical; strings NOT in
  the map → returned unchanged; case-insensitive `zip` variants; `application/octet-stream`
  → unchanged.
- All existing `pfb_filter()` call-sites remain green (oracle regression suite).
- `vendor/bin/phpunit` → green; `ruff check` / `shellcheck` → clean (no PHP files
  other than `pfblockerng.inc` touched in the implementation phases).
- Debug log output is observable in a manual smoke run.

---

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; FreeBSD stdlib only (no Composer packages added for production code).
- Commit style: `<scope>: <imperative summary> (ADR-42 PN)`.
- Branch: `adr/42-mime-normalisation` off `devel`; inline commits, push directly;
  PR only if direct push rejected.
- No live Unbound in CI — PHP unit tests only; manual smoke checklist for the
  live-box run.
- Every behaviour-changing phase must have a test that **fails before / passes after**
  (red → green evidence recorded in handoff).

---

## 6. Action plan

### Phase 1 — Extract and oracle-pin the current `pfb_filter()` MIME path

**Prompt:** `01_Extract_Oracle_Tests.txt`

Extract the MIME-string handling logic from `pfb_filter()` (constants 16–18) into
clearly named, pure helper functions, and lay down oracle/regression tests that
pin the current behaviour **before** the normalisation change is made. These tests
stay green through all subsequent phases.

Tests this phase adds:
- `test_pfb_filter_mime_allows_canonical_zip()` — `application/zip` passes gate.
- `test_pfb_filter_mime_rejects_x_zip_compressed()` — `application/x-zip-compressed`
  currently **fails** gate (this is the bug; record the red result in handoff).
- `test_pfb_filter_mime_rejects_x_zip()` — `application/x-zip` currently fails gate.
- `test_pfb_filter_mime_allows_canonical_gzip()` — `application/gzip` passes.
- `test_pfb_filter_mime_rejects_octet_stream()` — `application/octet-stream` fails.

### Phase 2 — Implement `pfb_mime_normalise()` and wire into constant 17

**Prompt:** `02_Implement_Normalise.txt`

Add the `pfb_mime_normalise(string $raw): string` helper and call it inside the
`PFB_FILTER_FILE_MIME` (17) branch of `pfb_filter()`. Add debug-level logging.

Tests this phase adds (these must **fail on Phase 1 code, pass after**):
- `test_normalise_x_zip_compressed_to_zip()`
- `test_normalise_x_zip_to_zip()`
- `test_normalise_zip_substring_variants()`
- `test_normalise_x_gzip_to_gzip()`
- `test_normalise_octet_stream_unchanged()`
- `test_normalise_unknown_string_unchanged()`
- Integration: `test_pfb_filter_mime_accepts_x_zip_compressed_after_normalise()`

### Phase 3 — Remove stale TODO; update inline documentation

**Prompt:** `03_Cleanup_TODO.txt`

Remove the TODO comment block referencing the `_COMPRESSED` incompatibility in
the ZIP branch. Replace with a reference to ADR-42 and ADR-44. Update any other
inline comments in `pfb_filter()` that describe the old, un-normalised flow.
Behaviour-preserving; all oracle tests from Phase 1 stay green.

### Phase 4 — Smoke checklist + mark Accepted

**Prompt:** `04_Smoke_And_Accept.txt`

Produce the manual smoke checklist document (see §7). Update ADR.md status to
`Accepted` once the maintainer confirms smoke results. No code change in this
phase.

---

## 7. Definition of Done

**Automated (CI must be green):**
- `vendor/bin/phpunit` → all tests green, including the red→green suite from Phase 2.
- `shellcheck` → clean on any shell fragments touched.
- No regressions in the existing pfBlockerNG test suite.

**Manual smoke checklist (owner: maintainer — no live Unbound in CI):**
- [ ] Download a blocklist feed served as a ZIP created by Python `zipfile` (or 7-Zip / Windows
  Explorer); confirm it passes the MIME gate and is processed normally.
- [ ] Download a feed whose ZIP previously triggered the `x-zip-compressed` rejection; confirm
  it now succeeds.
- [ ] Download a feed served as `application/gzip`; confirm it still passes (no regression).
- [ ] Enable pfBlockerNG debug logging; confirm normalisation events appear when a variant
  string is encountered (`raw: "application/x-zip-compressed" -> canonical: "application/zip"`).
- [ ] Download a feed that returns a genuine HTML error page; confirm it is still rejected.

**Reject criteria:**
- Any feed that previously succeeded now fails after normalisation.
- `application/octet-stream` is ever promoted through the normalisation path.
- `PFB_FILTER_FILE_MIME_COMPARE` (16) behaviour changes in any way.
