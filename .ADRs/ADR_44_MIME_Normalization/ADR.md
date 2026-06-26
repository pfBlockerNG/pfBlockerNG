# ADR-44: Normalise MIME-type strings before the allow-list gate in pfb_filter()

- **Status:** **Implemented (pending live-VM smoke fan-out)** (2026-06-26; PR #589 merged to `devel`) — all four phases landed (`pfb_mime_in_allowlist()` + `pfb_mime_normalise()` wired into the `PFB_FILTER_FILE_MIME` gate, oracle + red→green PHPUnit coverage incl. the gzip/bzip2 guard). A follow-up adds automated live-VM smoke for the reproducible behaviour (`tests/smoke/test_smoke_feeds.py`: zip/gzip/bzip2 feed decompression); the `x-zip-compressed` variant path is non-reproducible defensive code (see §1 + `RESULTS/SMOKE_CHECKLIST.md`). Flips to **Accepted** on a green CE + Plus smoke fan-out — no manual step.
- **Date:** 2026-06-25
- **Branch:** `adr/44-mime-normalisation` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
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

**The problem (premise revised after implementation — empirical note below):** The
allow-list contains only `application/zip` for ZIP archives. The concern was that
ZIPs packaged by non-canonical tools, or served with a non-standard MIME, could be
reported as `application/x-zip-compressed` / `application/x-zip` and rejected before
the ZIP dispatch branch.

**Empirical finding (2026-06-26).** pfBlockerNG detects the type by running
`/usr/bin/file -b --mime-type` on the downloaded **bytes** — never the HTTP
`Content-Type` — and FreeBSD libmagic returns `application/zip` for every ordinary
ZIP (deflate, stored, ZIP64, multi-file, Unicode-flag, empty — verified on
libmagic 5.41/5.46 + the compiled magic database). `application/x-zip-compressed`
is **absent from libmagic's magic database entirely** (it is a Windows / HTTP-header
MIME); `application/x-zip` is bound only to Mozilla `omni.ja`. So on a stock pfSense
box the variant strings do not arise from `file(1)`, and a normal ZIP already passes
the gate. The variant→`application/zip` normalisation is therefore **defensive** — it
guards the allow-list gate *should* a future libmagic, a custom magic file, or a
third-party `file` build ever emit those strings. The change's real, reproducible
value is the clean refactor of the MIME gate (`pfb_mime_in_allowlist()`) and the
guard that stops the new substring rule from mis-rewriting `application/gzip` /
`application/x-bzip2` (which *are* genuine libmagic outputs) to `application/zip`.
The pre-existing TODO/commented-out `PFB_FILTER_FILE_MIME_COMPRESSED` call in the ZIP
branch is unrelated (inner-content validation, out of scope) and is left untouched.

**Semantics that MUST be preserved (the contract — pin with tests before swapping):**

- Files whose raw `file` output is not a known archive variant string must never
  be promoted through normalisation (e.g. `application/octet-stream` → nothing).
- Existing hostname-based exceptions in `pfb_filter()` are unchanged.
- The allow-list itself (`$pfb['mime_types']`) is not modified; normalisation
  happens before the lookup, not inside it.
- `PFB_FILTER_FILE_MIME_COMPARE` (constant 16) is unaffected — it performs
  exact-match comparisons and must continue to do so.

**Explicitly kept out of scope:**

- Structural integrity tests for archives (deferred to a future ADR).
- ZIP path-traversal / inner-content hardening (deferred to a future ADR).
- Logging format standardisation (deferred to a future ADR).
- Plain-text heuristic scanning (deferred to a future ADR).

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
- `vendor/bin/phpunit` → green; `ruff check` / `shellcheck` → clean.
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
pin the current behaviour **before** the normalisation change is made.

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

Tests this phase adds (must **fail on Phase 1 code, pass after**):

- `test_normalise_x_zip_compressed_to_zip()`
- `test_normalise_x_zip_to_zip()`
- `test_normalise_zip_substring_variants()`
- `test_normalise_x_gzip_to_gzip()`
- `test_normalise_octet_stream_unchanged()`
- `test_normalise_unknown_string_unchanged()`
- `test_pfb_filter_mime_accepts_x_zip_compressed_after_normalise()`

### Phase 3 — Remove stale TODO; update inline documentation

**Prompt:** `03_Cleanup_TODO.txt`

Remove the TODO comment block referencing the `_COMPRESSED` incompatibility in
the ZIP branch. Replace with a reference to ADR-42 and ADR-44. Behaviour-preserving;
all oracle tests from Phase 1 stay green.

### Phase 4 — Smoke checklist + mark Accepted

**Prompt:** `04_Smoke_And_Accept.txt`

Produce the manual smoke checklist document. Update ADR.md status to `Accepted`
once the maintainer confirms smoke results.

---

## 7. Definition of Done

**Automated (CI must be green):**

- `vendor/bin/phpunit` → all tests green, including the red→green suite from Phase 2.
- `shellcheck` → clean on any shell fragments touched.
- No regressions in the existing pfBlockerNG test suite.

**Manual smoke checklist (owner: maintainer — no live Unbound in CI):**

- [ ] Download a blocklist feed served as a ZIP created by Python `zipfile` (or 7-Zip /
  Windows Explorer); confirm it passes the MIME gate and is processed normally.
- [ ] Download a feed whose ZIP previously triggered the `x-zip-compressed` rejection;
  confirm it now succeeds.
- [ ] Download a feed served as `application/gzip`; confirm it still passes (no regression).
- [ ] Enable pfBlockerNG debug logging; confirm normalisation events appear when a variant
  string is encountered.
- [ ] Download a feed that returns a genuine HTML error page; confirm it is still rejected.

**Reject criteria:**

- Any feed that previously succeeded now fails after normalisation.
- `application/octet-stream` is ever promoted through the normalisation path.
- `PFB_FILTER_FILE_MIME_COMPARE` (16) behaviour changes in any way.
