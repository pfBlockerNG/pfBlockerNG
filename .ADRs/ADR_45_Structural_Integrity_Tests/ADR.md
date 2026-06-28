# ADR-45: Structural integrity testing for downloaded compressed feeds

- **Status:** **Proposed** (2026-06-28)
- **Date:** 2026-06-28
- **Branch:** `adr/45-structural-integrity-tests` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
- **Target runtime:** PHP 8.3, FreeBSD / pfSense; shell via `exec()` to base archive tools (`gunzip`, `bzip2`, `bsdtar`, `7z`)
- **Test suite:** `vendor/bin/phpunit` (pure helper), `tests/smoke/test_smoke_feeds.py` (live-VM, ADR-04), `shellcheck`
- **Origin:** issue #581 (BBcan177) — the "structural integrity tests" proposal, identified by the source review as the **single highest-ROI change**. Sibling of ADR-44 (MIME normalisation, landed), ADR-46 (ZIP inner-content + path-traversal), ADR-48 (validation logging), ADR-49 (plain-text sanity).

---

## 1. Context

`pfb_download()` validates a downloaded feed by running the FreeBSD `file(1)`
MIME gate (`pfb_filter()` constant `PFB_FILTER_FILE_MIME`), then dispatches on the
detected type to a decompression branch (`gzip` → `gunzip`, `bzip2` → `bzip2 -dkc`,
`zip` → `bsdtar`, `7z` → `7z e -so`). **Between the MIME gate and extraction there is
almost no structural validation** — only a partial `tar -tf` for the GeoIP/top-1M/xlsx
special cases. A corrupt, truncated, or wrong-format archive that nonetheless satisfies
the MIME gate reaches extraction and either fails opaquely downstream or yields garbage.

**This ADR is the reconciled "primary fix" for #581 — not a layer-2 nicety.** ADR-44
(MIME normalisation) shipped and, during its implementation, **discovered that the
original #581 premise is largely non-reproducible**: pfBlockerNG runs `file -b
--mime-type` on the downloaded **bytes** (never the HTTP `Content-Type`), and FreeBSD
libmagic returns `application/zip` for every ordinary ZIP — `application/x-zip-compressed`
is not in libmagic's database at all. So variant-string rewriting is defensive, and the
real, reproducible gap #581 describes is elsewhere:

- **The `octet-stream` fallback for *valid* archives.** #581 explicitly notes feeds
  that "sometimes fall back toward `application/octet-stream`" — self-extracting ZIP
  stubs, archives with leading bytes before the first local header, some truncated or
  unusual shapes, or an older magic database. `file(1)` then returns a string not in the
  allow-list and the feed is **rejected even though it is a perfectly valid, extractable
  archive**. ADR-44 deliberately does **not** promote `octet-stream` (blind promotion is
  unsafe), so that rejection stands today with no remedy.
- **Corrupt / truncated archives are not caught early.** "Magic said gzip but the body
  was truncated HTML" reaches the decompressor and fails late and opaquely.

A **structural probe** — asking the native archive tool "is this actually a parseable
archive of this type?" — fixes both: it is the safe way to recover an `octet-stream`
that *is* a valid archive (positive identification, not blanket trust) **and** the cheap
early reject for corrupt input. This is the layered-defence step the source review called
the highest-ROI change.

**Semantics that MUST be preserved (pin with tests before changing):**

- A healthy feed that imports today must still import (every existing MIME path unchanged
  on the happy path).
- A genuinely-unknown `application/octet-stream` (random binary, an HTML error page) must
  **still be rejected** — recovery is allowed **only** when a structural probe positively
  identifies a supported archive type.
- The `file(1)` MIME gate stays as the cheap first filter; the structural probe is an
  added layer, not a replacement.

**Explicitly out of scope (own ADRs):**

- MIME variant-string normalisation — **done** (ADR-44).
- ZIP inner-content (`-bZ`) re-enable + path-traversal / member-name hardening — ADR-46.
- Standardised rejection-log format — ADR-48 (this ADR emits clear messages now; the
  shared format is unified there).
- Plain-text feed heuristics (NUL/HTML/min-content) — ADR-49.

---

## 2. Decision

Add a **pure mapping helper** plus a **structural-probe call** wired into `pfb_download()`,
and an **`octet-stream` structural-recovery** path.

1. **`pfb_archive_probe(string $canonical_type): ?array`** — a pure PHP function mapping a
   canonical archive MIME to the argv of its native integrity test, or `null` for a
   non-archive type. No I/O.

   | Canonical type | Integrity test (exit 0 ⇒ valid) |
   |---|---|
   | `application/zip` | `bsdtar -tf <file>` |
   | `application/gzip` / `application/x-gzip` | `gunzip -t <file>` |
   | `application/x-bzip2` | `bzip2 -t <file>` |
   | `application/x-7z-compressed` | `7z t <file>` |
   | anything else | `null` (no probe — not an archive) |

2. **`pfb_validate_archive(string $file, string $canonical_type): bool`** — runs the probe
   (`escapeshellarg` the path, discard stdout, check the exit code). Returns `TRUE` for a
   non-archive type (nothing to test) or a passing archive; `FALSE` on a failing probe.
   Called **immediately after the MIME gate, at the top of each archive branch** in
   `pfb_download()`. On `FALSE`: log the failure (format owned by ADR-48; a clear
   message in the interim), `unlink_if_exists()`, `return FALSE`.

3. **`octet-stream` structural recovery (the #581 fix).** When the MIME gate's raw `file`
   output is **not** in the allow-list (today an outright reject) and is
   `application/octet-stream` (or empty), attempt `pfb_validate_archive()` against each
   **supported** archive type in turn; on the **first** passing probe, treat the file as
   that canonical type and proceed. If no probe passes, reject exactly as today. This is a
   **positive identification** — `octet-stream` is never blanket-accepted.

### Per-area decision table

| Area | Decision |
|---|---|
| `pfb_archive_probe()` | New pure helper: canonical type → integrity-test argv (or `null`) |
| `pfb_validate_archive()` | New helper: run the probe; called at the top of each `pfb_download()` archive branch |
| `pfb_download()` zip/gzip/bzip2/7z branches | Add the structural probe before extraction; reject on failure |
| MIME gate (`pfb_filter()` const-17) | Add `octet-stream` → structural-recovery (only on a positive archive probe) |
| `$pfb['mime_types']` allow-list | **No change** — recovery is gated on a structural probe, not an allow-list entry |
| `PFB_FILTER_FILE_MIME_COMPRESSED` (18) inner check | **No change** (re-enable is ADR-46) |
| Healthy-feed happy path | Unchanged — probe only adds a pass-through check |

---

## 3. Consequences

### Positive

- **Closes the real #581 gap** — a valid archive `file(1)` mislabels as `octet-stream`
  now imports, recovered by a safe structural probe rather than an unsafe allow-list relax.
- **Early, clear rejection** of corrupt/truncated archives instead of an opaque late
  decompressor failure.
- **Consistent** structural validation across zip/gzip/bzip2/7z (today only ZIP/GeoIP gets
  a partial `tar -tf`).
- Native base tools only; no new dependency; healthy feeds unaffected.

### Negative / Risks

- **Risk:** an exotic-but-valid archive fails the probe and is rejected.
  **Mitigation:** the probe uses the *same* tool that would extract it, so "fails the
  probe" ⇒ "would have failed extraction"; logging records the tool + exit code.
- **Risk:** `octet-stream` recovery widens what is accepted.
  **Mitigation:** recovery requires a **positive** probe pass for a supported type; random
  binary / HTML still has no passing probe and is rejected. Covered by a both-branches
  smoke pair (valid-octet-stream-ZIP accepted **and** junk-octet-stream rejected).
- **Cost:** one extra `exec()` per archive download — negligible vs. the download itself.

---

## 4. Requirements (acceptance)

- `pfb_archive_probe()` is pure (type in → argv/`null` out; no I/O); unit-tested for every
  supported type, the `x-gzip` alias, and a non-archive (`text/plain` → `null`).
- `pfb_validate_archive()` returns `TRUE` for non-archives, `TRUE` on a passing probe,
  `FALSE` on a failing one (decision logic unit-tested via an injectable runner).
- Live-VM smoke (ADR-04) proves: a corrupt archive per format is rejected; a valid archive
  mislabelled `octet-stream` is recovered and imports; a healthy feed still imports; a junk
  `octet-stream` is still rejected.
- `vendor/bin/phpunit` green; `shellcheck` clean on touched fragments.

---

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; FreeBSD base tools only — no Composer packages for production code.
- `pfb_download()`'s shell paths are **not** off-appliance unit-testable, so the *decision*
  logic lives in pure helpers (unit-tested) and the live exec/end-to-end behaviour is
  covered by the ADR-04 smoke suite — same split as ADR-44.
- Commit style `<scope>: <imperative summary> (ADR-45 PN)`; ADR text lands direct to
  `devel`, implementation via the worktree + rebase-only-PR flow.
- Every behaviour-changing phase has a test that **fails before / passes after**.

---

## 6. Action plan

### Phase 1 — Extract `pfb_archive_probe()` + oracle-pin the dispatch (behaviour-preserving)

**Prompt:** `01_Extract_Probe_Oracle.txt`

Add the pure `pfb_archive_probe()` mapping helper and an injectable
`pfb_validate_archive()`; pin the current `pfb_download()` type→branch dispatch and the
existing partial `tar -tf` behaviour with oracle tests. No call-site behaviour change yet.

### Phase 2 — Wire the structural probe into the archive branches (red → green)

**Prompt:** `02_Wire_Structural_Probe.txt`

Call `pfb_validate_archive()` at the top of each archive branch in `pfb_download()`; reject
on a failing probe with a clear message. Smoke proves a truncated/corrupt archive per
format is now rejected early (red on pre-change code, green after).

### Phase 3 — `octet-stream` structural recovery (red → green)

**Prompt:** `03_Octet_Stream_Recovery.txt`

In the MIME gate, when the raw `file` output is not allow-listed and is
`octet-stream`/empty, probe each supported archive type; on the first pass, adopt that
canonical type. Smoke proves a valid ZIP that `file` reports as `octet-stream` now imports,
**and** a junk `octet-stream` is still rejected (both branches).

### Phase 4 — Smoke checklist + accept

**Prompt:** `04_Smoke_And_Accept.txt`

Add the corrupt-archive + octet-stream-recovery fixtures to `tests/smoke/test_smoke_feeds.py`;
green CE + Plus fan-out flips the ADR to Accepted (per CLAUDE.md ADR-acceptance).

---

## 7. Definition of Done

**Automated (CI / dispatch):**

- `vendor/bin/phpunit` green, including the Phase 1 oracle + the Phase 2/3 decision-logic tests.
- `tests/smoke/test_smoke_feeds.py` (ADR-04, CE + Plus): corrupt-archive-rejected,
  octet-stream-valid-archive-recovered, junk-octet-stream-rejected, healthy-feed-still-imports.
- `shellcheck` clean.

**Reject criteria:**

- Any healthy feed that imports today fails after the change.
- A genuinely-unknown `octet-stream` (random binary / HTML page) is ever accepted.
- A structural probe is added to a non-archive (plain-text) path.
