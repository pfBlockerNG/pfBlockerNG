# ADR-46: ZIP inner-content validation consistency and extraction-path hardening

- **Status:** **Proposed** (2026-06-28; facts refreshed 2026-07-03 against `devel` — the §1 extraction inventory was corrected to THREE disk-writing sites, and the guard-scope question in §2.3 is an open fork; phase prompts not yet authored) — defense-in-depth; lower priority than ADR-45 (most of the original "re-enable the inner check" ask is already satisfied — see §1) — **(facts refreshed 2026-07-04: the §1 "inner validation already active" premise was wrong — issue #808; the probe-target fix landed independently, narrowing this ADR to the member-name guard)**
- **Date:** 2026-06-28
- **Branch:** `adr/46-zip-inner-content-hardening` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
- **Target runtime:** PHP 8.3, FreeBSD / pfSense; `bsdtar` (libarchive)
- **Test suite:** `vendor/bin/phpunit` (pure helper), `tests/smoke/test_smoke_feeds.py` (ADR-04), `shellcheck`
- **Origin:** issue #581 (BBcan177) — "improve ZIP consistency / re-enable inner-content validation / defensive path checks". **Reconciled with the live code** (per the maintainer's direction): the inner-content half is largely already in place; this ADR formalises it and adds the member-name guard. Sibling of ADR-44 (MIME), ADR-45 (structural integrity), ADR-48 (logging), ADR-49 (plain-text).

---

## 1. Context

The source review proposed three things for the ZIP path: **re-enable the inner-content
(`file -bZ`) check, make ZIP consistent with gzip/bzip2/7z, and add path-traversal
defences.** Reading the *current* `pfb_download()` rather than the pre-implementation
spec, two of the three are already handled or infeasible:

- **ZIP inner-content validation is now real — it was a no-op until issue #808's fix.** After
  `tar -xOf` extraction the ZIP branch **re-runs `PFB_FILTER_FILE_MIME`**
  (`pfb_download()` in `pfblockerng.inc`, ~:9469), but until issue #808 the re-check probed
  `$input[1]` = `$file_download`, the ORIGINAL archive (already outer-MIME-allow-listed as
  `application/zip`), never the extracted payload — a pure no-op, live-confirmed by the
  ADR-48 fan-out. Issue #808's fix (landed on `devel`) repoints the probe at the extracted
  file, so a ZIP whose *contents* are not an allow-listed type is now genuinely rejected.
- **The `file -bZ` `_COMPRESSED` check cannot be re-enabled for ZIP.** libmagic's `-Z`
  decompresses a *single compressed stream* (gzip/bzip2/xz) and classifies the inner
  bytes; a **ZIP is a multi-member container**, not a single stream, so `-Z` does not
  classify ZIP inner content the way it does for gzip/bzip2/7z. This is the real reason
  for the long-standing commented-out block (the "incompatability with ZIP files" TODO),
  which ADR-44 left disabled and reworded. Re-enabling it is not a viable path; the
  post-extraction MIME re-check is the correct ZIP equivalent.
- **Path traversal on the main path is already neutralised.** The primary ZIP path extracts
  with `tar -xOf` (to **stdout**, piped through `sed`/`tr`) — member names never reach the
  filesystem, so a `../`-laden member cannot escape. There are **THREE** disk-writing
  extractions in `pfb_download()` (corrected 2026-07-03 — the original text claimed one):
  the gzip GeoIP branch (`tar -xzf --strip=1 -C {geoipshare}`, ~:9088), the **UT1/blacklist
  branch** (`tar -xf --include='*domains' … -C {dbdir}/…`, ~:9114 — a **third-party**
  archive from ut-capitole.fr whose member names feed on-disk filenames), and the ZIP
  GeoIP/top-1M branch (`tar -xf --strip=1 -C`, ~:9172). Only the last handles MaxMind /
  top-1M; the UT1 branch is not maintainer-trusted infrastructure.

So the residual, genuinely-new value is narrow and defense-in-depth:

1. **Make the ZIP inner-validation story explicit and consistent** — name the
   post-extraction MIME re-check as *the* ZIP inner-content gate, and document why `-bZ`
   stays off, so a future maintainer does not re-open the "re-enable the inner check"
   rabbit hole.
2. **Add an explicit member-name guard before any disk-writing extraction** — reject an
   archive containing a member whose name is absolute (`/…`), contains a `..` path
   component, or is implausibly long, *before* extracting to disk. **Open fork
   (guard scope):** the lazy root-cause is one guard call before **all three** `-C`
   extraction sites (§1) — the UT1 branch is the least-trusted of the three; if any site is
   deliberately excluded, the ADR must say why. Maintainer's call before the phase prompts
   are authored.

**Out of scope (own ADRs):** outer MIME normalisation (ADR-44, done); structural integrity
probes + octet-stream recovery (ADR-45); standardised reject logging (ADR-48); plain-text
heuristics (ADR-49).

**Semantics to preserve:** every feed that imports today still imports; the `-xOf` stdout
path is unchanged; the GeoIP/top-1M extraction still works for legitimate archives.

---

## 2. Decision

1. **`pfb_zip_member_names(string $file): array`** — list archive members (`bsdtar -tf`,
   the listing already used for the xlsx probe), returned as a PHP array. **Must filter
   bsdtar warning/noise lines** — the same listing path already special-cases a
   `tar: Failed to set default locale` first line (see the existing handling near the ZIP
   listing, ~:9168); a lister that returns warning lines as "member names" triggers exactly
   the false-reject risk §3 names. Thin, but isolates the `exec` for testing the guard
   logic against captured listings.

2. **`pfb_archive_members_safe(array $names): bool`** — a **pure** predicate: `FALSE` if any
   member name is absolute, contains a `..` component (split on `/`), or exceeds a sane length
   cap (**cap value settled in Phase 1 and pinned by its tests** — it is currently
   unspecified; *recommended, non-binding: the FreeBSD filesystem limits — 255 bytes per
   path component (`NAME_MAX`) and 1024 bytes total (`PATH_MAX`) — anything above them cannot
   extract anyway, so they reject nothing legitimate*); `TRUE` otherwise. Unit-tested against the full matrix of hostile and benign
   names.

3. **Wire the guard before disk extraction** (sites per the §1.2 guard-scope fork). Before
   each guarded `tar … -C`, call the guard on the member list; on `FALSE`, log via plain
   `pfb_logger()` matching the ADR-45 reject-line style (**ADR-48 is still Proposed — do not
   depend on it; restyle to its format when it lands**) + `unlink_if_exists()` +
   `return FALSE`. **Red-test observable:** the pre-change behaviour on a hostile archive is
   **silent partial success** — extraction errors are discarded (`>/dev/null 2>&1`) and the
   branch returns `TRUE` unconditionally (bsdtar's default refusal of `..` members just
   skips them) — so the failing-before test must assert the explicit reject log + `FALSE`
   return + no partial extraction, never a generic "import fails". The `-xOf` stdout path is
   left unchanged (no disk write, no traversal surface) but gains a one-line comment
   recording why no guard is needed there.

4. **Formalise the inner-content comment — SATISFIED by issue #808's fix, outside this ADR.**
   The in-code comment above the post-extraction re-check now documents it as the ZIP
   inner-content gate and explains why `-bZ` stays off (multi-member containers); no
   "deferred to a future ADR" wording remains. This ADR's residual scope is items 1–3 (the
   member-name guard) only.

### Per-area decision table

| Area | Decision |
|---|---|
| ZIP inner-content gate | **Satisfied (issue #808)** — post-extraction `PFB_FILTER_FILE_MIME` re-check now probes the extracted payload and is documented as the gate |
| `file -bZ` for ZIP | **Satisfied (issue #808)** — stays off, now documented in-code: `-Z` cannot classify a multi-member container |
| `tar -xOf` main path | Unchanged (stdout — no traversal surface); comment why |
| `tar … -C` disk-writing paths (gzip GeoIP, UT1/blacklist, ZIP GeoIP/top-1M) | Add `pfb_archive_members_safe()` guard before extraction (scope per the §1.2 open fork) |
| `pfb_archive_members_safe()` | New pure predicate: reject absolute / `..` / over-long member names |

---

## 3. Consequences

### Positive

- Closes the #581 "ZIP consistency / inner validation" item **honestly** — names the existing
  gate, documents the `-bZ` infeasibility, and removes the misleading "deferred" comment.
- Adds a real (if modest) traversal guard on the one disk-writing extraction path.
- Pure predicate ⇒ the hostile-name matrix is unit-testable off-appliance.

### Negative / Risks

- **Low residual value** — most of the original ask was already satisfied; this is
  defense-in-depth, not a fix for an observed failure. Sized accordingly (Proposed, low
  priority behind ADR-45).
- **Risk:** the member-name cap rejects a legitimate deep-path archive.
  **Mitigation:** the cap targets only absolute/`..`/pathological names; normal nested paths
  pass. Tested both ways.

---

## 4. Requirements (acceptance)

- `pfb_archive_members_safe()` is pure; unit-tested for absolute paths, `..` components,
  over-long names (all → `FALSE`) and benign nested names (→ `TRUE`).
- The GeoIP/top-1M extraction still imports a legitimate multi-file archive (smoke/regression).
- A crafted archive with a `../`-escaping member is rejected before disk extraction (smoke).
- `vendor/bin/phpunit` green; `shellcheck` clean.

---

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; `bsdtar` from base. The `exec`-bearing lister is thin; the *decision* logic lives in
  the pure predicate (unit-tested), live extraction covered by ADR-04 smoke.
- Commit style `<scope>: <imperative summary> (ADR-46 PN)`; ADR text direct to `devel`,
  implementation via worktree + rebase-only-PR.

---

## 6. Action plan

### Phase 1 — Pure `pfb_archive_members_safe()` predicate + oracle tests

**Prompt:** `01_Member_Safety_Predicate.txt`

Add the pure predicate and pin its decision matrix (absolute / `..` / over-long → reject;
benign → accept). No call-site change.

### Phase 2 — Wire the guard before disk extraction

**Prompt:** `02_Wire_Guard_And_Document.txt`

Call the guard before the GeoIP/top-1M `tar -xf -C`; reject on failure. (The inner-content
comment formalisation originally scoped here was satisfied by issue #808 — see §2 item 4;
Phase 2 is now the guard-wiring only.) Smoke: a malicious-member
archive is rejected; a legitimate multi-file archive still imports.

### Phase 3 — Smoke + accept

**Prompt:** `03_Smoke_And_Accept.txt`

Add the hostile-member + legitimate-multi-file fixtures and cases; green CE + Plus fan-out
flips the ADR to Accepted. Mechanics pinned in advance (they are not the `test_smoke_feeds.py`
default path):

- The GeoIP/top-1M URLs are **hardcoded** in `pfblockerng.php`, so `mock_feeds.feed_url()`
  cannot reach that branch via feed config — drive `pfb_download()` **directly** via
  `h.php_eval` pointed at the mock server (the `tests/smoke/test_smoke_714_asn_geoip.py`
  pattern).
- A `../`-member archive cannot be created by stock `zip`/`bsdtar` (they refuse) — craft it
  as **raw bytes** (e.g. Python `zipfile` on the dev box), commit it to
  `tests/smoke/fixtures/` with a README entry, and verify its on-FreeBSD classification per
  that README's FreeBSD-verified-corpus convention (the ADR-45 libmagic-divergence lesson).

---

## 7. Definition of Done

**Automated (CI / dispatch):**

- `vendor/bin/phpunit` green incl. the predicate matrix.
- `tests/smoke/test_smoke_feeds.py` (CE + Plus): legitimate multi-file archive imports;
  hostile-member archive rejected before extraction; existing ZIP feeds unaffected.
- `shellcheck` clean.

**Reject criteria:**

- A legitimate archive that imports today fails after the guard.
- The `-xOf` stdout path is altered (it must stay byte-for-byte).
- The post-extraction inner-content MIME re-check is removed or weakened.
