# ADR-46: ZIP inner-content validation consistency and extraction-path hardening

- **Status:** **Proposed** (2026-06-28) — defense-in-depth; lower priority than ADR-45 (most of the original "re-enable the inner check" ask is already satisfied — see §1)
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

- **ZIP inner-content validation is already active** — after `tar -xOf` extraction the
  ZIP branch **re-runs `PFB_FILTER_FILE_MIME` on the extracted payload**
  (`pfblockerng.inc` ~line 8389). So a ZIP whose *contents* are not an allow-listed type
  is already rejected. The source review itself noted this post-extraction check "is
  actually quite good."
- **The `file -bZ` `_COMPRESSED` check cannot be re-enabled for ZIP.** libmagic's `-Z`
  decompresses a *single compressed stream* (gzip/bzip2/xz) and classifies the inner
  bytes; a **ZIP is a multi-member container**, not a single stream, so `-Z` does not
  classify ZIP inner content the way it does for gzip/bzip2/7z. This is the real reason
  for the long-standing commented-out block (the "incompatability with ZIP files" TODO),
  which ADR-44 left disabled and reworded. Re-enabling it is not a viable path; the
  post-extraction MIME re-check is the correct ZIP equivalent.
- **Path traversal on the main path is already neutralised.** The primary ZIP path extracts
  with `tar -xOf` (to **stdout**, piped through `sed`/`tr`) — member names never reach the
  filesystem, so a `../`-laden member cannot escape. The **only** disk-writing extraction
  is the trusted GeoIP/top-1M branch (`tar -xf --strip=1 -C <dir>`), which handles MaxMind
  / top-1M archives, not arbitrary user feeds.

So the residual, genuinely-new value is narrow and defense-in-depth:

1. **Make the ZIP inner-validation story explicit and consistent** — name the
   post-extraction MIME re-check as *the* ZIP inner-content gate, and document why `-bZ`
   stays off, so a future maintainer does not re-open the "re-enable the inner check"
   rabbit hole.
2. **Add an explicit member-name guard before any disk-writing extraction** (the
   `tar -xf -C` GeoIP/top-1M path) — reject an archive containing a member whose name is
   absolute (`/…`), contains a `..` path component, or is implausibly long, *before*
   extracting to disk. Cheap insurance even though those feeds are trusted.

**Out of scope (own ADRs):** outer MIME normalisation (ADR-44, done); structural integrity
probes + octet-stream recovery (ADR-45); standardised reject logging (ADR-48); plain-text
heuristics (ADR-49).

**Semantics to preserve:** every feed that imports today still imports; the `-xOf` stdout
path is unchanged; the GeoIP/top-1M extraction still works for legitimate archives.

---

## 2. Decision

1. **`pfb_zip_member_names(string $file): array`** — list archive members (`bsdtar -tf`,
   the listing already used for the xlsx probe), returned as a PHP array. Thin, but isolates
   the `exec` for testing the guard logic against captured listings.

2. **`pfb_archive_members_safe(array $names): bool`** — a **pure** predicate: `FALSE` if any
   member name is absolute, contains a `..` component (split on `/`), or exceeds a sane length
   cap; `TRUE` otherwise. Unit-tested against the full matrix of hostile and benign names.

3. **Wire the guard before disk extraction.** In the GeoIP/top-1M branch, before
   `tar -xf --strip=1 -C`, call the guard on the member list; on `FALSE`, log (format per
   ADR-48) + `unlink_if_exists()` + `return FALSE`. The `-xOf` stdout path is left unchanged
   (no disk write, no traversal surface) but gains a one-line comment recording why no guard
   is needed there.

4. **Formalise the inner-content comment.** Replace the disabled `_COMPRESSED` block's prose
   with a precise statement: ZIP inner-content validation **is** the post-extraction
   `PFB_FILTER_FILE_MIME` re-check; `file -bZ` is not used for ZIP because `-Z` does not
   classify multi-member containers. Remove the "deferred to a future ADR" wording (this ADR
   *is* that resolution).

### Per-area decision table

| Area | Decision |
|---|---|
| ZIP inner-content gate | Keep the post-extraction `PFB_FILTER_FILE_MIME` re-check; document it as the gate |
| `file -bZ` for ZIP | Stays off — `-Z` cannot classify a multi-member container (documented, not deferred) |
| `tar -xOf` main path | Unchanged (stdout — no traversal surface); comment why |
| `tar -xf -C` GeoIP/top-1M path | Add `pfb_archive_members_safe()` guard before extraction |
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

### Phase 2 — Wire the guard before disk extraction + formalise the inner-content comment

**Prompt:** `02_Wire_Guard_And_Document.txt`

Call the guard before the GeoIP/top-1M `tar -xf -C`; reject on failure. Replace the disabled
`_COMPRESSED` prose with the precise inner-validation statement. Smoke: a malicious-member
archive is rejected; a legitimate multi-file archive still imports.

### Phase 3 — Smoke + accept

**Prompt:** `03_Smoke_And_Accept.txt`

Add the hostile-member + legitimate-multi-file fixtures to `tests/smoke/test_smoke_feeds.py`;
green CE + Plus fan-out flips the ADR to Accepted.

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
