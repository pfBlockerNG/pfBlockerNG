# ADR-49: Opt-in plain-text feed sanity scanning

- **Status:** **Proposed** (2026-06-28; facts refreshed + open forks recorded 2026-07-03 — see §2.1; phase prompts not yet authored, blocked on those forks) — heuristic, non-zero false-positive risk; ships **default-off** and stays Proposed until the §7 false-positive survey clears it
- **Date:** 2026-06-28
- **Branch:** `adr/49-plain-text-sanity-scan` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`, `pfblockerng_extra.inc` (PfbConfig field)
- **Target runtime:** PHP 8.3, FreeBSD / pfSense
- **Test suite:** `vendor/bin/phpunit` (pure scanner + the PfbConfig round-trip), `tests/smoke/test_smoke_feeds.py` (ADR-04)
- **Origin:** issue #581 (BBcan177) — "plain-text feeds can pass through as `text/html` (error pages) or `application/octet-stream`… quick NUL-byte / sanity scan." The source review flagged this as **heuristic and opt-in**. Sibling of ADR-44/45/46/48.

---

## 1. Context

The MIME allow-list is permissive for text (`text/plain`, `text/html`, `text/csv`,
`application/json`, `application/x-ndjson`, `inode/x-empty`, plus host exceptions — note
plain `application/octet-stream` is **rejected** at the gate on current `devel` except the
`ipinfo.io` host carve-out and the ADR-45 archive-recovery probe). A feed URL that returns an
**HTML error/captcha page**, a **truncated body**, or **binary garbage** classified as an
allow-listed text type therefore passes the gate and fails later — opaquely — during parsing,
or silently imports a near-empty list. `pfb_filter()` has a **control-character check**
(inside `pfb_filter()`, ~:880 — UTF-8-aware and fail-closed since commit `a13effe3`), but it
runs over `pfb_filter()` **arguments** (paths/URLs/values), not the downloaded body — there
is **no body-content check at the download stage today**, which is exactly the gap this ADR
fills. It also would not catch a well-formed HTML error page or a body that is simply too
small to be a real blocklist.

A cheap **content sanity scan** on the first few KB closes the common cases:

- **NUL / excess binary** — a `text/*` feed containing NUL bytes is not text.
- **HTML error page** — the body opens with `<!doctype html` / `<html` and contains no
  blocklist-shaped lines (no IP/CIDR, no `domain.tld`-looking token) in the first N lines.
- **Below minimum content** — fewer than a small floor of non-blank, non-comment lines.

**Why opt-in + Proposed:** these are *heuristics*. A legitimate feed can be a single line, can
legitimately contain `<` (a comment), or can be an HTML-ish format we accept on purpose. A
false positive **drops a real blocklist**, which is worse than the late failure it prevents.
So this ships behind a **default-off** switch and stays Proposed until a live false-positive
survey across the real feed catalogue clears it — never auto-accepted on green unit tests alone.

**Out of scope:** archive validation (ADR-45/46); the reject-log format (ADR-48 — this ADR
logs *through* it); changing the existing control-char check (kept; this complements it).

---

## 2. Decision

1. **`pfb_text_sanity(string $sample): ?string`** — a **pure** scanner over the first chunk of
   a text feed. Returns `null` if the sample looks like plausible blocklist text, or a short
   **reason token** (`nul_bytes` | `html_error_page` | `below_min_content`) if it does not.
   No I/O; the caller reads the sample and passes it in.

   **Open forks (resolve BEFORE authoring the phase prompts — the heuristic is currently
   unquantified, so its threshold-boundary unit tests cannot be enumerated):**

   - **Parameters:** sample size ("first few KB" — how many bytes?), the non-blank/non-comment
     line floor, the NUL/"excess binary" threshold, the "blocklist-shaped line" token regex and
     its first-N-lines window. *Recommended (2026-07-03, non-binding): sample = first 8 KiB;
     `nul_bytes` = ANY `\x00` in the sample (NUL in a text feed is unambiguous — no ratio
     heuristic); `below_min_content` floor = 1 (fires only on zero non-blank, non-comment
     lines — a legitimate single-line feed passes, which is the ADR's own stated FP guard);
     `html_error_page` = sample opens with `<!doctype html`/`<html` (case-insensitive,
     leading-whitespace-tolerant) AND zero blocklist-shaped lines in the first 20 lines, where
     blocklist-shaped = an IP/CIDR, or a hosts-style `IP<ws>domain`, or a bare/ABP-wrapped
     `domain.tld` token.*
   - **MIME scope of "text branches":** enumerate the exact MIMEs scanned. Two known self-FPs
     as currently sketched: a **minified one-line JSON feed** (`application/json` is
     allow-listed) trips `below_min_content`; `inode/x-empty` (also allow-listed — an empty
     200 body) reaches the text branch. Decide per-MIME exclusion or per-format rules.
     *Recommended (2026-07-03, non-binding): scan `text/plain`, `text/html`, `text/csv` only;
     exclude `application/json`/`application/x-ndjson` (structured formats — a parse failure
     is already loud, and line-count heuristics are meaningless for minified JSON) and
     `inode/x-empty` (an empty body is its own signal; rejecting it is a behaviour change
     beyond this ADR's scope).*
   - **Encoding/fail-mode:** byte-level or `/u` matching, and the verdict on an
     invalid-UTF-8 sample (a chunk boundary can split a multibyte char and make `/u`
     `preg_match` return FALSE). The sibling control-char check's precedent is fail-closed
     (`a13effe3`); pin a stance either way. *Recommended (2026-07-03, non-binding):
     byte-level (no `/u`) — every pattern above is pure ASCII, byte matching cannot be flipped
     by a chunk-truncated multibyte char, and it sidesteps the fail-open/fail-closed question
     entirely (a truncated UTF-8 tail is simply bytes that match or don't).*

2. **One registered PfbConfig field (ADR-28/29): `pfb_feed_sanity`** — a `PfbToggle`,
   **default off**. When off, `pfb_text_sanity()` is never consulted (zero behaviour change —
   the existing matrix is byte-for-byte unchanged). When on, a non-`null` reason →
   `pfb_validate_log()` (ADR-48, `stage=plaintext`) + reject. Registry entry + `since` +
   round-trip test + the sniff's `$registeredPaths` per the config-gateway rules.

3. **Wire after the MIME gate, on text branches only** — gated on `pfb_feed_sanity` being on.
   Archive branches are untouched.

### Per-area decision table

| Area | Decision |
|---|---|
| `pfb_text_sanity()` | New pure scanner → `null` (ok) or a reason token |
| `pfb_feed_sanity` PfbConfig field | New `PfbToggle`, **default off**; gates the scan |
| Existing control-char check (`pfb_filter()`, ~:880) | **Kept** — argument-level, not body-level; this complements, does not replace it |
| Archive branches | Untouched |
| Reject logging | Through ADR-48 (`stage=plaintext`) |

---

## 3. Consequences

### Positive

- Turns "HTML error page imported as 0 entries" / "truncated body" into an early, clear,
  opt-in rejection.
- Default-off ⇒ **zero** behaviour change for existing installs unless explicitly enabled.
- Pure scanner ⇒ the heuristic matrix (including the false-positive guards) is unit-testable.

### Negative / Risks

- **Risk (the headline one):** a heuristic false-positive **drops a legitimate feed**.
  **Mitigation:** default-off; conservative thresholds; both-branches unit tests (real
  blocklist samples → `null`; error-page/binary/tiny → reason); **Proposed** until a live
  catalogue survey shows no false positive. This is a documented, deliberate gate, not a
  blocker on the ADR's *code* landing — only on its flip to Accepted / any default-on change.
- Slight per-text-feed cost when enabled (one small read + scan) — negligible.

---

## 4. Requirements (acceptance)

- `pfb_text_sanity()` is pure; unit-tested: real IP/domain blocklist samples → `null`;
  NUL-bearing, HTML-error-page, and below-min samples → the right reason token; edge cases
  (single legitimate line, comment-only-then-data) → `null`.
- `pfb_feed_sanity` round-trips through PfbConfig (default off; on/off canonical tokens);
  with it **off**, the scan never runs (asserted).
- Smoke: with the flag on, an HTML-error-page feed is rejected (`stage=plaintext`); a healthy
  text feed still imports; with the flag off, the error-page feed behaves exactly as today.
- `vendor/bin/phpunit` green.

---

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; the scanner is pure (unit-tested), live behaviour via ADR-04 smoke.
- New registered field ⇒ follow `docs/misc/config-gateway.md` (registry, `since`, round-trip
  test, `$registeredPaths`); default-off preserves upgrade behaviour (absent-key = off = today).
- Commit style `<scope>: <imperative summary> (ADR-49 PN)`; ADR text direct to `devel`,
  implementation via worktree + rebase-only-PR. **Depends on ADR-48 for the reject-log helper —
  ADR-48 is still Proposed**, so Phase 2 must either be hard-ordered after ADR-48 Phase 1
  (the formatter) or emit an interim plain `pfb_logger()` line restyled when ADR-48 lands
  (pick one when authoring the prompts).
- **Smoke fixture platform check:** the MIME gate classifies via **on-box `file(1)`**, not the
  HTTP `Content-Type` (the mock feed server serves everything `text/plain` anyway) — the
  HTML-error-page fixture only reaches the text branch if FreeBSD libmagic calls it an
  allow-listed text type. Verify the fixture's on-FreeBSD classification and record it in
  `tests/smoke/fixtures/README.md` per the FreeBSD-verified-corpus convention (the ADR-45
  libmagic-divergence lesson).

---

## 6. Action plan

### Phase 1 — Pure `pfb_text_sanity()` scanner + oracle tests

**Prompt:** `01_Scanner_Oracle.txt`

Add the pure scanner and pin the matrix: blocklist samples → `null`; NUL / HTML-error /
below-min → the reason tokens; the false-positive guards (single line, comment-then-data).

### Phase 2 — `pfb_feed_sanity` PfbConfig field + wire the gate (default-off)

**Prompt:** `02_Config_And_Wire.txt`

Register `pfb_feed_sanity` (`PfbToggle`, default off) per the gateway rules; consult the scanner
on text branches only when on; reject via ADR-48. Red→green: with the flag on, an error-page
sample is rejected; with it off (default), unchanged. Round-trip test for the field.

### Phase 3 — Smoke + (stay Proposed) false-positive survey

**Prompt:** `03_Smoke_And_Survey.txt`

Smoke: flag-on rejects an HTML-error-page feed and still imports a healthy one; flag-off is a
no-op. The false-positive survey is **automated, not a manual sign-off** (per CLAUDE.md "ADR
acceptance"): a dispatch-only script walks the **in-tree feed catalogue**
(`src/usr/local/www/pfblockerng/pfblockerng_feeds.json`, ~295 `url` entries), fetches the
first N KB of each reachable feed, runs it through `pfb_text_sanity()`, and asserts **zero
non-`null` verdicts**; persist the run's results under `RESULTS/`. Live catalogue drift after
the survey is the documented out-of-CI limitation.

---

## 7. Definition of Done

**Automated (CI / dispatch):**

- `vendor/bin/phpunit` green incl. the scanner matrix + the `pfb_feed_sanity` round-trip.
- `tests/smoke/test_smoke_feeds.py` (CE + Plus): flag-on rejects an error-page feed
  (`stage=plaintext`) and imports a healthy text feed; flag-off reproduces today's behaviour.

**Stays Proposed until:** the automated catalogue survey (§6 Phase 3 — the in-tree
`pfblockerng_feeds.json` URLs through `pfb_text_sanity()`, zero non-`null`, results persisted
under `RESULTS/`) passes. Only then → Accepted; a default-on change is a separate decision.
Post-survey catalogue drift is the documented out-of-CI limitation, not part of the gate.

**Reject criteria:**

- The scan ever runs with `pfb_feed_sanity` off.
- A legitimate blocklist sample yields a non-`null` reason in tests.
- The existing control-char check is removed or weakened.
