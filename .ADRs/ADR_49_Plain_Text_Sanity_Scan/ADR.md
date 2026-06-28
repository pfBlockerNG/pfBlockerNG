# ADR-49: Opt-in plain-text feed sanity scanning

- **Status:** **Proposed** (2026-06-28) — heuristic, non-zero false-positive risk; ships **default-off** and stays Proposed until a live false-positive survey clears it
- **Date:** 2026-06-28
- **Branch:** `adr/49-plain-text-sanity-scan` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`, `pfblockerng_extra.inc` (PfbConfig field)
- **Target runtime:** PHP 8.3, FreeBSD / pfSense
- **Test suite:** `vendor/bin/phpunit` (pure scanner + the PfbConfig round-trip), `tests/smoke/test_smoke_feeds.py` (ADR-04)
- **Origin:** issue #581 (BBcan177) — "plain-text feeds can pass through as `text/html` (error pages) or `application/octet-stream`… quick NUL-byte / sanity scan." The source review flagged this as **heuristic and opt-in**. Sibling of ADR-44/45/46/48.

---

## 1. Context

The MIME allow-list is permissive for text (`text/plain`, `text/html`, `text/csv`,
`application/json`, `application/x-ndjson`, plus the `octet-stream`/`text/x-asm` host
exceptions). A feed URL that returns an **HTML error/captcha page**, a **truncated body**,
or **binary garbage** therefore passes the gate and fails later — opaquely — during parsing,
or silently imports a near-empty list. `pfb_filter()` already has a **control-character
check** (`pfblockerng.inc` line ~685), but it does not catch a well-formed HTML error page or
a body that is simply too small to be a real blocklist.

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
| Existing control-char check (line ~685) | **Kept** — this complements, does not replace it |
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
  implementation via worktree + rebase-only-PR. Depends on ADR-48 for the reject log helper.

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
no-op. Document the live false-positive survey as the gate to flip Accepted / consider a
default change — **not** done by green unit tests alone.

---

## 7. Definition of Done

**Automated (CI / dispatch):**

- `vendor/bin/phpunit` green incl. the scanner matrix + the `pfb_feed_sanity` round-trip.
- `tests/smoke/test_smoke_feeds.py` (CE + Plus): flag-on rejects an error-page feed
  (`stage=plaintext`) and imports a healthy text feed; flag-off reproduces today's behaviour.

**Stays Proposed until:** a live false-positive survey across the real feed catalogue shows no
legitimate feed is dropped. Only then → Accepted; a default-on change is a separate decision.

**Reject criteria:**

- The scan ever runs with `pfb_feed_sanity` off.
- A legitimate blocklist sample yields a non-`null` reason in tests.
- The existing control-char check is removed or weakened.
