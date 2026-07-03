# ADR-48: Standardised download-validation rejection logging

- **Status:** **Proposed** (2026-06-28; facts + scope refreshed 2026-07-03 against `devel` — ADR-45 landed, so its four structural reject sites are now in Phase 2's scope; one design fork remains open, see §2.1)
- **Date:** 2026-06-28
- **Branch:** `adr/48-download-validation-logging` (off `devel`) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`
- **Target runtime:** PHP 8.3, FreeBSD / pfSense
- **Test suite:** `vendor/bin/phpunit` (pure formatter), `tests/smoke/test_smoke_feeds.py` (ADR-04)
- **Origin:** issue #581 (BBcan177) — "always log the raw `file` output along with which validation step caused a rejection." Sibling of ADR-44 (MIME), ADR-45 (structural), ADR-46 (ZIP hardening), ADR-49 (plain-text). This ADR is the **observability layer** the other three log *through*.

---

## 1. Context

`pfb_download()` / `pfb_filter()` reject a feed at several points — the MIME gate, the
compressed inner check, the (ADR-45) structural probe, the (ADR-46) member-name guard, the
(ADR-49) plain-text scan. Each currently emits an **ad-hoc** message string via
`pfb_logger($msg, $level)` (sink levels: 1 = pfB log, 2 = pfB + error log, 3 = extras,
5 = debugger). The text varies per site, so an operator cannot reliably answer "**why** was
this feed rejected?" with a single grep, and the **raw `file` output** that drove the
decision is not consistently recorded next to the failing stage.

`pfb_logger` itself is fine — it is the sink. What is missing is a **consistent, greppable
reject-line format** layered on top, naming the **feed**, the **stage**, the **reason**, and
the **detected detail** (the raw `file` string, the failing tool's exit code, the offending
member name). #581 asks for exactly this: "log the raw output from `file` along with which
validation step caused a rejection."

**Out of scope:** changing log *sinks* or levels; the per-stage *logic* (owned by ADR-44/45/46/49).
This ADR only standardises the **message** the existing rejection sites emit, and gives the
sibling ADRs one helper to call.

---

## 2. Decision

1. **`pfb_validate_log_line(string $feed, string $stage, string $reason, string $detail = ''): string`**
   — a **pure** formatter producing a single canonical, greppable line, e.g.:

   ```text
   pfb_validate: REJECT feed=<header> stage=<stage> reason=<reason> detected=<detail>
   ```

   `stage` ∈ `mime` | `structural` | `inner` | `member` | `plaintext`. Values are
   `htmlspecialchars()`-escaped **and control-character/newline-neutralised** (these strings
   include attacker-influenced `file` output; `htmlspecialchars()` alone passes `\n`/control
   bytes, which would let a hostile `detail` forge or split the greppable line — violating the
   §7 reject criterion). The formatter also pins the **line-termination convention** (existing
   `pfb_logger` messages carry a leading `"\n"`); the oracle test includes a `\n`-bearing
   hostile `detail`. No I/O — string in, string out — so it is fully unit-testable.

   **Open fork (resolve before authoring the phase prompts):** the two reject sites *inside*
   `pfb_filter()` (the `PFB_FILTER_FILE_MIME` branch) cannot emit the canonical line as-is —
   `pfb_filter()` never receives the feed header (only `$reference`), the same branch serves
   both the outer MIME gate (`stage=mime`) and the ZIP post-extraction re-check (`stage=inner`)
   indistinguishably, and the raw `file` output (`$mime_raw`) is discarded on the FALSE return.
   Three defensible options: (a) return/out-param the detail and emit at the `pfb_download()`
   call sites, where `$header` and the stage are both in scope (recommended — no `pfb_filter()`
   contract change); (b) extend the `pfb_filter()` `$input`/signature to carry feed+stage
   (PFBL-01-sensitive surface); (c) downgrade `feed=` to the URL (`$input[2]` is available
   inside). The choice changes the public log format — maintainer's call.

2. **`pfb_validate_log(string $feed, string $stage, string $reason, string $detail = '', int $level = 2): void`**
   — builds the line via the formatter and emits it through `pfb_logger()` at the reject
   level (default 2 = pfB + error log). One call site per rejection.

3. **Wire every download-validation rejection through it**, replacing the ad-hoc strings.
   Landed sites to wire now: the MIME-gate failure (record the raw `file` output as
   `detected=`); the **live** inner-class checks — the pre-extraction `file -bZ` compressed
   peeks for gz/bz2/7z and the ZIP **post-extraction** `PFB_FILTER_FILE_MIME` re-run (the
   literal ZIP inner-content `PFB_FILTER_FILE_MIME_COMPRESSED` block is **commented out** in
   `pfb_download()` — deferred to ADR-46; do not wire the dead block); and the **four ADR-45
   structural-probe reject sites** (landed 2026-06-29 — the `"Corrupt or unreadable {type}
   archive"` messages in `pfb_download()`, `stage=structural`; the feed `$header` is in scope
   at those call sites). Still future: the ADR-46 member guard and the ADR-49 plain-text scan —
   each sibling ADR calls `pfb_validate_log()` rather than coining its own message.
   **Open sub-question:** the 7z missing-tool rejection in `pfb_download()` is a
   download-validation reject outside the `stage` vocabulary — decide in (new `stage` token) or
   out (leave its ad-hoc message).

### Per-area decision table

| Area | Decision |
|---|---|
| `pfb_validate_log_line()` | New pure formatter → canonical greppable reject line |
| `pfb_validate_log()` | Thin wrapper → `pfb_logger()` at the reject level |
| `pfb_filter()` MIME reject | Emit via the helper; `detected=` = raw `file` output (context plumbing per the §2 open fork) |
| Inner-class rejects (live) | gz/bz2/7z `file -bZ` peeks + ZIP post-extraction re-run — `stage=inner` (NOT the commented-out `_COMPRESSED` block) |
| ADR-45 structural rejects (landed) | The four `pfb_download()` corrupt-archive sites — `stage=structural` |
| `pfb_logger` sinks / levels | **No change** — same sinks, standardised message only |
| Sibling ADRs (46/49) | Call `pfb_validate_log()` instead of ad-hoc strings when they land |

---

## 3. Consequences

### Positive

- One `grep 'pfb_validate: REJECT'` answers "what failed and why," with the raw `file` output
  inline — the diagnosability #581 asked for.
- The sibling ADRs get a single, consistent way to report a rejection — no format drift.
- Pure formatter ⇒ fully unit-testable; no live box needed for the format contract.

### Negative / Risks

- **Risk:** a standardised line drops a useful per-site detail.
  **Mitigation:** the `detail` field is free-form; each site passes its most diagnostic value
  (raw MIME, tool exit code, member name).
- Touches several call sites. The `pfb_download()`-side swaps (structural, compressed peeks)
  are one-line and behaviour-preserving for the sink (same level, same file); the two sites
  *inside* `pfb_filter()` are **not** one-line swaps — they need the context plumbing decided
  by the §2 open fork. No test pins the current ad-hoc strings (smoke asserts alias absence,
  not log text), so rewording breaks nothing.

---

## 4. Requirements (acceptance)

- `pfb_validate_log_line()` is pure; unit-tested for each `stage`, for escaping of a hostile
  `detected` value, and for the exact canonical shape.
- A forced rejection at each wired stage emits the canonical line to the pfB/error log
  (smoke/diagnostic grep).
- No existing rejection silently loses its log entry.
- `vendor/bin/phpunit` green.

---

## 5. Constraints (from CLAUDE.md)

- PHP 8.3; no new sink. The formatter is pure (unit-tested); the live emission is observed in
  the ADR-04 smoke diagnostics bundle.
- Commit style `<scope>: <imperative summary> (ADR-48 PN)`; ADR text direct to `devel`,
  implementation via worktree + rebase-only-PR.
- **Ordering:** ADR-45 has **landed** (2026-06-29), so the structural stage exists and is wired
  in Phase 2 directly. ADR-46/49 remain future callers.

---

## 6. Action plan

### Phase 1 — Pure `pfb_validate_log_line()` + oracle tests

**Prompt:** `01_Formatter_Oracle.txt`

Add the pure formatter + the `pfb_validate_log()` wrapper; pin the canonical shape, every
`stage`, and hostile-value escaping. No call-site change.

### Phase 2 — Wire the existing reject sites (behaviour-preserving for sinks)

**Prompt:** `02_Wire_Reject_Sites.txt`

Replace the ad-hoc reject strings at the MIME gate, the live inner-class checks (gz/bz2/7z
`-bZ` peeks + ZIP post-extraction re-run), **and the four landed ADR-45 structural-probe
sites** (`stage=structural` — nothing else owns wiring them; ADR-45 will not retro-wire) with
`pfb_validate_log()` (same sink level). The MIME-gate call records the raw `file` output as
`detected=` (via the §2 fork's resolution). Smoke/diagnostic asserts the canonical line on a
forced rejection.

### Phase 3 — Smoke + accept

**Prompt:** `03_Smoke_And_Accept.txt`

Force a rejection per wired stage on the live VM; assert the canonical greppable line in the
pfB/error log. Green CE + Plus flips the ADR to Accepted.

---

## 7. Definition of Done

**Automated (CI / dispatch):**

- `vendor/bin/phpunit` green incl. the formatter oracle.
- `tests/smoke/test_smoke_feeds.py` (CE + Plus): a forced MIME / inner rejection emits the
  canonical line with the raw `file` output; no healthy feed logs a spurious REJECT.

**Reject criteria:**

- A rejection that logged before now logs nothing.
- A log sink or level changes (this ADR is message-only).
- An unescaped attacker-controlled `file` string reaches the log.
