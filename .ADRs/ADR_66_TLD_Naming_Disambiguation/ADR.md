# ADR-66: Disambiguate the two TLD features — `tld_allow` vs `tld_wildcard`

- **Status:** **Proposed** (2026-07-13)
- **Date:** 2026-07-13
- **Branch:** `adr/66-tld-naming-disambiguation` (off `devel`)
- **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc`,
  `src/usr/local/pkg/pfblockerng/pfb_unbound.py`,
  `src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php` (internal vars only),
  `docs/misc/*`
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); Python 3.11+ in Unbound's pythonmod (stdlib only)
- **Test suite:** `tests/` (pytest), `tests/php/` (PHPUnit)
- **Prerequisite:** issue **#1255** landed (the "Wildcard Blocking (TLD)" toggle now gates the
  Python/manifest path via a conditionally-present chroot oracle file + `config.tld_wildcard`).
  This ADR assumes that state and renames the surviving identifiers.

## 1. Context

pfBlockerNG's DNSBL has **two distinct TLD features** that are perennially confused in the code
because they share `*tld*`-shaped names, told apart today only by a misleading `py`/`python_`
prefix on one of them:

- **Feature A — "TLD Allow"** (UI label `pfblockerng_dnsbl.php:2679`): a **query-time allowlist**
  — block every TLD *not* specifically selected. Config key `pfb_pytld`; runtime
  `$pfb['dnsbl_pytld']` (`pfblockerng.inc:2675`); ini keys `python_tld` (enable) / `python_tlds`
  (list); evaluated in `pfb_unbound.py:6078-6088` (`evaluate_domain`).
- **Feature B — "Wildcard Blocking (TLD)"** (UI label `pfblockerng_dnsbl.php:1054`): a
  **build-time wildcard block** — collapse a feed's registrable domains to a wildcard zone (block
  all sub-domains), using the public-suffix oracle. Config key `pfb_tld`; runtime
  `$pfb['dnsbl_tld']` (`pfblockerng.inc:16005`); Python `classify()` (`pfb_unbound.py:4297`),
  `_dnsbl_load_tld_master`, `_dnsbl_tld_search`, `tld_master`.

**The `py`/`python_` prefix is a lie.** It reads as "the Python one," but *both* features run in
Python now: Feature A at query time (`evaluate_domain`), Feature B at manifest-build time
(`classify()`). The prefix distinguishes nothing and actively misleads. A reader hitting
`$pfb['dnsbl_tld']` vs `$pfb['dnsbl_pytld']`, or `tld_master`/`classify` vs `python_tlds`, cannot
tell which feature is meant without tracing the whole path. This ADR gives each feature a
**distinct, self-describing stem applied in every language** — `tld_allow` (A) and `tld_wildcard`
(B) — so the name states the feature, not the (now-meaningless) runtime stage.

### 1.1 Load-bearing facts (verified this session)

- **Two features, both Python** — Feature A query-time (`pfb_unbound.py:6078-6088`), Feature B
  build-time (`classify()` at `:5162`). The distinguishing dimension is stage, not language, so
  a stage-agnostic semantic stem is correct.
- **Identifier inventory (grep, `pfblockerng.inc` + `pfb_unbound.py`):** Feature A —
  `python_tlds` ×26, `python_tld` ×16, `python_tld_seg` ×11, `parse_python_tlds` ×4, `pytld_cnt`
  ×3, `dnsbl_pytld` ×3. Feature B (survivors) — `tld_master` ×17, `classify` ×9 (the bare
  wildcard classifier; `classify_idn`/`classify_label`/`classify_upstream_block` are unrelated
  and out of scope), `_dnsbl_tld_search` ×4, `_dnsbl_load_tld_master` ×2, plus `$pfb['dnsbl_tld']`
  readers. Re-grep at implementation time (reality-override); counts predate #1255.
- **Config gateway does NOT translate key names today** — a registry entry's array key doubles as
  the `config.xml` element (`pfblockerng_extra.inc:978,1113`, only `section`/`default`/`adapters`/
  `since`); config-gateway.md `:40` ("the stored config key stays `alexa_type` — no rename").
  Renaming a stored key would need a new indirection field or a migration. **This ADR does neither**
  — it is **internal-only** (decision below), so stored keys and www POST field names are untouched
  and config back/forward-compat is a non-issue by construction.
- **Cross-ADR interaction:** ADR-65 (Proposed, manifest = single DNSBL source) touches the same
  `classify()` / `tld_master` surface, and **#1255** reworks Feature B's oracle. Sequencing:
  **#1255 → ADR-66 → ADR-65**. ADR-65's already-written phase prompts reference the *old* names;
  Phase 4 of this ADR reconciles them (they carry reality-override lines, so a stale name is
  self-correcting, but we update them to keep the record honest).

### 1.2 Explicitly NOT part of this ADR

- **TOP1M** (`alexa_inclusion`/`alexa_count`/`top1m_token`) — a third TLD-adjacent feature, already
  distinctly named; untouched.
- **`safesearch_tlds`** (SafeSearch) and **`hsts_tlds`** (HSTS preload) — separate features that
  merely contain "tld"; not part of the Allow/Wildcard conflation; untouched.
- **The ADR-65-doomed PHP `.txt` writers** — `tld_analysis()` (`pfblockerng.inc:8402`),
  `pfb_dnsbl_py_swap`, and the legacy `py_data`/`py_zone` interchange are **removed by ADR-65 P5/P6**.
  Renaming a function about to be deleted is churn, so their *function names* are **not** renamed
  here; their *readers of `$pfb['dnsbl_tld']`* do get the variable rename (the variable rename is
  global; ADR-65 later deletes some of those readers).
- **Stored `config.xml` keys and www POST field names** — kept verbatim (internal-only depth).

## 2. Decision

**Behaviour-preserving, internal-only rename.** Give each feature a distinct stem applied across
PHP, Python, the `.inc↔.py` ini bridge, and the manifest bridge. No behaviour changes; no stored
config / www-POST changes; no config migration.

### 2.1 Feature A — "TLD Allow" → stem `tld_allow`

| in-code identifier (rename) | new name |
| --- | --- |
| `$pfb['dnsbl_pytld']` | `$pfb['dnsbl_tld_allow']` |
| ini/pfb `python_tld` (enable flag) | `tld_allow` |
| ini/pfb/cfg `python_tlds` (allow list) | `tld_allow_list` |
| `python_tld_seg` (ini + inc + py) | `tld_allow_seg` |
| py `parse_python_tlds()` | `parse_tld_allow()` |
| inc `pytld_cnt` / `pytld` locals | `tld_allow_cnt` / `tld_allow` |
| **stays (stored config / POST):** `pfb_pytld`, `pfb_pytld_sort`, `pfb_pytlds_{gtld,cctld,itld,bgtld}` | — |

### 2.2 Feature B — "Wildcard Blocking (TLD)" → stem `tld_wildcard`

| in-code identifier (rename) | new name |
| --- | --- |
| `$pfb['dnsbl_tld']` (EXACT — not `dnsbl_tld_data`/`_remove`/`_txt`) | `$pfb['dnsbl_tld_wildcard']` |
| py `classify()` (the wildcard classifier only) | `tld_wildcard_classify()` |
| py `_dnsbl_load_tld_master` | `_dnsbl_load_tld_wildcard_master` |
| py `_dnsbl_tld_search` | `_dnsbl_tld_wildcard_search` |
| py `tld_master` (build-config blob key + var; per #1255 the oracle rides the shipped `pfb_py_tld` file loaded reader-side — a manifest `config.tld_master` key is ignored, so there is NO manifest-writer rename for it) | `tld_wildcard_master` |
| manifest `config.tld_exclusion` + py/inc `tld_exclusion` | `tld_wildcard_exclusion` |
| manifest `config.tld_blacklist` + py/inc `tld_blacklist` (whole-TLD block; a sub-feature of Wildcard Blocking — UI-gated on `pfb_tld`, `dnsbl.php:3639-3644`, and gated OFF with the toggle per #1255) | `tld_wildcard_blacklist` |
| **stays (already the stem / #1255):** `config.tld_wildcard` (the enable flag) | — |
| **stays (stored config / POST):** `pfb_tld`, `tldexclusion`, `tldblacklist` | — |

### 2.3 Semantics that MUST be preserved (pin with tests before renaming)

1. **Feature A decisions unchanged** — for the same config + query corpus, `evaluate_domain`
   returns identical verdicts + log fields before and after (TLD-Allow arm: block iff enabled and
   `tld not in <allow list>`).
2. **Feature B decisions unchanged** — `classify()` (renamed) returns identical `(class, key)` for
   every input; the zone/data split and the `tld_wildcard_exclusion` opt-out behave identically.
3. **`.inc↔.py` ini bridge round-trips** — the ini keys renamed on BOTH sides (`.inc` writer +
   `.py` reader) still hand the same values across; a half-renamed bridge is a broken build.
4. **Manifest bridge round-trips** — `config.tld_exclusion`/`config.tld_blacklist` renamed on
   the writer (`pfblockerng.inc`) AND reader (`_dnsbl_config_from_manifest`) together. Per
   #1255 there is no `config.tld_master` manifest key (the oracle rides the shipped
   `pfb_py_tld` file, loaded reader-side); the internal `tld_master` build-blob key + var
   rename is reader-side only.
5. **No stored-config / www-POST change** — `config.xml` round-trips byte-identically; existing
   installs are unaffected; the UI posts the same field names.
6. **TOP1M / SafeSearch / HSTS untouched** — no accidental capture by a substring rename
   (`dnsbl_tld` must not catch `dnsbl_tld_data`; `classify` must not catch `classify_idn`).

### 2.4 Delta budget (rename scope per phase)

Behaviour-preserving, so there are no behaviour deltas. The "budget" is the **identifier set** a
phase may touch; the oracle stays byte-identical across every phase:

- **R-A (Phase 2):** the Feature-A identifier set (§2.1) only.
- **R-B (Phase 3):** the Feature-B identifier set (§2.2) only.

A phase touching the other feature's identifiers, or any stored key / behaviour, is out of budget.

## 3. Consequences

**Positive:** a reader can tell the two features apart from any single identifier; the misleading
`py`/`python_` prefix is gone; ADR-65's later TLD work lands on unambiguous names; `tld_master`
vs `tld_allow_list` no longer read as the same kind of thing.

**Negative / risks:** a wide mechanical diff (~90 occurrences across two files + www internal
vars); the `.inc↔.py` and manifest bridges must be renamed atomically or the build breaks
(mitigated by per-bridge phases + the round-trip oracle); substring-rename hazards
(`dnsbl_tld`→must not hit `dnsbl_tld_data`; `classify`→must not hit `classify_idn`) — mitigated
by exact-identifier edits and Semantic 6's guard test.

## 4. Requirements (acceptance)

- Every identifier in §2.1/§2.2 renamed; the "stays" rows demonstrably unchanged (grep proof).
- The decision oracle (Phase 1) is byte-identical green before and after every rename phase.
- `config.xml` round-trip test proves no stored-key change (Semantic 5).
- Full gate suite green (`python3 -m pytest`, `ruff`, `mypy tests/`, `php -l`, `vendor/bin/phpunit`,
  `composer phpstan`, `composer phpcs`).
- ADR-65's phase prompts + `docs/misc` reconciled to the new names (Phase 4).

## 5. Constraints (from CLAUDE.md)

- Python: 4-space indent, `from __future__ import annotations`, type hints, stdlib only inside the
  Unbound loader. PHP: tabs, PHP 8.3, no `die()`/`exit()` in library code.
- Naming follows house style: runtime `$pfb['dnsbl_*']`, ini/pfb lowercase `snake_case`, Python
  `snake_case` functions. New names sit beside their siblings (`dnsbl_tld_allow` beside
  `dnsbl_tld_wildcard`, both beside `dnsbl_*`).
- No stored `config.xml` key rename (internal-only); no `write_config()` churn.
- Comments/docstrings mentioning a renamed symbol are reconciled (no stale names left behind).

## 6. Action plan

### Phase 1 — Oracle: pin both TLD features + the bridges (behaviour-preserving)

Prompt: `01_Oracle.txt`

- Build a golden oracle over Feature A (`evaluate_domain` TLD-Allow arm: enabled/disabled, tld
  in/out of the allow list) and Feature B (`classify()`: 2-label, multi-label suffix, deeper sub,
  exclusion member, >5 labels) — the frozen expectation Phases 2/3 re-run unchanged.
- Pin the `.inc↔.py` ini bridge and the manifest bridge round-trips (values survive the
  writer→reader hop) so a half-renamed bridge fails loudly.
- A guard test for Semantic 6 (a `dnsbl_tld_data`-shaped and a `classify_idn`-shaped fixture that
  would fail if a substring rename over-reached).
- Tests only; no production change.

### Phase 2 — Rename Feature A (`tld_allow`) (behaviour-preserving)

Prompt: `02_Rename_Tld_Allow.txt`

- Rename the §2.1 identifiers across `pfblockerng.inc`, `pfb_unbound.py`, and `www` internal vars,
  including the `python_tld`/`python_tlds` ini keys on BOTH the `.inc` writer and `.py` reader
  (atomic — Semantic 3). Delta budget R-A only.
- Oracle stays byte-identical green; the ini-bridge round-trip test proves the atomic rename.

### Phase 3 — Rename Feature B (`tld_wildcard`) (behaviour-preserving)

Prompt: `03_Rename_Tld_Wildcard.txt`

- Rename the §2.2 identifiers, including `config.tld_exclusion`/`config.tld_blacklist` on BOTH
  the manifest writer (`pfblockerng.inc`) and reader (`_dnsbl_config_from_manifest`) — atomic
  (Semantic 4); the internal `tld_master` build-blob key + var is reader-side only (no
  manifest key, #1255). Rename `$pfb['dnsbl_tld']` exactly (NOT `dnsbl_tld_data`/`_remove`/`_txt`); rename
  `classify` exactly (NOT `classify_idn`/`classify_label`/`classify_upstream_block`). Delta budget
  R-B only.
- Oracle byte-identical green; the manifest-bridge round-trip + Semantic-6 guard tests prove no
  over-reach.

### Phase 4 — Docs + ADR-65 reconciliation (behaviour-preserving)

Prompt: `04_Docs_Adr65_Reconcile.txt`

- Reconcile code comments/docstrings that mention renamed symbols; update `docs/misc`
  (architecture-notes DNSBL/manifest section).
- Update ADR-65's phase prompts (`.ADRs/ADR_65_*/0*.txt`) and ADR.md references to the new names.
- Docs-class change; markdownlint clean.

## 7. Definition of done

- All §2.1/§2.2 identifiers renamed; grep shows zero surviving `python_tld*`/`parse_python_tlds`/
  `dnsbl_pytld` and zero Feature-B `classify(`/`tld_master`/`_dnsbl_tld_search` old names in
  production (excluding the intentionally-kept ADR-65-doomed writers).
- The Phase-1 oracle is byte-identical green after Phases 2 and 3 (paste both runs).
- `config.xml` round-trip proves no stored-key change.
- Full canonical gates green for every touched language.
- ADR-65 references + `docs/misc` reconciled.
- **Reject criteria:** any oracle drift (a decision or log field changed) → the rename altered
  behaviour, STOP; any stored-key/POST-field change; any substring over-reach
  (`dnsbl_tld_data`/`classify_idn` mutated).
