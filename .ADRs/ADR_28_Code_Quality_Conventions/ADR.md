# ADR-28: Code-Quality Conventions (enums, short-circuiting, literals, string-ops)

- **Status:** **Proposed** (2026-06-17)
- **Date:** 2026-06-17
- **Branch:** `adr/28-code-quality-conventions` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (+ `pfblockerng_install.inc`, `pfblockerng_extra.inc`, `pfb_unbound_include.inc`) — PHP core
  - `src/usr/local/www/` — PHP UI pages, widgets, wizard, JS
  - `src/usr/local/pkg/pfblockerng/pfb_unbound.py` — Python (Unbound loader, stdlib-only)
  - `src/usr/local/pkg/pfblockerng/pfblockerng.sh` (+ `list_scripts/*.sh`) — POSIX shell
  - `CLAUDE.md` — the conventions policy of record
  - `tests/phpcs/PfBlockerNG/` — the targeted enforcement sniff
  - `tests/php/`, `tests/` — round-trip + behaviour-pinning tests
  - `tests/smoke/` — the automated upgrade-contract case (Phase 11)
- **Target runtime:** PHP 8.3 (pfSense CE 2.8); Python 3.11+ (stdlib only inside Unbound's pythonmod); POSIX `/bin/sh`
- **Test surface:** `vendor/bin/phpunit` + `vendor/bin/phpcs` + `vendor/bin/phpstan` (PHP, PR gate); `python -m pytest` (Python + tooling, PR gate); `tests/smoke` (ADR-04 live VM — the upgrade-contract + behaviour proof); `shellcheck`/`sh -n`

Originates from **issue #265** (BBcan177) with refinements in its comments (andrebrait): prefer
**enumerated types** over booleans for type-safe languages, and generalise "boolean-first tests"
to **short-circuiting**. Coordinates with **ADR-26** (shell locale/portability — do not disturb
its inline `LC_ALL=C` prefixes).

---

## 1. Context (today)

### 1.1 The five requested conventions

Issue #265 asks for five code-quality conventions, refined by its comments:

1. **Prefer booleans over `on`/`off` string flags** — and (comment) prefer **enumerated types**
   over raw booleans in typed languages: more expressive at the call site, cheap, and
   refactoring-stable when a third option appears. Strings only where a value is genuinely
   open-ended or is a serialized/wire format.
2. **Put the cheap boolean/enum test first** in a conditional — generalised (comment) to
   **leverage short-circuiting** so an expensive test (regex, filesystem, lookup) only runs when
   a cheap guard already passed.
3. **Align `=` with tabs** where it aids readability.
4. **Prefer string functions over regex** where semantically equivalent (cheaper, clearer) —
   genuinely material only in hot loops.
5. **Uppercase `TRUE`/`FALSE`** (PHP) — matches pfSense house style.

### 1.2 Current state (measured, not assumed)

- `pfblockerng.inc` carries **~845** `true`/`false`-family tokens in mixed case (incl. stray
  PascalCase `False`, e.g. `:10564`, `:1640`), and **33** `preg_*` calls (most one-shot, a few in
  per-line/per-host loops).
- **236** `== 'on'` / `== 'off'` comparisons across `src/` (13 files) read config-derived flags.
- **Zero** PHP `enum` declarations exist anywhere in `src/` today — this is greenfield.
- Config flags are stored in `config.xml` as `'on'`/`''` (checkboxes) or small option strings,
  read via `config_get_path(...)` and compared `== 'on'` (`pfblockerng.inc:1334,1346,1364`).
- The config→runtime seam is **`pfb_global()`** (`pfblockerng.inc:1278`): it reads each
  `installedpackages/...` blob into `$pfb[...]` and already normalises several flags to
  `'on'`/`'off'`/`''` runtime strings (e.g. `$pfb['dnsbl_lenient']` at `:1364`). These derived
  runtime values are an **internal** representation, not the stored contract.

### 1.3 The upgrade contract (load-bearing constraint)

pfBlockerNG ships **no config-version/migration routine** — confirmed by audit. There is no
harness that rewrites stored values on package upgrade. Therefore **the stored representation in
`config.xml` *is* the upgrade contract**: if an upgrade changed a stored `'on'` to a boolean
`true` (or a stored option string to an enum name), every existing install would read a value its
code no longer recognises — a silent settings-loss regression with no migration to repair it.

### 1.4 Premise check (why this is NOT an ADR-01-style perf bet)

Issue #265 frames items 1 and 4 as performance ("quicker", "less intensive"). For per-flag config
reads in PHP/Python that delta is unmeasurable — there is **no perf premise to disprove**, so this
ADR is anchored on **maintainability, expressiveness, and type-safety**, not speed. The single
place where item 4 is genuinely material is **hot loops** (per-feed-line in `pfblockerng.sh`,
per-DNS-query / per-host in `pfb_unbound.py` and `pfblockerng.inc`); those are targeted, not a
blanket regex ban.

## 2. Decision

Adopt the five conventions as the project's **policy of record in `CLAUDE.md`**, and apply them
across the existing code in **progressive, correlated, behaviour-preserving phases** (§6) — each
one commit, each leaving the full suite green, each reviewed before the next. Per-language mapping:

### 2.1 Per-language convention table

| Item | PHP 8.3 | Python 3.11+ | POSIX shell | `www/` JS |
| ---- | ------- | ------------ | ----------- | --------- |
| 1 — enums/bools over strings | backed `enum` for settings/mode values; genuine **predicates return `bool`** | `enum.Enum` / `typing.Literal`; predicates return `bool` | **N/A** (no bool/enum type) — keep flag strings | `const` enums/booleans for new code |
| 2 — short-circuit | cheap guard first in `&&`/`\|\|`; guard side-effect ordering | same | `&&`/`\|\|` order; `case` guard before `grep` | same |
| 3 — `=` alignment | opportunistic, **touched blocks only** | same (respect `ruff format`) | opportunistic | same |
| 4 — string-ops over regex | `str_*`/`strpos`/`str_contains` over `preg_*` where equivalent; **hot loops first** | `str` methods over `re` in per-query/per-line paths | parameter-expansion / `case` over `grep -E`/`sed` where equivalent | `String.prototype` methods over `RegExp` |
| 5 — uppercase `TRUE`/`FALSE` | **uppercase** literals | `True`/`False` (Python is correct as-is) | N/A | `true`/`false` (JS is lowercase) |

### 2.2 Enums are internal; the config storage format is hard-frozen (the adapter rule)

- **`config.xml` stored values never change** — every checkbox `'on'`/`''` and every option string
  stays byte-identical across upgrade. This is the contract from §1.3.
- Enums/booleans are an **internal runtime representation only**. The conversion happens at a
  **read-boundary adapter** (centred on `pfb_global()` and any sibling read site): stored string →
  internal enum/bool on read; internal enum/bool → the **exact same legacy stored string** on write.
- A **backed enum's backing value equals the stored string** where a direct map is natural
  (`case On = 'on'`), so `Enum::tryFrom($stored) ?? Enum::default()` is the adapter and `$e->value`
  is the writer. Where a field's "off" is `''` vs `'off'`, the adapter is **field-aware** of that
  field's exact legacy vocabulary — there is no single global toggle.
- **Round-trip identity is mandatory and pinned by tests**: for every adapted field, every existing
  stored value (incl. empty / unset / any legacy variant) must satisfy `write(read(v)) == v`. **If a
  field cannot round-trip losslessly, it is excluded** — it stays a string, documented as such. This
  is the falsifiable gate (§7).

### 2.3 Semantics that MUST be preserved (the contract — pinned before each swap)

1. **Every `config.xml` stored value is byte-identical before/after** any phase — proven by the
   per-field round-trip tests (§2.2) and the smoke upgrade check (§7).
2. **No behavioural change** from any enum adoption, conditional reorder, or regex→string swap —
   the DNSBL/IP/Geo decisions, UI output, and feed processing are identical. Proven by PHPUnit +
   pytest golden tests over touched logic and the ADR-04 smoke fan-out.
3. **Short-circuit reorders never change evaluation side effects** — a condition with a side effect
   (assignment, function with effects) is reordered only when proven order-independent; otherwise
   left as-is.
4. **`pfb_unbound.py` stays stdlib-only** and its per-query latency does not regress.

### 2.4 Explicitly kept / out of scope

- **`config.xml` storage format** (§2.2) — frozen, never migrated.
- **`py_unbound.ini`** and any **manifest / serialized / wire** value the Python or shell side
  reads — these are contracts with other processes; kept as strings.
- **ADR-26 shell locale prefixes** (`LC_ALL=C` on collation sinks) — untouched; the shell phase
  coordinates with, never rewrites, them.
- **Genuine boolean predicates** (functions answering a yes/no, presence checks) — these return
  `bool` (uppercase literals in PHP), **not** an enum; an enum predicate is an anti-pattern.
- **Standalone repo-wide reformatting** — alignment (item 3) is applied only within blocks a phase
  already edits; a mass realign of untouched lines is the "gratuitous reformatting" CLAUDE.md
  forbids and is **out of scope**.
- **Stub files** (`stubs/`), generated artifacts, and third-party vendored code.

## 3. Consequences

**Positive**

- Call sites read as domain intent (`Toggle::On`, `IdnMode::All`) instead of bare `'on'`/`''`
  string literals; a new option is a new enum case, not a scatter of new string compares.
- Cheap-guard-first conditionals avoid needless regex/filesystem/lookup work on the common path.
- One documented, partly machine-enforced convention set future code follows mechanically.
- Mixed-case PHP literals and stray PascalCase booleans are normalised; the diff noise shrinks.

**Negative / risks**

- This is a **large, correlated refactor** touching most of the codebase. The mitigation is the
  phasing discipline: a tested adapter safety-net first, mechanical/provably-safe phases before
  semantic ones, per-subsystem bounded diffs, and orchestrator review at every phase boundary.
- Enum adoption at the config seam is the highest-risk change; it is gated entirely by the §2.2
  round-trip identity tests and the smoke upgrade check — a field that cannot round-trip is excluded
  rather than forced.
- Short-circuit reordering can silently change behaviour if a reordered condition has a side
  effect; §2.3.3 forbids reordering those.

**Neutral**

- Shell gains no enums/booleans (no such type); its phase is items 2–4 only and must not disturb
  ADR-26.
- Python `True`/`False` is already correct; its phase is enums-for-modes + short-circuit +
  str-over-`re` in hot paths only.

## 4. Requirements (acceptance)

- All five conventions documented in `CLAUDE.md` as the policy of record, with the per-language
  table (§2.1), the hard-freeze + adapter rule (§2.2), and the out-of-scope carve-outs (§2.4).
- The retroactive sweep completed across PHP, Python, and shell in the §6 phases, each
  behaviour-preserving and green.
- A targeted PHPCS sniff enforcing uppercase PHP `TRUE`/`FALSE` (cheap, mechanical) added and
  wired into `phpcs.xml.dist` + CI.
- Round-trip identity tests covering every adapted config field's full stored vocabulary.
- Full suite green at every phase: `python -m pytest`, `vendor/bin/phpunit`, `vendor/bin/phpstan`,
  `vendor/bin/phpcs`, `ruff check`/`ruff format`, `shellcheck`/`sh -n`. `ui_render` (Tier A) gates
  each `src/`-touching PR automatically.
- **Phase 11** adds an automated **upgrade-contract** smoke case and dispatches the **smoke fan-out
  (CE + Plus)** + the **UI tiers** — the live-VM acceptance gate, green before Accept.

## 5. Constraints (from CLAUDE.md)

- **Naming** — new enums/cases/keys follow the established `pfB_*`/`pfb_*` and surrounding patterns.
- **PHP** — tabs; PHP 8.3; no `die()`/`exit()` in library code; keep the PFBL-01 `RequirePfbFilter`
  sniff green; stub any newly-reached pfSense function from upstream rather than working around it.
- **Python** — 4 spaces; `from __future__ import annotations`; `enum` is stdlib (allowed in the
  Unbound loader); no bare `except`.
- **Shell** — POSIX `sh`; quote expansions; do not touch ADR-26 `LC_ALL=C` prefixes.
- **Clean the diff** — minimal, intentional changes; alignment opportunistic within touched blocks
  only; no churn-then-revert, no scratch files.
- **Plan with a higher model, implement with Sonnet** — each phase is executed by a Sonnet
  sub-agent under orchestrator gating (`/adr-phase`).

## 6. Action plan

**Non-breaking phase-split strategy.** (1) The tested adapter + enum infrastructure lands **first**
as the safety net before any call-site swap. (2) Provably behaviour-preserving mechanical phases
(literal-case normalisation) precede semantic phases (enum adoption, reordering, regex→string), so
the riskier diffs land on an already-normalised, low-noise surface. (3) Phases are **bounded per
subsystem** so each diff stays reviewable. (4) Each phase is one commit, leaves the full suite
green, and is reviewed against its objective before the next starts.

### Phase 1 — Conventions policy + enum/adapter infrastructure (prep)

Prompt: `01_Policy_And_Infra.txt` — behaviour-preserving, unused-in-prod.

- Write the conventions policy into `CLAUDE.md` (§2.1 table, §2.2 adapter rule, §2.4 carve-outs).
- Introduce the internal enum types (PHP backed enums + Python `Enum`/`Literal`) for the recurring
  config flags, and the **field-aware read/write adapter** helpers (PHP `pfb_cfg_*`, Python sibling).
- Pin **round-trip identity** over every existing stored value (incl. `''`/unset/legacy) in
  `tests/php/` + `tests/`. No call site changed yet.

### Phase 2 — PHP `TRUE`/`FALSE` uppercase normalisation: package `.inc`

Prompt: `02_Php_Literals_Pkg.txt` — mechanical, behaviour-preserving.

- Normalise all boolean literals to uppercase across `pfblockerng.inc`, `pfblockerng_install.inc`,
  `pfblockerng_extra.inc`, `pfb_unbound_include.inc`; fix stray PascalCase. No logic change.

### Phase 3 — PHP `TRUE`/`FALSE` uppercase normalisation: `www/`

Prompt: `03_Php_Literals_Www.txt` — mechanical, behaviour-preserving.

- Same normalisation across `src/usr/local/www/` PHP (pages, widgets, wizard). Split from Phase 2
  to bound the diff.

### Phase 4 — Enum adoption at the `pfb_global()` config seam

Prompt: `04_Enum_Adoption_Inc_Seam.txt` — behaviour-preserving via the Phase-1 adapter.

- Convert the `pfb_global()` (`pfblockerng.inc:1278`) flag population to internal enums/bools via the
  adapter, and update the downstream `=== 'on'` compares it feeds. Save paths write the legacy string
  back. Round-trip tests extended; behaviour pinned.

### Phase 5 — Enum adoption: remaining `.inc` + `www/` flags

Prompt: `05_Enum_Adoption_Rest.txt` — behaviour-preserving via the adapter.

- Extend enum adoption to the remaining config-derived flag reads in the other `.inc` files and the
  `www/` pages, all through the same adapter. Any field that cannot round-trip is excluded + noted.

### Phase 6 — Short-circuit / cheap-test-first reordering (PHP)

Prompt: `06_Short_Circuit_Php.txt` — behaviour-preserving (side-effect-safe).

- Reorder conditionals so the cheap enum/bool guard precedes expensive tests, only where the
  reorder is provably side-effect-free (§2.3.3). Golden tests over non-trivial reordered logic.

### Phase 7 — regex → string functions (PHP)

Prompt: `07_Regex_To_String_Php.txt` — behaviour-preserving.

- Replace `preg_*` with `str_*`/`strpos`/`str_contains`/`str_starts_with` where semantically
  equivalent, **prioritising hot loops**. Each swap pinned by a test asserting identical results on
  representative + edge inputs. Non-equivalent regexes are left as-is.

### Phase 8 — Python conventions (`pfb_unbound.py`)

Prompt: `08_Python_Conventions.txt` — behaviour-preserving, stdlib-only.

- Introduce `Enum`/`Literal` for mode values; apply short-circuit ordering; replace `re` with `str`
  methods in the per-query/per-line hot path where equivalent. pytest green; no latency regression.

### Phase 9 — Shell conventions (`pfblockerng.sh` + `list_scripts/`)

Prompt: `09_Shell_Conventions.txt` — behaviour-preserving; coordinates with ADR-26.

- Apply short-circuit ordering, string-ops (`case`/parameter-expansion) over `grep -E`/`sed` where
  equivalent, and opportunistic alignment. **Do not touch** ADR-26 `LC_ALL=C` prefixes. shellcheck +
  smoke green.

### Phase 10 — Enforcement sniff + CLAUDE.md reconcile

Prompt: `10_Sniff_And_Dod.txt`.

- Add the targeted PHPCS sniff enforcing uppercase PHP `TRUE`/`FALSE`; wire into `phpcs.xml.dist` +
  CI; pin it with a fixture test alongside the PFBL-01 sniff tests. Reconcile `CLAUDE.md` (incl. any
  documented field exclusions), ensure the diff is minimal.

### Phase 11 — Smoke/UI validation + automated upgrade-contract + Definition of Done

Prompt: `11_Smoke_And_Validation.txt` — the acceptance gate.

- Build an **automated upgrade-contract smoke case** (`tests/smoke`, `repo`/upgrade marker): install
  the prior release `.pkg` with a representative settings spread, capture `config.xml`, `pkg upgrade`
  to the branch build, then assert every adapted field's stored value is **byte-identical** and a
  representative runtime behaviour (a blocked DNSBL name, an IP block) is unchanged. This automates
  the §7 contract proof so acceptance needs no manual sign-off (CLAUDE.md "ADR acceptance").
- **Dispatch the live-VM validation:** `smoke-fanout.yml` (ADR-04 suite, **CE + Plus**, AND-gated)
  and the **UI tiers** (`ui_render` is the PR gate; dispatch `ui_e2e`/`ui_browser` too). Record the
  green run links. Confirm the full DoD (§7).

## 7. Definition of done

- Every §4 requirement met; full suite green at every phase (commands in §4).
- **Round-trip identity proven** for every adapted config field over its full stored vocabulary
  (the §2.2 gate). Any excluded field documented in `CLAUDE.md` / the ADR.
- The PHPCS uppercase-`TRUE`/`FALSE` sniff active and green.
- **Automated upgrade-contract smoke (Phase 11)** green on the live-VM fan-out: install prior
  release → configure a representative settings spread (DNSBL on/off, IDN mode, lenient, auto-VIP, a
  couple of feeds) → `pkg upgrade` to the branch build → assert every adapted field's `config.xml`
  value is **byte-identical** and a representative runtime behaviour (blocked DNSBL name, IP block) is
  unchanged. This automates the contract proof — **no manual sign-off** (CLAUDE.md "ADR acceptance").
- **Smoke fan-out (CE + Plus) + UI tiers green** — `smoke-fanout.yml` AND-gate passes; `ui_render`
  PR gate green; `ui_e2e`/`ui_browser` dispatched green.
- **Residual manual check (owner: maintainer, out-of-CI):** true *visual* GUI correctness only — a
  spot-check that the settings pages render unchanged. Per CLAUDE.md this is a documented out-of-CI
  limitation, **not** an acceptance blocker.
- **Reject criteria (explicit):**
  - If a config field's stored value **cannot round-trip losslessly** through its adapter and the
    field cannot simply be excluded without losing the convention's value → that field's conversion
    is **rejected** (kept as string).
  - If any phase measurably **regresses `pfb_unbound.py` per-query latency** or the feed-processing
    hot path → that change is reverted.
  - If the enum-everywhere churn is found to **introduce behavioural regressions the adapter +
    tests cannot contain** → narrow scope to derived/new code only (fall back to the "policy +
    bounded audit" posture) rather than forcing the full sweep.

See the ordered `NN_*.txt` phase prompts in this directory.
