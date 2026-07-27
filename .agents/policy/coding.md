# Coding standards — naming, comments, conventions, linting

Scope: writing code in any language. Load when: any code change, plus the `lang-*.md`
context file for each touched language (`.agents/context/`).

## Naming — follow the established pattern

**A new variable, element `id`, dict key, or config key follows the conventions already in
that file (or similar files)** — match the surrounding pattern (prefix, casing, separators,
word order); with sibling `pfB_*` identifiers, a wizard flag is `pfB_wizard_disable`, not
`donotshowthisagain`. An off-pattern name is a smell even when it works. Spans the whole
stack.

## Comments — constraint, not narration

A comment states a constraint the code cannot show; default budget **≤3 lines**. Design
rationale lives in the ADR / architecture-notes and the comment carries a one-line pointer
(`// ADR-49: content-sanity gate; contract pinned by PfbTextSanityTest`) — never a
restatement: a contract stored in ADR + comment + test is three copies, two of which drift.
One-line regression breadcrumbs stay (`// issue #946: decode UTF-16 BOM first — else
nul_bytes false-positives`). **Compression sheds redundancy, never essential information: usage
instructions and function-contract facts (params, returns, invariants, defaults) that
are expressed nowhere else may be reworded tighter, never removed.** The budget bites
hardest mid-code; a file header carrying interface documentation may run long.
**Operational headers of executable scripts are interface documentation, not
narration** — usage, options/params with defaults, env vars, examples stay in the
header unless the script itself prints an equivalent `--help`/usage. **Never in
committed comments:** ADR **phase numbers**
("wired in Phase 4"), **`RESULTS/` handoff refs**, **review archaeology** (reviewer names,
`PR #N` finding IDs, `review-fanout CN`), or correctness argument aimed at the gate/reviewer
— that evidence belongs in the handoff / gate record / PR body, not the tree. Enforced on
**added** lines under `src/` + `scripts/` by `scripts/check_comment_narration.py`
(pre-commit + CI, diff-scoped — pre-existing narration is grandfathered until its cleanup
lands); escape a genuine need inline with `# narration-ok: <reason>`.

## Code-quality conventions (ADR-28)

| Item | PHP 8.3 | Python 3.11+ | POSIX shell | `www/` JS |
| ---- | ------- | ------------ | ----------- | --------- |
| 1 — enums/bools over strings | backed `enum` for settings/mode values; predicates return `bool` | `enum.Enum` / `typing.Literal`; predicates return `bool` | **N/A** — keep flag strings | `const` enums/booleans for new code |
| 2 — short-circuit | cheap guard first in `&&`/`\|\|` | same | same; `case` guard before `grep` | same |
| 3 — `=` alignment | opportunistic, **touched blocks only** | same (respect `ruff format`) | opportunistic | same |
| 4 — string-ops over regex | `str_*` over `preg_*` where equivalent; hot loops first | `str` methods over `re` in per-line paths | parameter-expansion / `case` over `grep -E`/`sed` | `String.prototype` over `RegExp` |
| 5 — boolean literals | **uppercase `TRUE`/`FALSE`** (PHPCS-enforced) | `True`/`False` | N/A | lowercase |

Storage adapter rule (behaviour-preserving upgrades, grandfather seeds, canonical current storage,
`PfbStoredEnum` mechanics) + per-field inventory:
[`docs/misc/config-gateway.md`](../../docs/misc/config-gateway.md).

## Normalize once — bind derived values, never re-derive

Derive a normalized form of a value **once**, bind it to a variable, and evaluate every
subsequent condition and use against that binding — never re-run the same pure operation
(`strip`/`trim`, `lower`/`strtolower`, `split`/`explode`, decode, `basename`, …) on the
same input across successive expressions, and never compute a value only to throw it away
and recompute it later in the same scope. Canonical smell (Python):

```python
if not line.strip() or line.lstrip().startswith("#"):  # strips twice…
    continue
pattern = line.partition("#")[0].strip()  # …then strips again
```

Right shape: `line = line.strip()` at loop entry, then test and slice `line`. Same rule in
PHP (`trim($x)` repeated across an `if` chain), shell (re-running the same
`${var%...}`/`sed` derivation), and JS. Hot per-line paths (DNSBL/feed parsing) matter
most, but the rule is about clarity as much as cost — one binding names the invariant
("`line` is stripped from here on") instead of making the reader re-verify it per use.
Applies to new code and to any touched block; fix the redundancy when you edit one.

## Text-field sanitization — sanitize once, at ingestion (issue #1723)

Every user-entered text field is sanitized through the shared helpers in
`pfblockerng.inc` exactly ONCE, at ingestion — the first operation a handler performs on
the field, before any evaluation of its contents (validation, comparison, persist) —
never an ad-hoc `trim`/`str_replace` chain and never re-sanitized downstream:

- **Single-line fields:** `pfb_sanitize_text()` — legacy-encoding→UTF-8 scrub, strips
  control characters (Cc) + BOM, Unicode-aware trim. Unicode format characters
  (ZWJ/ZWNJ, bidi marks) survive: fields accept Unicode text, especially comments.
- **Multi-line textarea fields:** `pfb_sanitize_text_area()` at ingestion — CRLF/CR
  normalized to LF, control characters stripped except `\n`/`\t`, each line
  right-stripped (indentation survives) — then persisted with a plain `base64_encode()`.
  `pfb_text_area_encode()` (`base64_encode(pfb_sanitize_text_area(...))`) remains only
  for programmatic writers whose encode call itself IS the ingestion point (the
  alerts.php/pfblockerng_extra.inc/pfblockerng_install.inc re-encoders, the Unbound
  `custom_options` re-encode, `pfblockerng_category_edit.php`'s Reports-tab whitelist-alias
  `addgroup` branch) — never a second pass after a `$_POST` field already went
  through the ingestion prologue. Parse through `pfb_text_area_decode()`, which
  sanitizes once on read, drops blank/whitespace-only rows, and preserves the valid row
  `"0"`.
- **Downstream is structural, not sanitizing:** once ingested, a consumer may still do
  its own per-format hygiene on the one sanitized binding — split into lines, skip
  blank/comment rows, lowercase — that is shape-parsing for its own use, not a second
  sanitize pass. Exemplar: `pfb_unbound.py`'s `_load_user_regex_entries()` base64-decodes
  the persisted blob, then `re.split()`s and strips per line and skips `#`/blank rows —
  structural parsing of already-sanitized data, never re-stripping control chars.
- **Validation stays fail-closed:** `pfb_filter()` remains the backstop gate (rejects
  Cc/BOM and invalid UTF-8; type-specific checks after), run on the one sanitized
  binding. `PFB_FILTER_DOMAIN` / `PFB_FILTER_TLD` accept IDN input by validating its
  `idn_to_ascii()` punycode form and returning the original text; mixed-script domains
  are accepted by design (admins block typosquats in their own lists).

A new field MUST route through these helpers; a persist path that deliberately stays
narrower documents why. The one fork raised so far — the GUI hook-script editor, whose
saved content is executable script source rather than list data (issue #1728) — was
resolved *against* a carve-out: it joins the standard (issue #1734), so a literal control
byte in a hook script must be written as an escape (`\033`). Contracts
pinned by `PfbSanitizeTextTest`, `TextAreaDecodeTest`, `PfbFilterContractTest`, and
`tests/smoke/ui/test_sanitize_persist.py`.

## Linting

Run linters while working; the `.githooks/pre-commit` hook blocks failing commits
(path-scoped to staged file types); CI is the final authority.

- **Python:** `ruff check .` / `ruff check . --fix` / `ruff format .` (config in
  `pyproject.toml`; `.flake8` mirrors the 120-col limit for IDE Flake8 — keep in sync).
- **PHP:** Intelephense (`.inc` = PHP via `files.associations`); PHPStan + PHPUnit + PHPCS via
  `composer install`; run PHPStan/PHPCS through the composer scripts — `composer phpstan` and
  `composer phpcs -- --standard=phpcs.xml.dist src/` — which carry the required
  `--memory-limit=1G`/`-d memory_limit=1G` (bare `vendor/bin/phpstan` OOMs at PHP's default
  128M on this codebase, and PHPStan accepts no memory limit in `phpstan.neon`). The
  `stubs/pfsense/` stubs are for PHPStan, NOT runtime doubles (those live in
  `tests/php/pfsense_doubles.php`). Three custom sniffs (`tests/phpcs/PfBlockerNG/`, each
  pinned by its own `*SniffTest.php`): **PFBL-01 `RequirePfbFilter`** (semantic validation
  before exec/manifest-write/path-build inside `pfblockerng.inc` input handlers — add new
  in-scope surfaces to `scopeFunctions`), **`UppercaseBooleanLiteral`** (all `src/` PHP),
  **`RequireConfigGateway`** (see the config gateway in
  [`docs/misc/config-gateway.md`](../../docs/misc/config-gateway.md)).
- **Shell:** ShellCheck; `.shellcheckrc` suppresses SC1091 + SC2154 only — don't suppress
  others without justification.
- **URL-encoding check** (`scripts/check_url_encoding.py`, pre-commit + CI): forbids naked
  shell-var interpolation into an HTTP-client URL query — let the value ride
  `curl --data-urlencode` instead.
- **Version-literal check** (`scripts/check_version_literals.py`, pre-commit + CI): forbids
  hardcoding a supported pfSense/FreeBSD version token (CE/Plus version, `FreeBSD:NN` ABI,
  `php8x`/`py31x` flavor, `ce-`/`plus-` varver) as a **value** — an exact quoted literal or a
  bare `key=value`/`key: value` RHS — anywhere under `src/`/`scripts/`/`.github/workflows/`.
  Read it from the ci-metadata matrix (`read-version-matrix.sh`) at runtime instead of
  restating it (a literal silently drifts when the matrix moves). Prose, comments, and Python
  docstrings stay clean; escape a genuine one-off with an inline `# version-literal-ok: <reason>`.
  The bare/explicit-path invocation is the authoritative pre-commit/CI gate (full scan); it
  also has diff-scoped `--staged`/`--diff <base>` modes (issue #1000) that judge only added
  lines — like `check_comment_narration.py`, but re-reading each changed file's whole content
  (needed for correct comment/docstring state) and filtering to the added lines, for ad-hoc
  and CI-PR invocation.
- **Comment-narration check** (`scripts/check_comment_narration.py`, pre-commit + CI,
  diff-scoped): forbids ADR phase numbers, `RESULTS/` handoff refs, and review archaeology on
  **added** lines under `src/` + `scripts/` ("Comments — constraint, not narration"); escape a
  genuine need inline with `# narration-ok: <reason>`.
- **Retired-token guard** (`scripts/check_retired_tokens.py`, issue #1059; pre-commit,
  CI-PR, and a Claude `PreToolUse` hook, diff-scoped, **warn-only during rollout**): a quoted literal
  removed on ≥3 scan-root lines and not re-added as the same exact quoted span is a
  *retirement*; any surviving occurrence (`git grep -F` over `src/`/`scripts/`/
  `.github/workflows/`) is reported as a straggler (the #1047 class). Findings warn; a tool
  error (exit ≥2) fails the CI job. Escapes: `# retired-token-ok: <reason>` on an intentional
  survivor, `--token-allowlist` for a staged migration. Promote to blocking once the observed
  false-positive rate is near zero.
- **Markdown:** `npx markdownlint-cli2` (`--fix` to autofix). Blank line around every
  heading/list/fence; a language on every fence (`text` for plain output); single trailing
  newline. Rules + rationale in `.markdownlint.jsonc`; clean lint enforced pre-commit + CI.
