# Coding standards — naming, comments, conventions, linting

Scope: code in any language. Load when: any code change, plus `lang-*.md` context file per touched language (`.agents/context/`).

## Naming — follow the established pattern

**New variable, element `id`, dict key, or config key follows conventions already in that file (or similar files)** — match surrounding pattern (prefix, casing, separators, word order); with sibling `pfB_*` identifiers, wizard flag is `pfB_wizard_disable`, not `donotshowthisagain`. Off-pattern name = smell even when works. Spans whole stack.

## Comments — constraint, not narration

Comment states constraint code cannot show; default budget **≤3 lines**. Design rationale lives in ADR / architecture-notes, comment carries one-line pointer (`// ADR-49: content-sanity gate; contract pinned by PfbTextSanityTest`) — never restatement: contract stored in ADR + comment + test = three copies, two drift. One-line regression breadcrumbs stay (`// issue #946: decode UTF-16 BOM first — else
nul_bytes false-positives`). **Compression sheds redundancy, never essential information: usage instructions and function-contract facts (params, returns, invariants, defaults) expressed nowhere else may be reworded tighter, never removed.** Budget bites hardest mid-code; file header carrying interface documentation may run long. **Operational headers of executable scripts are interface documentation, not narration** — usage, options/params with defaults, env vars, examples stay in header unless script itself prints equivalent `--help`/usage. **Never in committed comments:** ADR **phase numbers** ("wired in Phase 4"), **`RESULTS/` handoff refs**, **review archaeology** (reviewer names, `PR #N` finding IDs, `review-fanout CN`), or correctness argument aimed at gate/reviewer — that evidence belongs in handoff / gate record / PR body, not tree. Enforced on **added** lines under `src/` + `scripts/` by `scripts/check_comment_narration.py` (pre-commit + CI, diff-scoped — pre-existing narration grandfathered until cleanup lands); escape genuine need inline with `# narration-ok: <reason>`.

## Code-quality conventions (ADR-28)

| Item | PHP 8.3 | Python 3.11+ | POSIX shell | `www/` JS |
| ---- | ------- | ------------ | ----------- | --------- |
| 1 — enums/bools over strings | backed `enum` for settings/mode values; predicates return `bool` | `enum.Enum` / `typing.Literal`; predicates return `bool` | **N/A** — keep flag strings | `const` enums/booleans for new code |
| 2 — short-circuit | cheap guard first in `&&`/`\|\|` | same | same; `case` guard before `grep` | same |
| 3 — `=` alignment | opportunistic, **touched blocks only** | same (respect `ruff format`) | opportunistic | same |
| 4 — string-ops over regex | `str_*` over `preg_*` where equivalent; hot loops first | `str` methods over `re` in per-line paths | parameter-expansion / `case` over `grep -E`/`sed` | `String.prototype` over `RegExp` |
| 5 — boolean literals | **uppercase `TRUE`/`FALSE`** (PHPCS-enforced) | `True`/`False` | N/A | lowercase |

Storage adapter rule (behaviour-preserving upgrades, grandfather seeds, canonical current storage, `PfbStoredEnum` mechanics) + per-field inventory: [`docs/misc/config-gateway.md`](../../docs/misc/config-gateway.md).

## Normalize once — bind derived values, never re-derive

Derive normalized form of value **once**, bind to variable, evaluate every subsequent condition and use against that binding — never re-run same pure operation (`strip`/`trim`, `lower`/`strtolower`, `split`/`explode`, decode, `basename`, …) on same input across successive expressions, never compute value only to throw away and recompute later in same scope. Canonical smell (Python):

```python
if not line.strip() or line.lstrip().startswith("#"):  # strips twice…
    continue
pattern = line.partition("#")[0].strip()  # …then strips again
```

Right shape: `line = line.strip()` at loop entry, then test and slice `line`. Same rule in PHP (`trim($x)` repeated across `if` chain), shell (re-running same `${var%...}`/`sed` derivation), and JS. Hot per-line paths (DNSBL/feed parsing) matter most, but rule about clarity as much as cost — one binding names invariant ("`line` is stripped from here on") instead of making reader re-verify per use. Applies to new code and any touched block; fix redundancy when you edit one.

## Text-field sanitization — sanitize once, at ingestion (issue #1723)

Every user-entered text field sanitized through shared helpers in `pfblockerng.inc` exactly ONCE, at ingestion — first operation handler performs on field, before any evaluation of contents (validation, comparison, persist) — never ad-hoc `trim`/`str_replace` chain, never re-sanitized downstream:

- **Single-line fields:** `pfb_sanitize_text()` — legacy-encoding→UTF-8 scrub, strips every `\p{C}` character (Cc/Cf/Co/Cs/Cn, subsumes BOM) + BOM, Unicode-aware trim. Unicode format characters (ZWJ/ZWNJ, bidi marks) do NOT survive as of issue #1795: package has no use for them, letting them through was seam that let same input be simultaneously "sanitized" here and "rejected" by stricter `\p{C}` validator downstream (issue #756/#1761).
- **Multi-line textarea fields:** `pfb_sanitize_text_area()` at ingestion — CRLF/CR normalized to LF, every `\p{C}` character stripped except `\n`/`\t`, each line right-stripped (indentation survives) — then persisted with plain `base64_encode()`. `pfb_text_area_encode()` (`base64_encode(pfb_sanitize_text_area(...))`) remains only for programmatic writers whose encode call itself IS ingestion point (alerts.php/pfblockerng_extra.inc/pfblockerng_install.inc re-encoders, Unbound `custom_options` re-encode, `pfblockerng_category_edit.php`'s Reports-tab whitelist-alias `addgroup` branch) — never second pass after `$_POST` field already went through ingestion prologue. Parse through `pfb_text_area_decode()`, which sanitizes once on read, drops blank/whitespace-only rows, preserves valid row `"0"`.
- **Downstream is structural, not sanitizing:** once ingested, consumer may still do own per-format hygiene on the one sanitized binding — split into lines, skip blank/comment rows, lowercase — that is shape-parsing for own use, not second sanitize pass. Exemplar: `pfb_unbound.py`'s `_load_user_regex_entries()` base64-decodes persisted blob, then `re.split()`s and strips per line and skips `#`/blank rows — structural parsing of already-sanitized data, never re-stripping control chars.
- **Validation stays fail-closed:** `pfb_filter()` remains backstop gate (rejects Cc/BOM and invalid UTF-8; type-specific checks after), run on the one sanitized binding. `PFB_FILTER_DOMAIN` / `PFB_FILTER_TLD` accept IDN input by validating its `idn_to_ascii()` punycode form and returning original text; mixed-script domains accepted by design (admins block typosquats in own lists).

New field MUST route through these helpers; persist path that deliberately stays narrower documents why. One fork raised so far — GUI hook-script editor, whose saved content is executable script source rather than list data (issue #1728) — resolved *against* carve-out: joins standard (issue #1734), so literal control byte in hook script must be written as escape (`\033`). Contracts pinned by `PfbSanitizeTextTest`, `TextAreaDecodeTest`, `PfbFilterContractTest`, `tests/smoke/ui/test_sanitize_persist.py`.

## Linting

Run linters while working; `.githooks/pre-commit` hook blocks failing commits (path-scoped to staged file types); CI is final authority.

- **Python:** `ruff check .` / `ruff check . --fix` / `ruff format .` (config in `pyproject.toml`; `.flake8` mirrors 120-col limit for IDE Flake8 — keep in sync).
- **PHP:** Intelephense (`.inc` = PHP via `files.associations`); PHPStan + PHPUnit + PHPCS via `composer install`; run PHPStan/PHPCS through composer scripts — `composer phpstan` and `composer phpcs -- --standard=phpcs.xml.dist src/` — which carry required `--memory-limit=2G`/`-d memory_limit=1G` (bare `vendor/bin/phpstan` OOMs at PHP's default 128M on this codebase, and PHPStan accepts no memory limit in `phpstan.neon`). `stubs/pfsense/` stubs are for PHPStan, NOT runtime doubles (those live in `tests/php/pfsense_doubles.php`). Three custom sniffs (`tests/phpcs/PfBlockerNG/`, each pinned by own `*SniffTest.php`): **PFBL-01 `RequirePfbFilter`** (semantic validation before exec/manifest-write/path-build inside `pfblockerng.inc` input handlers — add new in-scope surfaces to `scopeFunctions`), **`UppercaseBooleanLiteral`** (all `src/` PHP), **`RequireConfigGateway`** (see config gateway in [`docs/misc/config-gateway.md`](../../docs/misc/config-gateway.md)).
- **Shell:** ShellCheck; `.shellcheckrc` suppresses SC1091 + SC2154 only — don't suppress others without justification.
- **URL-encoding check** (`scripts/check_url_encoding.py`, pre-commit + CI): forbids naked shell-var interpolation into HTTP-client URL query — let value ride `curl --data-urlencode` instead.
- **Version-literal check** (`scripts/check_version_literals.py`, pre-commit + CI): forbids hardcoding supported pfSense/FreeBSD version token (CE/Plus version, `FreeBSD:NN` ABI, `php8x`/`py31x` flavor, `ce-`/`plus-` varver) as **value** — exact quoted literal or bare `key=value`/`key: value` RHS — anywhere under `src/`/`scripts/`/`.github/workflows/`. Read from ci-metadata matrix (`read-version-matrix.sh`) at runtime instead of restating (literal silently drifts when matrix moves). Prose, comments, Python docstrings stay clean; escape genuine one-off with inline `# version-literal-ok: <reason>`. Bare/explicit-path invocation is authoritative pre-commit/CI gate (full scan); also has diff-scoped `--staged`/`--diff <base>` modes (issue #1000) that judge only added lines — like `check_comment_narration.py`, but re-reading each changed file's whole content (needed for correct comment/docstring state) and filtering to added lines, for ad-hoc and CI-PR invocation.
- **Comment-narration check** (`scripts/check_comment_narration.py`, pre-commit + CI, diff-scoped): forbids ADR phase numbers, `RESULTS/` handoff refs, review archaeology on **added** lines under `src/` + `scripts/` ("Comments — constraint, not narration"); escape genuine need inline with `# narration-ok: <reason>`.
- **Guard-erosion check** (`scripts/check_guard_erosion.py`, pre-commit + CI, diff-scoped): a **removed** test declaration under `tests/` — Python `def test_*`, PHPUnit `function test*`, shellspec `It`/`Example`, `node --test` `test`/`it` — must be matched by the same name re-declared in the same language, by an added `successor: <retired name>` comment, or by a dated row in `docs/history/retired-tests.md`. Both sides count only where the runner really collects (`test_*.py`, `*_test.py`, `*Test.php`, `*_spec.sh` plus the hand-selected `*_env.sh`, `*.test.js`, `*.test.mjs`), so dead code neither triggers nor excuses; runs `--no-renames` because a pure `git mv` otherwise emits no hunks. `tools/webassets/` node tests are out of scope (issue #2396).
- **Re-entry-bounds check** (`scripts/check_reentry_bounds.py`, pre-commit + CI + `run-gates.sh`): forbids a **blocking** nested `pfblockerng.php` re-entry composed by hand — a line naming both a PHP interpreter (`/usr/local/bin/php`, `$pathphp`, `$pfb['php']`) and the target (`pfblockerng.php`, `$pathpfbphp`, `PFB_REENTRY_SCRIPT`) must be backgrounded (`mwexec_bg(`, `/usr/sbin/daemon -p`, a trailing `&`) or routed through the bounded spawn seam — `pfb_reentry_exec()` (PHP) / `pfb_reentry()` (shell), issue #2016 — so a stalled child cannot hold an update pass open forever. Commented-out compositions still flag; the only exemption is the seven-entry in-file `_ALLOWLIST` (the shell seam plus the six crontab *command strings*), with each entry keyed by repository-relative path, needle-scoped to one line, and carrying its justification. `--self-test` is the gate's red canary and runs first.
- **Markdown:** `npx markdownlint-cli2` (`--fix` to autofix). Blank line around every heading/list/fence; language on every fence (`text` for plain output); single trailing newline. Rules + rationale in `.markdownlint.jsonc`; clean lint enforced pre-commit + CI.
