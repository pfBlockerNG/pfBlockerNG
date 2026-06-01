# CLAUDE.md — pfBlockerNG

## Communication

**Always activate `/caveman` skill at session start.** Terse, no filler, full technical accuracy.

---

## Repository structure

```text
pfBlockerNG/
├── src/                   # Production code — root mirrors pfSense filesystem
│   ├── etc/inc/priv/      # pfSense privilege definitions (.priv.inc)
│   └── usr/local/
│       ├── pkg/pfblockerng/   # Core package logic
│       │   ├── pfblockerng.inc        # Main PHP include
│       │   ├── pfblockerng_install.inc
│       │   ├── pfblockerng_extra.inc
│       │   ├── pfb_unbound_include.inc
│       │   ├── pfb_unbound.py         # Unbound Python plugin
│       │   ├── pfblockerng.sh         # Shell script (POSIX sh)
│       │   └── ip_pre_AWS_*.sh        # Per-region AWS IP-prefix pre-scripts (hand-maintained)
│       ├── share/             # Package metadata (info.xml)
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # Python test suite (pytest)
├── scripts/               # Developer tooling (deploy, stub generation)
│   ├── deploy.sh          # Push files to live pfSense over SSH
│   ├── setup-hooks.sh     # One-time: point git at .githooks (core.hooksPath)
│   └── update-pfsense-stubs.py  # Regenerate stubs from pfSense source
├── stubs/pfsense/         # PHP stubs for Intelephense (IDE only, not shipped)
├── stubs/python/          # unboundmodule.py stub for Pylance/mypy + tests (not shipped)
├── .editorconfig          # Indent rules per language
├── .shellcheckrc          # ShellCheck suppressions
├── .flake8                # Flake8 config mirroring Ruff (Flake8 can't read pyproject.toml)
├── .markdownlint.jsonc    # markdownlint rule set (VS Code extension + markdownlint-cli2)
├── .markdownlint-cli2.jsonc  # markdownlint-cli2 globs + ignores
├── pyproject.toml         # pytest + ruff + mypy config
└── README.md
```

Release archives contain only `src/`. Everything else (stubs, scripts, tests, CI, pyproject.toml, `.githooks/`) is dev-only.

---

## Git hooks

Activate once after cloning: `sh scripts/setup-hooks.sh` (sets `core.hooksPath`
to `.githooks`; or run `git config core.hooksPath .githooks` directly). git cannot
auto-apply a committed hooks path — cloning must not silently install hooks — so
this one-time opt-in is required.

**Claude: before working in this repo, ensure the hooks are active.** If
`git config core.hooksPath` is not `.githooks`, run `sh scripts/setup-hooks.sh`
once at the start of the session (idempotent; safe to re-run).

**Claude: any GitHub Actions workflow that commits code must activate the hooks
first.** Have the workflow run `sh scripts/setup-hooks.sh` before its commit/push
steps (after checkout) so automated commits go through the same `pre-commit` /
`pre-push` checks — subject to which tools the runner has installed.

- **`.githooks/pre-commit`** runs the fast linters (and the unit suite) and blocks
  the commit on any failure: `ruff check`/`ruff format --check`, `python -m pytest`,
  `markdownlint-cli2`, `sh -n` + `shellcheck`, and `php -l`. Each check runs only
  when its tool is installed (a missing tool is reported and skipped — CI is the
  hard gate); PHPStan runs only when `vendor/bin/phpstan` exists. Bypass in an
  emergency with `git commit --no-verify`.
- **`.githooks/pre-push`** enforces tag naming before pushes reach the remote.

---

## Running tests

```sh
python -m pytest
```

Run from repo root. `pyproject.toml` sets `testpaths` and `-v`. No `cd` needed.

Run after **any** change to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` or
`tests/` — in-loop, for fast feedback; don't wait for the commit to find breakage.
The pre-commit hook re-runs the suite at commit time and CI is the final authority,
so a separate manual pre-commit run is not needed.

---

## Linting

Run the linters below **while working**, for fast feedback. Enforcement is layered,
so treat them as feedback rather than a manual pre-commit checklist: the
`.githooks/pre-commit` hook blocks any commit that fails them, and CI is the final
authority. (CI runs them even when the local hook is inactive or a tool is missing.)

### Python

```sh
ruff check .        # lint
ruff check . --fix  # lint + autofix
ruff format .       # format
```

Config in `pyproject.toml`. Target: Python 3.11+ (pfSense CE 2.8 / FreeBSD 15).

Ruff is the canonical linter. `.flake8` exists only so contributors who run
Flake8 (e.g. the VS Code extension) get the same 120-column limit and ignore set
— Flake8 can't read `pyproject.toml`, so without it Flake8 falls back to a
79-column default and to whitespace checks Ruff delegates to `ruff format`. Keep
the two in sync if the Ruff config changes.

### PHP

Intelephense in VS Code. `.inc` files are PHP — `files.associations` handles this.
Stubs in `stubs/pfsense/` resolve pfSense-provided functions. If Intelephense flags
a pfSense function as undefined, add it to the appropriate stub file rather than
expanding the `undefinedFunctions` suppression in `.vscode/settings.json`.

### Shell

ShellCheck via VS Code extension. All scripts use `#!/bin/sh` (POSIX sh, not bash).
`.shellcheckrc` suppresses SC1091 (pfSense source files unreachable locally) and
SC2154 (rc(8)-injected variables). Do not suppress other rules without justification.

### Markdown

markdownlint via the VS Code "markdownlint" extension and the CLI. Run from repo root:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint + autofix
```

When writing Markdown, produce compliant output directly: put a blank line around
every heading, list, and fenced code block; give each fenced block a language
(use a `text` fence for plain output, trees, or ASCII); and end the file with a
single trailing newline. Long lines and compact (unaligned) tables are fine — `MD013`
and `MD060` are disabled.

Rule set is in `.markdownlint.jsonc` (read by both the extension and the CLI);
globs/ignores are in `.markdownlint-cli2.jsonc`. The ruleset is pragmatic — it
enforces structural/consistency rules but disables ones that fight the
documentation style: `MD013` (line length), `MD060` (table-column alignment),
`MD036` (the ADR `**Positive**`/`**Negative**` inline sub-headers), and `MD041`
(frontmatter-led files such as `.claude/skills/*.md` don't open with an H1);
`MD024` is `siblings_only`. `**/TRANSCRIPT.md` is ignored (verbatim transcript,
not maintained docs). Keep the disabled-rule rationale in `.markdownlint.jsonc`
in sync if the set changes. A clean lint (`0 error(s)`) is enforced by the
pre-commit hook and in CI (`test.yml`) alongside ShellCheck/PHP; run
`npx markdownlint-cli2 --fix` while editing for fast feedback.

---

## Code standards

### PHP

- Indent: **tabs** (enforced by `.editorconfig`)
- Target: PHP 8.3 (pfSense CE 2.8)
- Functions injected by pfSense at runtime (from `util.inc`, `config.lib.inc`, etc.)
  are declared in `stubs/pfsense/` — do not `require_once` pfSense files in tests
- No `die()`/`exit()` in library code; return values or throw

### Python

- Indent: **4 spaces**
- Target: Python 3.11+; use `from __future__ import annotations` for forward refs
- Add type hints to new functions; leave existing untyped code alone unless touching it
- No bare `except:`; use `except Exception` at minimum
- `pfb_unbound.py` runs inside Unbound's Python loader — no dependencies outside stdlib
- Unbound injects its API symbols (`log_info`, `RR_TYPE_*`, `DNSMessage`, …) as
  globals at runtime; `pfb_unbound.py` references them as bare names. They are
  declared once in `stubs/python/unboundmodule.py` (a dev/test stand-in), which
  Pylance/mypy resolve via the `TYPE_CHECKING` import and the test suite copies
  onto `builtins` (see `tests/conftest.py`). Add a new injected symbol there.

### Shell

- POSIX sh only (`#!/bin/sh`), no bash-isms (`[[`, arrays, `$RANDOM`, etc.)
- Quote all variable expansions: `"$var"`, `"${var}"`
- Use absolute paths for all binaries (pfSense convention); do not rely on `$PATH`
- `ip_pre_AWS_*.sh` are near-identical, hand-maintained per-region pre-scripts
  (selectable in the UI) that differ only by a `jq` region filter; when changing
  shared logic, apply it uniformly across all of them

---

## Updating documentation

Update `README.md` when:

- Workflow steps change (test command, deploy command, release steps)
- Minimum supported pfSense CE version changes
- New developer tooling is added

Update `stubs/pfsense/` when:

- Minimum supported pfSense CE version is bumped — run:

  ```sh
  python scripts/update-pfsense-stubs.py            # defaults to the newest public source
  python scripts/update-pfsense-stubs.py --version X.Y.Z
  ```

  The generator downloads pfSense source from GitHub and emits one stub file per
  module (`util.php`, `interfaces.php`, `certs.php`, …) with cross-file dedup. It
  defaults to **2.7.2** (`STUB_SOURCE_VERSION`): Netgate's public mirror is frozen
  there — no `RELENG_2_8_0` ref — and those signatures are stable across 2.7→2.8,
  which is all PHPStan level 0 needs (symbol existence). Generate from a real 2.8
  checkout if/when one is available.
- pfBlockerNG starts calling a new pfSense API function not yet stubbed — add it
  to the appropriate file in `stubs/pfsense/` manually
- `globals.php` is **always** manually maintained (array shapes can't be auto-derived);
  `logging.php` and `supplemental.php` are likewise hand-maintained and never
  regenerated (`supplemental.php` holds pfSense functions used on CE 2.8 that are
  absent from the 2.7.2 stub source, e.g. `config_read_file`). PHPStan is the gate:
  prefer stubbing a real pfSense function over a `phpstan-baseline.neon` suppression.

---

## Branches and releases

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable  | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel`. Pushing a `vX.Y.Z` tag triggers CI: tests → GitHub
Release → PR on `pfsense/FreeBSD-ports`. Tags from `devel` become pre-releases;
tags from `main` become stable releases.

---

## Commit style

Follow existing log: `<scope>: <imperative summary>`.
Examples: `ci: simplify pytest invocation`, `dev: add ShellCheck config`, `pfblockerng: fix IPv6 subnet match`.
No period at end of subject line. Body optional for non-obvious changes.
