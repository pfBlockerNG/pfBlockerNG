# CLAUDE.md — pfBlockerNG

## Communication

**Always activate `/caveman` skill at session start.** Terse, no filler, full technical accuracy.

---

## Repository structure

```
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
│       │   └── ip_pre_AWS_*.sh        # Auto-generated AWS IP prefix scripts
│       ├── share/             # Package metadata (info.xml)
│       └── www/               # Web UI (PHP pages, JS, widgets, wizards)
├── tests/                 # Python test suite (pytest)
├── scripts/               # Developer tooling (deploy, stub generation)
│   ├── deploy.sh          # Push files to live pfSense over SSH
│   └── update-pfsense-stubs.py  # Regenerate stubs from pfSense source
├── stubs/pfsense/         # PHP stubs for Intelephense (IDE only, not shipped)
├── .editorconfig          # Indent rules per language
├── .shellcheckrc          # ShellCheck suppressions
├── pyproject.toml         # pytest + ruff + mypy config
└── README.md
```

Release archives contain only `src/`. Everything else (stubs, scripts, tests, CI, pyproject.toml, `.githooks/`) is dev-only.

---

## Git hooks

`.githooks/pre-push` enforces tag naming before pushes reach the remote.
Activate once after cloning: `git config core.hooksPath .githooks`

---

## Running tests

```sh
python -m pytest
```

Run from repo root. `pyproject.toml` sets `testpaths` and `-v`. No `cd` needed.

Run after **any** change to `src/usr/local/pkg/pfblockerng/pfb_unbound.py` or `tests/`.

---

## Linting

### Python

```sh
ruff check .        # lint
ruff check . --fix  # lint + autofix
ruff format .       # format
```

Config in `pyproject.toml`. Target: Python 3.11+ (pfSense CE 2.8 / FreeBSD 15).

### PHP

Intelephense in VS Code. `.inc` files are PHP — `files.associations` handles this.
Stubs in `stubs/pfsense/` resolve pfSense-provided functions. If Intelephense flags
a pfSense function as undefined, add it to the appropriate stub file rather than
expanding the `undefinedFunctions` suppression in `.vscode/settings.json`.

### Shell

ShellCheck via VS Code extension. All scripts use `#!/bin/sh` (POSIX sh, not bash).
`.shellcheckrc` suppresses SC1091 (pfSense source files unreachable locally) and
SC2154 (rc(8)-injected variables). Do not suppress other rules without justification.

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

### Shell
- POSIX sh only (`#!/bin/sh`), no bash-isms (`[[`, arrays, `$RANDOM`, etc.)
- Quote all variable expansions: `"$var"`, `"${var}"`
- Use absolute paths for all binaries (pfSense convention); do not rely on `$PATH`
- `ip_pre_AWS_*.sh` files are auto-generated — do not edit manually

---

## Updating documentation

Update `README.md` when:
- Workflow steps change (test command, deploy command, release steps)
- Minimum supported pfSense CE version changes
- New developer tooling is added

Update `stubs/pfsense/` when:
- Minimum supported pfSense CE version is bumped — run:
  ```sh
  python scripts/update-pfsense-stubs.py --version X.Y.Z
  ```
- pfBlockerNG starts calling a new pfSense API function not yet stubbed — add it
  to the appropriate file in `stubs/pfsense/` manually
- `globals.php` is **always** manually maintained (array shapes can't be auto-derived)

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
