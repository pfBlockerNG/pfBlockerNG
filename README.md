# pfBlockerNG

IP and DNS blocking for pfSense, maintained at
[andrebrait/pfBlockerNG](https://github.com/andrebrait/pfBlockerNG).

Original author: [BBcan177](https://github.com/BBcan177).

## Branches

| Branch | Channel | pfSense port |
|--------|---------|-------------|
| `main` | Stable | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

New features land in `devel` first. Once stable, `devel` is merged into
`main` to cut a new production release.

---

## Development workflow

### Prerequisites

- A running pfSense instance accessible via SSH
- FreeBSD ports tree cloned at (e.g.) `~/git/FreeBSD-ports`
  ([pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports))
- Python 3.11+ for running tests locally

### IDE setup (VS Code)

Open the repository in VS Code and install the recommended extensions when
prompted (or run **Extensions: Show Recommended Extensions** from the command
palette).  The workspace ships with a full configuration in `.vscode/`:

| Extension | Purpose |
| --------- | ------- |
| [Intelephense](https://marketplace.visualstudio.com/items?itemName=bmewburn.vscode-intelephense-client) | PHP language server — `.inc` files are auto-associated as PHP |
| [Python + Pylance](https://marketplace.visualstudio.com/items?itemName=ms-python.python) | Python language support and type analysis |
| [ShellCheck](https://marketplace.visualstudio.com/items?itemName=timonwong.shellcheck) | POSIX sh linter — dialect is detected from the `#!/bin/sh` shebang |
| [markdownlint](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint) | Markdown linter — reads `.markdownlint.jsonc` / `.markdownlint-cli2.jsonc` |
| [EditorConfig](https://marketplace.visualstudio.com/items?itemName=editorconfig.editorconfig) | Enforces `.editorconfig` rules (tabs for PHP/shell, spaces for Python) |

#### PHP stubs

`stubs/pfsense/` contains PHP function and global-variable declarations for the
pfSense API.  Intelephense discovers these automatically and uses them for
autocomplete and type-checking instead of reporting every pfSense call as
"undefined".

To regenerate the stubs after a pfSense CE version bump, run:

```sh
python scripts/update-pfsense-stubs.py --version X.Y.Z
```

The default version is the minimum pfSense CE release supported by this package
(`MIN_PFSENSE_VERSION` at the top of the script).  The script fetches the
relevant pfSense source files from GitHub and rewrites all stub files except
`stubs/pfsense/globals.php`, which is manually maintained.

### Git hooks

The repository ships hooks in `.githooks/` — a tracked directory, so they are
shared and reviewed (the default `.git/hooks` is local-only and cannot be
committed):

- **`pre-commit`** runs the fast linters and the unit suite (Ruff, pytest,
  markdownlint, ShellCheck + `sh -n`, `php -l`; PHPStan only when `vendor/` is
  present) and blocks the commit on any failure. A check whose tool is not
  installed is skipped (CI is the hard gate); bypass with `git commit --no-verify`.
- **`pre-push`** enforces the tag naming convention before anything is pushed:

| Commit reachable from | Required tag form  |
| --------------------- | ------------------ |
| `origin/main`         | `vX.X.X`           |
| `origin/devel` only   | `vX.X.X-devel`     |
| Neither               | push is rejected   |

Activate the hooks once after cloning (git cannot auto-apply a committed hooks
path):

```sh
sh scripts/setup-hooks.sh    # sets core.hooksPath to .githooks
```

These are local client-side guards. CI enforces the same checks (and the tag
rules) server-side, so anything that bypasses a hook is still caught by GitHub
Actions.

### Running the test suite locally

```sh
python3 -m pytest
```

Test paths and options are configured in `pyproject.toml`; no `cd` is required.

### DNSBL list build (Python)

DNSBL blocklist preprocessing lives in the Python plugin
(`src/usr/local/pkg/pfblockerng/pfb_unbound.py`), not in shell/PHP. PHP/shell only
**download** each feed, run the **DNSBL-IP firewall pass** (embedded IPs →
`DNSBLIP_v4` pf alias, stripped from Python's input), and write a per-feed
**manifest** that the plugin reads at `init`:

- `/var/unbound/pfb_py_sources.json` — the manifest: a `config` block (TLD master
  path, TLD blacklist/exclusion, user whitelist, TOP1M list + enabled flag) plus
  one `feeds` row per raw file (`{raw, feed, group, format_hint, log_flag}`).
- `/var/unbound/pfb_py_raw/<feed>.raw` — per-feed IP-stripped bare-domain raw.

`pfb_unbound.dnsbl_build_from_manifest()` then does **parse → normalise → classify
(data/zone via the public-suffix master) → build** `dataDB`/`zoneDB` +
feed/group index + query-time `whiteDB`, and emits the loaded-entry total to
`/var/unbound/pfb_py_count`. The build performs **no** dedup, subdomain collapse,
or build-time whitelist/TOP1M removal (dict keys dedup for free; whitelist + TOP1M
apply at query time via `whiteDB`). It is a pure, reentrant `(manifest, config) →
BuildResult` function — no Unbound symbols, fully unit-testable. See
[ADR-06](.ADRs/ADR_06_DNSBL_Preprocessing_To_Python/ADR.md) for the full contract.

The decision-equivalence of this move (block/resolve/whitelist/HSTS/noAAAA across
hosts/plain/basic-ABP/csv:pon, plus feed/group attribution and the emitted count)
is pinned by the golden + build unit tests in the default `pytest` run:

```sh
python -m pytest tests/test_adr06_golden_oracle.py \
                 tests/test_adr06_build_module.py \
                 tests/test_adr06_init_from_raw.py \
                 tests/test_adr06_php_boundary.py
```

### Benchmarks

`benchmarks/` holds an opt-in suite comparing the domain-trie matcher against the
flat-dict matcher it replaced (latency on positive/negative queries, and memory
footprint). It is dev-only, not shipped, and not collected by the default
`pytest` run. See [`benchmarks/README.md`](benchmarks/README.md):

```sh
python -m pip install -r benchmarks/requirements.txt
python -m pytest benchmarks/test_bench_matching.py --benchmark-columns=min,mean,ops
python -m pytest benchmarks/test_memory.py -s
```

It also holds the ADR-06 init-time / peak-RAM spike for the Python DNSBL build —
the kill-gate that gated moving preprocessing into the plugin (build wall-time and
retained dict footprint on a large, un-pruned ≥1M-entry corpus):

```sh
python -m pip install pympler    # dev-only retained-footprint tool (ADR-05 §3a)
SPIKE_N=5 SPIKE_SIZES=1000000 python benchmarks/spike_adr06_build.py
```

### Linting

#### Python

[Ruff](https://docs.astral.sh/ruff/) is configured in `pyproject.toml`, enforced
in CI (`ruff check .` + `ruff format --check .`), and can be run locally:

```sh
pip install ruff
ruff check .        # lint
ruff check . --fix  # lint and auto-fix
ruff format .       # format
```

#### PHP

[PHPStan](https://phpstan.org/) runs at level 0 and is configured in
`phpstan.neon`.  Pre-existing legacy errors are suppressed via
`phpstan-baseline.neon`; only errors introduced by new changes will fail.

Install dependencies once (requires [Composer](https://getcomposer.org/)):

```sh
composer install
```

Then run the analysis:

```sh
vendor/bin/phpstan analyse
```

#### Shell

[ShellCheck](https://www.shellcheck.net/) is available as a VS Code extension
(see IDE setup above) and is also enforced in CI at `--severity=warning`.
Configuration is in `.shellcheckrc`.

#### Markdown

[markdownlint](https://github.com/DavidAnson/markdownlint) runs as a VS Code
extension (see IDE setup above) and on the command line, and is enforced in CI:

```sh
npx markdownlint-cli2          # lint
npx markdownlint-cli2 --fix    # lint and auto-fix
```

The rule set is in `.markdownlint.jsonc` and the runner globs/ignores are in
`.markdownlint-cli2.jsonc`. The ruleset is pragmatic: it disables rules that
fight the documentation style (`MD013` line length, `MD060` table alignment,
`MD036` inline sub-headers, `MD041` first-line heading) and ignores the verbatim
`TRANSCRIPT.md`.

### Building via the FreeBSD ports system

On a FreeBSD machine with the ports tree available:

```sh
# Stable
cd /usr/ports/net/pfSense-pkg-pfBlockerNG
make package

# Devel
cd /usr/ports/net/pfSense-pkg-pfBlockerNG-devel
make package
```

The resulting `.pkg` file is in `work/pkg/`.

---

## Installing on a pfSense instance for testing

Use the helper script to push files directly to a running pfSense box
over SSH. The script copies changed source files to the correct system
paths and restarts the relevant services.

```sh
./scripts/deploy.sh <pfsense-host> [--channel devel|stable]
```

Example:

```sh
./scripts/deploy.sh root@192.168.1.1
./scripts/deploy.sh root@192.168.1.1 --channel stable
```

The script defaults to the **devel** channel (files from this branch).
Pass `--channel stable` when deploying from the `main` branch.

See [`scripts/deploy.sh`](scripts/deploy.sh) for full options.

---

## Updating pfSense's ports repository

When a new version is ready to ship, tag the commit and push the tag:

```sh
# From devel (pre-release)
git tag v3.2.17-devel
git push origin v3.2.17-devel

# From main (production release)
git tag v3.2.16
git push origin v3.2.16

```

The release workflow will:

1. Run the test suite.
2. Publish a GitHub Release with a changelog.
3. Open a PR on [pfsense/FreeBSD-ports](https://github.com/pfsense/FreeBSD-ports)
   updating `GH_TAGNAME` in the corresponding port Makefile.

To update the ports tree manually instead:

```sh
# In your FreeBSD-ports clone, edit the appropriate Makefile:
# net/pfSense-pkg-pfBlockerNG/Makefile        (stable)
# net/pfSense-pkg-pfBlockerNG-devel/Makefile  (devel)

# Update GH_TAGNAME to the new tag, then bump PORTREVISION if the
# PORTVERSION is unchanged, or update PORTVERSION to match the new tag.
```
