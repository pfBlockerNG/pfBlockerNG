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

The repository ships a `pre-push` hook in `.githooks/` that enforces the tag
naming convention before anything is pushed to the remote:

| Commit reachable from | Required tag form  |
| --------------------- | ------------------ |
| `origin/main`         | `vX.X.X`           |
| `origin/devel` only   | `vX.X.X-devel`     |
| Neither               | push is rejected   |

Activate the hook once after cloning:

```sh
git config core.hooksPath .githooks
```

This is a local client-side guard. The CI release workflow enforces the same
rules server-side, so tags that bypass the hook are still rejected by GitHub
Actions.

### Running the test suite locally

```sh
python3 -m pytest
```

Test paths and options are configured in `pyproject.toml`; no `cd` is required.

### Linting

#### Python

[Ruff](https://docs.astral.sh/ruff/) is configured in `pyproject.toml` and can
be run locally:

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
