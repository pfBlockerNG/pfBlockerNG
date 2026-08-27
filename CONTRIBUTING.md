# Contributing to pfBlockerNG

This guide covers developing, testing, building, and releasing the package. For
installation and a feature overview, see the [README](README.md); the per-feature
design records (one Architecture Decision Record per subsystem) live under
[`legacy/ADRs/`](legacy/ADRs/).

## Principles & standards (read first)

Before changing code, read **[`CLAUDE.md`](CLAUDE.md)** — the operating contract for this
repo. This guide is the *how-to* (setup, subsystems, build, test, release); `CLAUDE.md` is the
*rules*, and wins where they overlap. Key sections to internalise:

- **Working principles — don't guess.** Investigate the source of truth and the live state
  (never infer from one generated artifact); resolve pfSense-provided functions from the real
  upstream source rather than guessing a workaround; confirm a genuinely ambiguous or
  architecturally significant choice before building.
- **Code standards.** Naming follows the surrounding pattern; per-language rules (PHP tabs /
  8.3; Python 4-space / 3.11+ / stdlib-only in `pfb_unbound.py`; POSIX `sh` with inline
  `LC_ALL=C` on collation sinks).
- **Test coverage (mandatory).** Cover every branch, assert before-and-after, no coverage
  theater — the suites and how to run them are below.

## Development workflow

### Prerequisites

- A running pfSense instance accessible via SSH
- Our FreeBSD-ports fork cloned at (e.g.) `~/git/FreeBSD-ports` —
  [pfBlockerNG/FreeBSD-ports](https://github.com/pfBlockerNG/FreeBSD-ports), branch
  `pfblockerng/use-github` (the build-input branch carrying our port; ADR-17 self-hosted
  distribution — we do **not** use the upstream `pfsense/FreeBSD-ports`)
- The developer toolchain below (Python via `uv`, PHP, and the pinned shell/workflow linters)

### Toolchain setup

CI runs every gate directly on the runner with pinned tool versions, and a local run is
graded by whatever is on your `PATH` — so install the same versions. What the workflows
pin today:

| Tool | Version | Used by |
| --- | --- | --- |
| Python | 3.11 (`.python-version`); packages from `uv.lock` | pytest, mypy, Ruff, the policy checkers |
| PHP | 8.3 **and** 8.5 (from the supported-version matrix) | `php -l`, PHPStan, PHPCS, PHPUnit |
| ShellCheck | v0.11.0 | shell lint |
| shellspec | 0.28.1 | the shell suite (run under `dash`) |
| actionlint | 1.7.12 | workflow lint |
| Node | current LTS | markdownlint, the widget and webassets JS tests |

macOS (Homebrew):

```sh
brew install uv jq dash-shell shellcheck shellspec actionlint composer node
brew install php@8.3 php@8.5    # php@8.5 is Homebrew's alias for the current `php`
brew install kcov               # optional: informational shellspec coverage
```

`php@8.3` is keg-only, so it stays off `PATH`: invoke it as
`"$(brew --prefix php@8.3)/bin/php"`, or `brew link --overwrite --force php@8.3` to make it
the default `php`.

Debian/Ubuntu:

```sh
sudo apt-get install -y jq dash shellcheck composer unzip iprange \
  php8.3-cli php8.3-curl php8.3-intl php8.3-mbstring php8.3-xml
```

`uv`, `shellspec`, `actionlint` and `kcov` are not in the Ubuntu 24.04 archive: install
`uv` per [the Astral install docs](https://docs.astral.sh/uv/getting-started/installation/),
and shellspec/actionlint from the same pinned, checksum-verified release assets the
workflows use (see [`.github/workflows/test.yml`](.github/workflows/test.yml)). PHP 8.5 is
not in that archive either — covering the second matrix leg locally needs a third-party PHP
repository or a source build, and CI covers it in any case.

Then create the Python environment once. `uv` puts it in a project-local `.venv`, resolved
from the committed lock file:

```sh
uv sync --locked --group dev
```

`--locked` fails rather than silently re-resolving when `uv.lock` is stale — that is what
stops a transitive package from moving a gate with no diff. The groups are declared in
`pyproject.toml` under `[dependency-groups]`: `dev` (lint, typing, unit suites), `smoke`
(the ADR-04 live-VM harness) and `bench` (the benchmark suite). Run a tool from that
environment with `uv run <cmd>`; no manual activation needed.

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

`stubs/pfsense/` holds PHP function + global-variable declarations for the pfSense API;
Intelephense discovers them automatically for autocomplete and type-checking instead of
flagging every pfSense call "undefined".

Regenerate after a pfSense CE bump:

```sh
python scripts/update-pfsense-stubs.py --version X.Y.Z
```

Default version is the minimum CE this package supports (`MIN_PFSENSE_VERSION` at the script
top). It fetches the pfSense source from GitHub and rewrites all stub files except the
hand-maintained `stubs/pfsense/globals.php`.

A CE version bump also requires updating the **supported-version matrix** and
refreshing the CI smoke image. See
[Rebuilding the image on a CE bump](#rebuilding-the-image-on-a-ce-bump) below for
the full three-step procedure (matrix edit → image refresh → smoke fan-out).

### Git hooks

The repository ships hooks in `.githooks/` — a tracked directory, so they are
shared and reviewed (the default `.git/hooks` is local-only and cannot be
committed):

- **`pre-commit`** runs the fast linters and the unit suites (Ruff, pytest,
  markdownlint, ShellCheck + `sh -n`, shellspec, `php -l`; PHPStan and PHPUnit
  only when `vendor/` is present) and blocks the commit on any failure. A check
  whose tool is not installed is skipped (CI is the hard gate); bypass with
  `git commit --no-verify`.
- **`pre-push`** enforces the release tag scheme before anything is pushed (single source:
  [`scripts/release-version.sh`](scripts/release-version.sh)):

| Release channel | Required tag form |
| --- | --- |
| Stable | `vX.Y.Z` |
| Testing | `vX.Y.Z.aN` / `.bN` / `.rN`, where `Z != 0` |
| Edge | `vX.Y.0.aN` / `.bN` / `.rN` |
| Malformed or mismatched trailer | push is rejected |

Activate the hooks once after cloning (git cannot auto-apply a committed hooks
path):

```sh
sh scripts/setup-hooks.sh    # sets core.hooksPath to .githooks
```

These are local client-side guards. CI enforces the same checks (and the tag
rules) server-side, so anything that bypasses a hook is still caught by GitHub
Actions.

### Shell setup (macOS, optional)

On macOS, Homebrew's `bin` is on `PATH` only for **login** shells (`brew shellenv` lives in
`~/.zprofile`), so the pre-commit hook's tools (`node`/`npx`, `php`, `shellcheck`) can go
missing in the non-login shells editors and agents spawn. The hook self-bootstraps Homebrew's
`PATH` anyway; to make the same tools resolve in your own interactive shells — and upgrade
Apple's ancient `/bin/bash` 3.2 to Homebrew's — run once:

```sh
sh scripts/setup-dev-shell.sh
```

It writes a small idempotent managed block into `~/.brew_path.sh`, `~/.zshenv`, `~/.bashrc`,
`~/.bash_profile`, `~/.profile`. macOS-only (no-ops elsewhere); with no Homebrew it prints an
install hint and **changes no dotfiles**. It never changes your login shell or `/etc/shells` —
it only prints the optional `sudo` commands for those.

### Running the test suite locally

Python (the bulk of the suite), from the locked environment created above:

```sh
uv run pytest
```

Test paths and options are configured in `pyproject.toml`; no `cd` is required.

Optional **branch**-coverage report for the Unbound matcher (issue #38 — line
coverage hides one-sided decision branches; this surfaces them):

```sh
uv run pytest --cov=pfb_unbound --cov-branch --cov-report=term-missing
```

`pytest-cov` is already in the `dev` group. The report is informational only — CI runs
the same one (non-blocking), with no enforced floor.

Type checking for the test suite (the `tests.*` mypy override requires full
annotations):

```sh
uv run mypy tests/
```

PHP unit tests (PHPUnit) cover the pure/extractable PHP helpers
(input filtering, IDN/textarea decode, ABP-IP extraction, IPv4 normalisation,
the Python manifest writer). Install the dev dependencies once, then run:

```sh
composer install      # pulls phpunit/phpunit into vendor/
vendor/bin/phpunit     # config in phpunit.xml; no live pfSense needed
```

The suite loads the **real** `pfblockerng.inc` off-appliance via
`tests/php/bootstrap.php` (empty shims for the pfSense `require_once` includes
plus behavioural doubles for the pfSense runtime functions) — see
[`tests/php/README.md`](tests/php/README.md). Deep pfSense-runtime integration
stays the live-VM smoke's job (ADR-04).

CI grades on Linux with the pinned versions listed under
[Toolchain setup](#toolchain-setup); your host is only as close to that as you make it.
Where the two disagree, CI is the answer that counts — and the disagreement usually shows
up as a test that *skips*, not one that fails. Locale data, `file(1)` classification, the
PHP build (whether `php://memory` can fail `flock()`), the uid you run as and the `tar`
flavour on the box each decide whether a case runs at all. Read the skip list, not just
the exit status; a skip is not coverage.

CI gates the skip *set*, not just its count (issues #2359 and #2369): every blocking
test row writes JUnit and runs `scripts/check_skip_allowlist.py` against
`tests/skip-allowlist.txt`. The file stays shared because ids carry a unique
`<suite>:<classname>::<name>` prefix for pytest, PHPUnit, ShellSpec, each Node invocation,
Ports parity, UI, and smoke. A test that starts skipping and is not on that file fails the
build. To add a legitimately new skip, add its id as its own line with a trailing
`# <reason>` comment (a bare id with no reason is itself a build failure) — run the suite
to get the exact id from its report, never hand-guess it.

`scripts/agent/run-gates.sh` adds the same report/check when its touched-path mapping
already selects pytest, PHPUnit, or ShellSpec; it does not add new local suites. The
`pre-commit` hook runs the fast subset. A missing tool is a **failure** for `run-gates.sh`
(`--allow-missing` downgrades it to a skip); the hook is lenient because CI is the hard gate.

### Shell tests (shellspec)

The POSIX `sh` — the `ip_pre_AWS_*.sh` region pre-scripts and the testable
functions in `pfblockerng.sh` — has a functional suite under `tests/shell/`, run
with [shellspec](https://shellspec.info/) (pure POSIX, native kcov coverage):

```sh
shellspec            # from the repo root; reads ./.shellspec
shellspec --kcov     # with coverage (informational; needs kcov)
```

Install shellspec **0.28.1** — the version CI pins and verifies by checksum, so a
clean local run and CI agree. Either take the release asset:

```sh
curl -fsSLo shellspec-dist.tar.gz \
  https://github.com/shellspec/shellspec/releases/download/0.28.1/shellspec-dist.tar.gz
tar -xzf shellspec-dist.tar.gz -C "$HOME"   # then put "$HOME/shellspec" on PATH
```

or use `brew install shellspec` (macOS) and check `shellspec --version`. The
pre-commit hook and CI run it automatically when `shellspec` is present (coverage
is informational, no floor).
See [`tests/shell/README.md`](tests/shell/README.md) for the harness contracts
(the `iprange` PATH shim, the AWS fixture, and the `PFB_SOURCED` source-for-test
pattern).

## Subsystem internals

Per-subsystem design lives in the ADRs under [`legacy/ADRs/`](legacy/ADRs/), summarised — with the
cross-subsystem detail — in
[`docs/misc/architecture-notes.md`](docs/misc/architecture-notes.md): the DNSBL/ABP build
pipeline (ADR-06/07/62), zero-downtime data swap (ADR-10), IDN homoglyph protection (ADR-08),
the sinkhole VIP (ADR-13), aggregated "Uber" aliases (ADR-11), update hooks (ADR-12),
content-addressed alias reloads (ADR-40), change detection (ADR-42), and scheduling (ADR-43).

The update-hook and aggregated-alias features are user-facing; their usage (and a linked HAProxy
hook example) is documented in the [README](README.md).

## Benchmarks

`legacy/benchmarks/` holds an opt-in suite comparing the domain-trie matcher against the
flat-dict matcher it replaced (latency on positive/negative queries, and memory
footprint). It is dev-only, not shipped, and not collected by the default
`pytest` run. See [`legacy/benchmarks/README.md`](legacy/benchmarks/README.md):

```sh
uv sync --locked --group bench
uv run pytest legacy/benchmarks/test_bench_matching.py --benchmark-columns=min,mean,ops
uv run pytest legacy/benchmarks/test_memory.py -s
```

It also holds the ADR-06 init-time / peak-RAM spike for the Python DNSBL build —
the kill-gate that gated moving preprocessing into the plugin (build wall-time and
retained dict footprint on a large, un-pruned ≥1M-entry corpus):

```sh
# pympler (the dev-only retained-footprint tool, ADR-05 §3a) is in the `bench` group
SPIKE_N=5 SPIKE_SIZES=1000000 uv run python legacy/benchmarks/spike_adr06_build.py
```

…and the ADR-07 regex/ReDoS spike (`spike_adr07_regex.py`, stdlib only) — the
de-risking measurement for full ABP support: regex reduction ratio, irreducible
count, added per-query latency at feed scale, and the worst real ReDoS first-hit
on a ≤253-char input vs the kill-threshold (run with `tracemalloc` off):

```sh
uv run python legacy/benchmarks/spike_adr07_regex.py
SPIKE_COUNTS=10,100,1000 SPIKE_ROUNDS=50 uv run python legacy/benchmarks/spike_adr07_regex.py
```

## Linting

### Python

[Ruff](https://docs.astral.sh/ruff/) is configured in `pyproject.toml`, enforced
in CI (`ruff check .` + `ruff format --check .`), and can be run locally:

```sh
uv run ruff check .        # lint
uv run ruff check . --fix  # lint and auto-fix
uv run ruff format .       # format
```

Ruff is pinned in the `dev` group, so `uv sync --locked --group dev` is the only install
step.

### PHP

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

The same `composer install` provides [PHPUnit](https://phpunit.de/) for the PHP
unit suite (`vendor/bin/phpunit`, config in `phpunit.xml`) — the fast functional
layer beneath the live-VM smoke. See
[Running the test suite locally](#running-the-test-suite-locally) and
[`tests/php/README.md`](tests/php/README.md).

### Shell

[ShellCheck](https://www.shellcheck.net/) is available as a VS Code extension
(see IDE setup above) and is also enforced in CI at `--severity=info`.
Configuration is in `.shellcheckrc`. CI pins **v0.11.0**; install that same
release locally (Homebrew and most distributions carry it, but check what your
package manager actually gives you — `shellcheck --version`). Older ShellCheck
reports findings 0.11.0 does not, so a version gap reds CI after a clean local
run. Functional shell tests (shellspec) live in
`tests/shell/` — see [Shell tests (shellspec)](#shell-tests-shellspec) above.

### Markdown

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

## Building and deploying

### Building via the FreeBSD ports system

On a FreeBSD machine with the ports tree available:

```sh
# Stable
cd /usr/ports/net/pfSense-pkg-pfBlockerNG
make package

# Pre-release channel (edge is the line the devel branch builds;
# testing and nightly have their own recipes)
cd /usr/ports/net/pfSense-pkg-pfBlockerNG-edge
make package
```

The resulting `.pkg` file is in `work/pkg/`.

### Deploying to a pfSense box for testing

Push files directly to a running pfSense box over SSH — the script copies changed source
files to their system paths and restarts the relevant services:

```sh
./scripts/deploy.sh <pfsense-host> [--channel devel|stable]
```

Example:

```sh
./scripts/deploy.sh root@192.168.1.1
./scripts/deploy.sh root@192.168.1.1 --channel stable
```

Defaults to the **devel** channel (this branch's files); pass `--channel stable` from `main`.
Full options: [`scripts/deploy.sh`](scripts/deploy.sh).

### How the `pkg` repository is published (GitHub Pages)

The self-hosted repository (installed per the [README](README.md#installation))
is published from the separate [`pfBlockerNG/pkg`](https://github.com/pfBlockerNG/pkg)
repository. This repository produces immutable tagged Release assets or a
digest-pinned Nightly OCI handoff, then dispatches the repository-local
ingestion workflow in `pkg`. The `pkg` workflow verifies the immutable input,
owns catalogue and site generation, and commits its own GitHub Pages tree.
pfBlockerNG never checks out or writes `pkg`; it retains only source-side
builders, provenance creation, installer, and boot-hook code.

Live publication remains opt-in until the owner completes the GHCR access and
canary checkpoint: `PKG_PUBLICATION_ENABLED` must be set to `true` as a
repository Actions variable. Leaving it unset keeps scheduled Nightly OCI
publication and tagged/manual `pkg` dispatch disabled.

Recipe and rendered-site bytes are tested in `pfBlockerNG/pkg`; this repository
tests only its source-side installer and published channel URL contract. CI does
not clone one repository from the other for a cross-repository byte comparison,
because that would reintroduce a floating ownership dependency. A coordinated
client/recipe change lands in `pkg` first, then updates this source contract.

See [ADR-17](legacy/ADRs/ADR_17_Pkg_Repository/ADR.md) and the
[distribution architecture notes](docs/misc/architecture-notes.md)
for the package identity, signing, channel, and live-gate contracts.

## Smoke tests (live pfSense VM)

The smoke suite (ADR-04, `tests/smoke/`) boots a **real pfSense CE VM** under
QEMU/KVM, installs the branch's freshly-built `.pkg`, and asserts pfBlockerNG's
real behaviour end-to-end — the DNS path (Unbound + `pfb_unbound.py`, probed
with `dig`/`dnspython`) and the IP path (`pfctl` alias tables + rules, over
SSH). It is **dev-only**, marked `@pytest.mark.smoke`, and **deselected from the
default `uv run pytest`** (`pyproject.toml` `addopts: --ignore=tests/smoke`),
so the normal unit run is unaffected.

### Running it in CI

The **default full run is the fan-out**: `.github/workflows/smoke.yml`
runs the ADR-04 suite across **every `ci:true` image — CE *and* Plus** (ADR-24) —
in parallel (`fail-fast: false`), gated by the `all-smoke-passed` AND-check. It
takes **no inputs** (it reads the CI matrix from the `ci-metadata` branch), is the
validation an ADR is accepted against, and is what `version-tracker` dispatches on
a version bump (plus a nightly `schedule`). This is the canonical "run the smoke
suite" command:

```sh
gh workflow run smoke.yml                  # all ci:true legs (CE + Plus) — the default
```

Both it and the single-leg callee are **gated** — `workflow_dispatch` +
`workflow_call` (the fan-out also runs nightly) — **not** every-PR yet, because the
per-run wall-time has not been measured against §7's ~20 min/job budget.

For a **narrow, single-leg run** — one image, or a non-default `pytest_marker` the
fan-out can't select (e.g. the ADR-17 `repo` flow) — drive the reusable callee
`.github/workflows/smoke-single.yml` directly (it is also what the fan-out invokes per leg):

```sh
gh workflow run smoke-single.yml                          # single CE leg (composes the ref from the SMOKE_IMAGE_* vars)
gh workflow run smoke-single.yml -f image_ref=ghcr.io/<org>/pfsense-ce@sha256:<digest>
gh workflow run smoke-single.yml -f pytest_marker=repo    # ADR-17 repo-install flow (single leg)
```

The ADR-17 repository-install flow has its **own** fan-out too —
`.github/workflows/repo-install.yml` runs the `repo` marker across **every `ci:true`
leg (CE + Plus)** on a nightly `schedule` + `workflow_dispatch`, so the self-hosted
`pkg` repo is proven to install on Plus as well as CE.

The workflow builds the `.pkg` (`build-pkg-linux.yml`, portable Linux builder), pulls the pfSense
image from private GHCR, then runs `pytest -m smoke`. The test fixture **blocks
the runner's egress after `deploy()`** so the run is hermetic — feeds come from
an in-runner mock server reached over the SLIRP host alias `10.0.2.2`. Required
Actions
config (see `legacy/ADRs/ADR_04_VM_Smoke_Tests/RESULTS/02_Results.txt`):
`SMOKE_IMAGE_REF`, `SMOKE_GHCR_USER`, `SMOKE_GHCR_TOKEN`, `SMOKE_SSH_PRIV_KEY`
(and, to match the baked image, `SMOKE_DNSBL_VIP4` / `SMOKE_CONTROL_NAME` /
`SMOKE_CONTROL_IP`).

### Running it locally

Needs `/dev/kvm`, `qemu-system-x86_64` + `qemu-img`, `oras`, `ssh`, and a built
`.pkg`. Then:

```sh
uv sync --locked --group smoke
export SMOKE_IMAGE_REF=ghcr.io/<org>/pfsense-ce@sha256:<digest>   # private GHCR
export SMOKE_SSH_KEY=/path/to/guest_priv_key                      # mode 600
export SMOKE_PKG=/path/to/pfBlockerNG-*.pkg                       # from build-pkg
oras login ghcr.io                                                # for the pull
uv run pytest tests/smoke -m smoke --override-ini="addopts="
```

The fixture pulls the image by `SMOKE_IMAGE_REF` and boots an ephemeral overlay
(the base qcow2 is never mutated). Missing KVM/secrets/deps → the suite **skips**
cleanly, never errors. (CI sets `SMOKE_IMAGE_DIR` instead, pointing at the
pre-pulled image, so the fixture blocks egress after `deploy()` without
needing another network pull.)

### Rebuilding the image on a CE bump

When a new pfSense CE release lands (or you raise the minimum supported CE version),
follow this three-step procedure. The daily **version-tracker** (`version-tracker.yml`)
performs steps 2–3 automatically once the matrix is updated; you can also dispatch
each workflow manually.

**Step 1 — Update the supported-version matrix.**
Edit `supported-versions.json` on the `ci-metadata` orphan branch via a PR against
`ci-metadata`. Add a new entry (or update `status: "beta"` → `"GA"`; or drop the
oldest CE entry when the newest goes GA). Schema and lifecycle policy:
[`scripts/README.md`](scripts/README.md#supported-version-matrix).

**Step 2 — Refresh the CI smoke image.**
Dispatch `.github/workflows/image-refresh.yml` with `pfsense_version` and
`freebsd_version` from the new matrix entry. The workflow:

1. Pulls the current GHCR tag for this CE version.
2. Boots a copy and runs `pfSense-upgrade` (works for patch, minor, and major jumps).
3. Applies the **six-check sanity gate** (VM boots; SSH answers; `/etc/version` matches;
   `pfctl -sr` loads; `install-from-repo.sh` + `pfblockerng.php update` exit 0;
   `dig` control record resolves).
4. Publishes the new GHCR tag **only on gate pass** — fail-closed (a bad image is
   never published). Old tags are kept.

If the gate fails, use `scripts/image-publish.sh` to produce a fresh seed from a
clean manual install (manual fallback — see
[`legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`](legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md)).
The automated image refresh (`image-refresh.yml`) is **CE-only**; the **Plus** image is
refreshed **manually** with `scripts/image-publish.sh` (re-export + push the licensed,
private qcow2 — the MAC/SMBIOS uuid must stay constant, ADR-24). The seed and every version
snapshot are retained as immutable GHCR tags; the GHCR package is **private**.

**Step 3 — Run the smoke fan-out.**
Dispatch `.github/workflows/smoke.yml` (no inputs — it reads the CI matrix
itself). The fan-out runs the ADR-04 smoke suite across **all** `ci: true` images —
**CE and Plus** (ADR-24) — in parallel (`fail-fast: false`). The `all-smoke-passed`
AND-gate fails if any single leg fails — one red leg makes the whole gate red, no partial pass.

### Adding a matrix case

Cases live in `tests/smoke/test_smoke_matrix.py` and compose the Phase-4 helpers
(`tests/smoke/helpers.py`). The recipe (full version in
`RESULTS/05_Results.txt`):

1. Register the feed body in memory (hermetic, no fixture file):
   `feed_url = mock_feeds.register("smoke_<name>.txt", "<body lines>\n")`.
2. Build a spec — `h.DnsblCase(...)` (DNS path) or `h.IpCase(...)` (IP path) —
   choosing the response mode from the map: **NXDOMAIN** = `dnsbl_python` (exact
   match only, no subdomain block), **NULL** = `dnsbl_unbound` +
   `logging='disabled'`, **VIP** = `dnsbl_unbound` + `logging='enabled'`.
3. Drive it through `with h.CaseContext(deployed_vm, spec):` (it picks the
   reload verb; pass `scope="update"` for DNSBL-IP), then assert with
   `h.dns_probe` / `h.is_nxdomain` / `h.is_null_ip` / `h.is_vip` /
   `h.resolves_to`, and `h.pfctl_table_members` / `h.member_present` /
   `h.pfctl_rule_has_alias` for the IP side. `__exit__` resets to baseline.

### HTTP feed-load smoke (ADR-16)

`tests/smoke/test_smoke_feeds.py` (marker `smoke`) exercises the **real
HTTP fetch path** — pfBlockerNG's `curl` over SLIRP to the `_MockFeedServer`
— across the representative IP + DNSBL formats. This is the only place in the
suite where a feed arrives over HTTP rather than a local file (`write_local_feed`).

**Fixture files** live under `tests/smoke/fixtures/` and are committed to the
repo. Each file is the verbatim body `curl` fetches; the guest reaches it at
`http://10.0.2.2:<port>/<filename>` over SLIRP (survives the egress block):

| File | Format | Type |
|------|--------|------|
| `ip_plain_cidr.txt` | plain IPv4 + CIDR | IP v4 |
| `ip_range.txt` | IPv4 range `a-b` | IP v4 |
| `ip_ipv6.txt` | IPv6 single + CIDR | IP v6 |
| `dnsbl_plain.txt` | plain domain | DNSBL |
| `dnsbl_hosts.txt` | hosts `0.0.0.0 domain` | DNSBL |
| `dnsbl_abp.txt` | ABP / EasyList (\|\|d^ block, @@ allow) | DNSBL |

All data is inert: IP files use RFC 5737 / RFC 3849 documentation ranges;
DNSBL files use `uuid-<hex>.com` names.

**How cases register a fixture.** In a test, pass `mock_feeds.feed_url("<name>")`
as the `feed_url` to `IpCase`/`DnsblCase`. `_MockFeedServer.register()` is
called automatically for each file in `tests/smoke/fixtures/` when the
`mock_feeds` fixture starts. To add a new format:

1. Drop a fixture file into `tests/smoke/fixtures/` (follow the inert-data rule).
2. Update `tests/smoke/fixtures/README.md` to document its member/non-member set.
3. Add a case in `test_smoke_feeds.py` using `mock_feeds.feed_url("<name>")`.

**Kill-gate / gate status.** The HTTP-fetch reliability is the ADR-16 Part-C
kill-gate (≥ 4/5 clean runs). The test is authored in the `smoke` marker and
gated as part of the `ui-tests`-labeled PR suite; the GO/DEMOTE decision is
recorded in `legacy/ADRs/ADR_16_Feeds_Tabs_And_Feed_Smoke/RESULTS/05_Results.txt`
(status: OPTIMISTIC-GO, pending the live CI run). If the live run shows
&lt; 4/5 clean, `test_smoke_feeds.py` is demoted to dispatch-only as a fast-follow.

## Web UI tests (live pfSense VM)

The UI suite (ADR-14, `tests/smoke/ui/`) drives the **webConfigurator** on the
same ADR-04 smoke VM — reusing the `smoke_vm` fixture and `helpers.py` — to catch
WebUI regressions that `php -l`/PHPStan structurally cannot (pages that 500,
render a PHP `Warning`/`Notice`, or break form persistence). It is **dev-only**,
deselected from the default `uv run pytest` exactly like the smoke suite
(`--ignore=tests/smoke`), so the normal unit run is unaffected. Three tiers, by
cost/frequency:

| Tier | Marker | What it does | When |
|------|--------|--------------|------|
| **A — render-smoke** | `ui_render` | Authenticated-HTTP GET of every pfBlockerNG page (the 14 main paths + the dashboard widget + the two DNSBL-VIP sinkhole pages) → 200, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a page-specific marker present, **and** no new `php_error.log` line during the sweep. Cheap/hermetic. | **Per-PR** when PHP/JS files change (blocking); release |
| **B — functional** | `ui_e2e` | CSRF-POST flows (save General; add/save an IP feed/alias; toggle a DNSBL setting) → assert the **effective** `config.xml`/`pfctl`/unbound state via `helpers.config_get`, never the HTTP response alone. | Daily/on-demand; release |
| **B — browser** | `ui_browser` | Headless Playwright/Chromium reusing the auth session (injected `PHPSESSID` cookie — no second login) to exercise the JS-only UX (`enable_change_*`, `pfb_autocomplete*`, `pfb_chg_state_bkgd`, the dashboard widget) and capture **per-page screenshots** as artifacts. | Daily/on-demand; release |

The pass/fail oracle is **never HTTP 200 alone** (a 200 can carry a rendered PHP
warning or a blank body) — Tier A reads the body + the page marker + the on-box
`php_error.log`; Tier B asserts the effective state.

### Feeds page — IPv4 / IPv6 / DNSBL sub-tabs (ADR-16)

The **Feeds** page (`pfblockerng_feeds.php`) is organized into **IPv4 / IPv6 /
DNSBL sub-tabs** (`?type=ipv4|ipv6|dnsbl`, default `ipv4`), matching the IP /
DNSBL / Reports top-level structure. Each sub-tab renders only its own type's
Feed Settings alias-name inputs and predefined-feeds table; a bare URL defaults
to the IPv4 tab. The Tier-A render entries are `feeds_ipv4`, `feeds_ipv6`, and
`feeds_dnsbl` (three `ui_render` cases, one per `?type`). A `ui_browser` test
(`tests/smoke/ui/test_browser_feeds.py`, marker `ui_browser`) screenshots all
three tabs and asserts the second sub-tab row (`[IPv4 | IPv6 | DNSBL]`), the
active-tab highlight, and that each tab lists only its type.

### Running it in CI

`.github/workflows/ui-tests.yml` is a **reusable** workflow
(`workflow_call` + `workflow_dispatch` + a daily `schedule`), matrix-parametric
on **image-ref/version** and tier-selectable, building the branch `.pkg` via
`build-pkg-linux.yml` and booting the GHCR image. **One GH job per
(tier × version)** with `fail-fast: false`, so GitHub's "Re-run failed jobs"
re-runs only the flaky leg (no auto-retry on assertions; bounded readiness retry
only on boot/login). Diagnostics (screenshots + VM/boot logs + the smoke state
snapshot) upload `if: always()` as `ui-diagnostics-<tier>-<variant>-<version>`
(variant = ce/plus, e.g. `ui-diagnostics-browser-ce-2.8`). Wiring:

- **Tier A** runs per-PR (`test.yml`) on PRs touching `src/**/*.php`, `**/*.inc`,
  `src/**/*.js`, folded into the **"All tests passed"** aggregate (blocking).
- **Tier B** (functional + browser) runs on the daily `schedule` (skipped when no
  commit landed in 24 h) and on `workflow_dispatch` — **never** gating a PR.
- **Release** (`release.yml`) `needs:` the full suite (`tier: all`) via the
  `ui-suite` job before `release`/`sync-ports-fork` — each leg re-runnable in isolation
  (a flaky browser leg costs one re-run, not a republish).

Dispatch a run with:

```sh
gh workflow run ui-tests.yml -f tier=render        # one tier
gh workflow run ui-tests.yml -f tier=all           # render + functional + browser
gh workflow run ui-tests.yml -f image_ref=ghcr.io/<org>/pfsense-ce@sha256:<digest>
```

### Running it locally

Same prerequisites as the smoke suite (`/dev/kvm`, `qemu`, `oras`, `ssh`, a built
`.pkg`) plus the UI deps. The browser tier also needs the Chromium binary
(a separate download from the `playwright` wheel) and skips cleanly without it:

```sh
uv sync --locked --group smoke
uv run playwright install chromium                    # browser tier only
export SMOKE_IMAGE_REF=ghcr.io/<org>/pfsense-ce@sha256:<digest>
export SMOKE_SSH_KEY=/path/to/guest_priv_key          # mode 600
export SMOKE_PKG=/path/to/pfBlockerNG-*.pkg           # from build-pkg
export SMOKE_ADMIN_PASSWORD=<baked admin password>    # REQUIRED — else the UI fixtures FAIL
uv run pytest tests/smoke/ui -m ui_render   --override-ini="addopts="   # Tier A
uv run pytest tests/smoke/ui -m ui_e2e      --override-ini="addopts="   # Tier B functional
uv run pytest tests/smoke/ui -m ui_browser  --override-ini="addopts="   # Tier B browser
```

Without `SMOKE_ADMIN_PASSWORD` the UI fixtures **fail** (never skip) — the tests cannot
run without the baked credential, and a skipped tier would report a false pass. Screenshots land under
`$SMOKE_UI_SCREENSHOT_DIR/<version>/` (default `test-results/ui-screenshots/`, a
git-ignored build output).

### Version matrix and adding an image

The `version` axis is built **parametric** but runs the **single existing CE
image** today. Adding a second pfSense image (Plus / another CE) is a one-line
change — append a label to `DEFAULT_VERSIONS` in the `prepare` job of
`ui-tests.yml` and wire its image ref — then the matrix expands to one leg per
(tier × version) with no harness change. Building/publishing that image follows
[`legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`](legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md)
(see [Rebuilding the image on a CE bump](#rebuilding-the-image-on-a-ce-bump) above).

## Image pipeline (smoke-test base)

The CI smoke harness (ADR-04) boots a real pfSense CE VM. Three dev-only scripts
build and drive its disk image — no Packer, since pfBlockerNG compiles nothing:

- [`scripts/image-publish.sh`](scripts/image-publish.sh) — on the Proxmox host,
  export a powered-off VM's ZFS disk to a compressed qcow2 and `oras push` it to
  GHCR, tagged by CE version (older tags kept).
- [`scripts/image-upgrade.sh`](scripts/image-upgrade.sh) — pull a published tag,
  boot it, run `pfSense-upgrade`, power off, and publish the result as a new
  version tag (the source tag is left untouched).
- [`scripts/install-from-repo.sh`](scripts/install-from-repo.sh) — install
  pfBlockerNG onto a clean pfSense **from this repo's `src/`** (no Netgate pkg),
  via the port's `rc.packages … POST-INSTALL` hook. pfBlockerNG is not baked into
  the image; the harness runs this after every boot (the disk is immutable).

These produce one image per supported minor CE version; CI runs the smoke matrix
across all of them. See [`scripts/README.md`](scripts/README.md) for the build/ABI
details and [`legacy/ADRs/ADR_04_VM_Smoke_Tests/`](legacy/ADRs/ADR_04_VM_Smoke_Tests/).

## Releasing

New features land in `devel`; `devel` is promoted to `main` by rebase to cut a
stable release. Releases are cut by **dispatching**
[`.github/workflows/release.yml`](.github/workflows/release.yml) — you do **not** push a tag by
hand; the workflow validates the scheme, commits the changelog, and **creates + pushes** the tag
on the changelog commit. The tag scheme (single source:
[`scripts/release-version.sh`](scripts/release-version.sh)) is enforced before anything is cut:

- **Edge prerelease** — `vX.Y.0.aN` / `.bN` / `.rN`.
- **Testing prerelease** — `vX.Y.Z.aN` / `.bN` / `.rN`, where `Z != 0`.
- **Stable** — `vX.Y.Z`.

```sh
# Dry-run (the default): validate + build, publish nothing
gh workflow run release.yml -f tag=v4.0.0.a1 -f channel=edge -f source=release/4.0

# Cut the real release
gh workflow run release.yml -f tag=v4.0.0.a1 -f channel=edge -f source=release/4.0 -f dry_run=false
```

The release workflow will:

1. Run the test suite.
2. Publish a GitHub Release with a changelog.
3. Bump `PORTVERSION` + `GH_TAGNAME` on the matching port **directly on our own fork**
   [pfBlockerNG/FreeBSD-ports](https://github.com/pfBlockerNG/FreeBSD-ports) (branch
   `pfblockerng/use-github`, the build-input branch) — the `sync-ports-fork` job pushes it,
   with **no upstream `pfsense/FreeBSD-ports` PR** (ADR-17 self-hosted distribution).
4. Publish the self-hosted `pkg` repository to GitHub Pages (see
   [How the `pkg` repository is published](#how-the-pkg-repository-is-published-github-pages)).

To update the ports tree manually instead:

```sh
# In our fork clone (pfBlockerNG/FreeBSD-ports, branch pfblockerng/use-github),
# edit the matching port Makefile:
# net/pfSense-pkg-pfBlockerNG/Makefile          (stable)
# net/pfSense-pkg-pfBlockerNG-testing/Makefile  (testing)
# net/pfSense-pkg-pfBlockerNG-edge/Makefile     (edge)
# net/pfSense-pkg-pfBlockerNG-nightly/Makefile  (nightly)

# Update GH_TAGNAME to the new tag, then bump PORTREVISION if the
# PORTVERSION is unchanged, or update PORTVERSION to match the new tag.
# Push to pfblockerng/use-github (the build-input branch) — no upstream PR.
```
