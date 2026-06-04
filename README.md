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

A CE version bump also means **rebuilding and republishing the pfSense CE smoke
image** (ADR-04): upgrade-in-place for a patch/minor bump, a fresh seed on a
major, via `.github/workflows/build-image.yml`. See
[Smoke tests](#smoke-tests-live-pfsense-vm) below and
[`.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`](.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md).

### Git hooks

The repository ships hooks in `.githooks/` — a tracked directory, so they are
shared and reviewed (the default `.git/hooks` is local-only and cannot be
committed):

- **`pre-commit`** runs the fast linters and the unit suites (Ruff, pytest,
  markdownlint, ShellCheck + `sh -n`, shellspec, `php -l`; PHPStan and PHPUnit
  only when `vendor/` is present) and blocks the commit on any failure. A check
  whose tool is not installed is skipped (CI is the hard gate); bypass with
  `git commit --no-verify`.
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

### Shell setup (macOS, optional)

On macOS, Homebrew's `bin` is on `PATH` only for **login** shells (`brew shellenv`
lives in `~/.zprofile`), so the pre-commit hook's tools (`node`/`npx` for
markdownlint, `php`, `shellcheck`) can go missing in the non-login shells that
editors and agents spawn. The hook self-bootstraps Homebrew's `PATH` regardless,
but to make the same tools resolve in your own interactive/manual shells — and to
upgrade Apple's ancient `/bin/bash` 3.2 to Homebrew's bash — run once:

```sh
sh scripts/setup-dev-shell.sh
```

It writes a small idempotent managed block into `~/.brew_path.sh`, `~/.zshenv`,
`~/.bashrc`, `~/.bash_profile`, and `~/.profile`. It's macOS-only (it exits doing
nothing on other systems); if Homebrew isn't installed it prints an install hint and
exits **without changing any dotfiles**. It does not change your login shell or
`/etc/shells` — it only prints the optional `sudo` commands for those.

### Running the test suite locally

Python (the bulk of the suite):

```sh
python3 -m pytest
```

Test paths and options are configured in `pyproject.toml`; no `cd` is required.

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

### Shell tests (shellspec)

The POSIX `sh` — the `ip_pre_AWS_*.sh` region pre-scripts and the testable
functions in `pfblockerng.sh` — has a functional suite under `tests/shell/`, run
with [shellspec](https://shellspec.info/) (pure POSIX, native kcov coverage):

```sh
shellspec            # from the repo root; reads ./.shellspec
shellspec --kcov     # with coverage (informational; needs kcov)
```

Install with `brew install shellspec` (macOS) or the official installer
(`curl -fsSL https://git.io/shellspec | sh`). The pre-commit hook and CI run it
automatically when `shellspec` is present (coverage is informational, no floor).
See [`tests/shell/README.md`](tests/shell/README.md) for the harness contracts
(the `iprange` PATH shim, the AWS fixture, and the `PFB_SOURCED` source-for-test
pattern).

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

#### Full ABP/EasyList support (ADR-07)

ABP/EasyList feeds are parsed **entirely in Python** — the old PHP `$easylist`
lite parser is gone. PHP header-sniffs an ABP feed, tags it `format_hint = 'abp'`,
and passes its **raw** lines through verbatim (IP anchors `||1.2.3.4^` and hosts
IPs still diverted to the DNSBL-IP firewall pass). `parse('abp', line)` is the one
DNS-only ABP parser; it adds the rules the lite parser silently dropped:

- **`@@` allow exceptions** (block + allow) — fixes the systematic over-blocking.
- **Regex** `/re/` and `@@/re/`: anchored-reducible patterns fold to `dataDB`/
  `zoneDB`/`whiteDB` (zero per-query cost); only irreducible regex compiles into
  `regexDB` (block) / `allowRegexDB` (allow).
- **`$important` / `$badfilter`** precedence, resolved by a 6-band numeric scale
  (user allow/block always win; feed `$important` > feed plain; `@@` > `||`). A
  build-emitted `important_rules` flag keeps a **byte-identical fast path** when no
  ABP precedence feature is loaded (the no-regression guarantee).
- **Out of scope, parsed-and-skipped:** element-hiding (`##`/`#@#`/`#?#`),
  path/URL rules, and page-context `$options` — never approximated as DNS blocks.

Untrusted regex (feed **and** the user Python Regex List) is kept tolerable by a
best-effort safeguard, **not** vetting: an opt-in "Limit long/complex regex"
static cap drops over-long / nested-quantifier patterns at load, and an always-on
runtime guard times each match — warns over a ceiling and **evicts** the pattern
over a higher one (snapshot-iterate, evict-after-loop; thread-safe under the GIL).
The accepted residual is a single slow first-hit before eviction (`re` cannot be
interrupted mid-match). The `DNSBL_Regex` alias count now reflects the **admitted**
(cap-filtered) regex total, emitted by Python to `/var/unbound/pfb_py_regex_count`.
See [ADR-07](.ADRs/ADR_07_ABP_DNSBL_Support/ADR.md) for the full contract.

ABP feeds build through the Python manifest path regardless of the DNSBL **TLD**
mode: the manifest is written unconditionally and `parse('abp', …)` does its own
TLD classification. The legacy PHP `tld_analysis()` pass (which re-parses the
combined feed dump as `,domain,,log,feed,group` CSV) is **not** ABP-aware, so it
**skips** any feed carrying the persisted `.abp` marker — an ABP feed's raw lines
are never CSV-mangled, and its domains/regex still build in Python. Plain feeds
keep the legacy TLD behaviour unchanged. **Follow-up:** a later pass should review
the full ABP × DNSBL-TLD-mode integration (ideally folding the PHP TLD pass into
the Python build for all feeds).

The decision-equivalence of the ADR-06 move (block/resolve/whitelist/HSTS/noAAAA
across hosts/plain/csv:pon, plus feed/group attribution and the emitted count) is
pinned by the golden + build unit tests, and the ADR-07 ABP semantics + the
no-regression fast path by the `test_adr07_*` suite — all in the default `pytest`
run:

```sh
python -m pytest tests/test_adr06_golden_oracle.py \
                 tests/test_adr06_build_module.py \
                 tests/test_adr06_init_from_raw.py \
                 tests/test_adr06_php_boundary.py \
                 tests/test_adr07_decision_spec.py \
                 tests/test_adr07_parser.py \
                 tests/test_adr07_reconcile.py \
                 tests/test_adr07_matcher_strata.py \
                 tests/test_adr07_emit_wire.py \
                 tests/test_adr07_regex_safety.py \
                 tests/test_adr07_php_boundary.py
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

…and the ADR-07 regex/ReDoS spike (`spike_adr07_regex.py`, stdlib only) — the
de-risking measurement for full ABP support: regex reduction ratio, irreducible
count, added per-query latency at feed scale, and the worst real ReDoS first-hit
on a ≤253-char input vs the kill-threshold (run with `tracemalloc` off):

```sh
python benchmarks/spike_adr07_regex.py
SPIKE_COUNTS=10,100,1000 SPIKE_ROUNDS=50 python benchmarks/spike_adr07_regex.py
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

The same `composer install` provides [PHPUnit](https://phpunit.de/) for the PHP
unit suite (`vendor/bin/phpunit`, config in `phpunit.xml`) — the fast functional
layer beneath the live-VM smoke. See
[Running the test suite locally](#running-the-test-suite-locally) and
[`tests/php/README.md`](tests/php/README.md).

#### Shell

[ShellCheck](https://www.shellcheck.net/) is available as a VS Code extension
(see IDE setup above) and is also enforced in CI at `--severity=warning`.
Configuration is in `.shellcheckrc`. Functional shell tests (shellspec) live in
`tests/shell/` — see [Shell tests (shellspec)](#shell-tests-shellspec) above.

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

## Smoke tests (live pfSense VM)

The smoke suite (ADR-04, `tests/smoke/`) boots a **real pfSense CE VM** under
QEMU/KVM, installs the branch's freshly-built `.pkg`, and asserts pfBlockerNG's
real behaviour end-to-end — the DNS path (Unbound + `pfb_unbound.py`, probed
with `dig`/`dnspython`) and the IP path (`pfctl` alias tables + rules, over
SSH). It is **dev-only**, marked `@pytest.mark.smoke`, and **deselected from the
default `python -m pytest`** (`pyproject.toml` `addopts: --ignore=tests/smoke`),
so the normal unit run is unaffected.

### Running it in CI

`.github/workflows/smoke.yml` runs the matrix on GitHub-hosted KVM. It is
**gated** — `workflow_dispatch` + `workflow_call` only (a nightly `schedule` is
provided, commented) — **not** every-PR yet, because the per-run wall-time has
not been measured against §7's ~20 min/job budget. Once a dispatched run
confirms it fits, add a `pull_request` trigger to move it to every-PR. Trigger a
run with:

```sh
gh workflow run smoke.yml                        # uses the SMOKE_IMAGE_REF secret/variable
gh workflow run smoke.yml -f image_ref=ghcr.io/<org>/pfsense-ce@sha256:<digest>
```

The workflow builds the `.pkg` (`build-pkg.yml`, FreeBSD VM), pulls the pfSense
image from private GHCR, then runs `pytest -m smoke`. The test fixture **blocks
the runner's egress after `deploy()`** so the run is hermetic — feeds come from
an in-runner mock server reached over the SLIRP host alias `10.0.2.2`. Required
Actions
config (see `.ADRs/ADR_04_VM_Smoke_Tests/RESULTS/02_Results.txt`):
`SMOKE_IMAGE_REF`, `SMOKE_GHCR_USER`, `SMOKE_GHCR_TOKEN`, `SMOKE_SSH_PRIV_KEY`
(and, to match the baked image, `SMOKE_DNSBL_VIP4` / `SMOKE_CONTROL_NAME` /
`SMOKE_CONTROL_IP`).

### Running it locally

Needs `/dev/kvm`, `qemu-system-x86_64` + `qemu-img`, `oras`, `ssh`, and a built
`.pkg`. Then:

```sh
python -m pip install -r tests/smoke/requirements.txt
export SMOKE_IMAGE_REF=ghcr.io/<org>/pfsense-ce@sha256:<digest>   # private GHCR
export SMOKE_SSH_KEY=/path/to/guest_priv_key                      # mode 600
export SMOKE_PKG=/path/to/pfBlockerNG-*.pkg                       # from build-pkg
oras login ghcr.io                                                # for the pull
python -m pytest tests/smoke -m smoke --override-ini="addopts="
```

The fixture pulls the image by `SMOKE_IMAGE_REF` and boots an ephemeral overlay
(the base qcow2 is never mutated). Missing KVM/secrets/deps → the suite **skips**
cleanly, never errors. (CI sets `SMOKE_IMAGE_DIR` instead, pointing at the
pre-pulled image, so the fixture blocks egress after `deploy()` without
needing another network pull.)

### Rebuilding the image on a CE bump

The pfSense CE image is **seeded once** (one clean manual install, archived) and
**upgraded in place** for every subsequent release — `build-image.yml` runs
`pfSense-upgrade` on the prior tag for patch/minor (and major), gated by the
smoke round-trip (publish-on-pass, fail-closed). A **fresh manual re-seed** is
the fallback only when that gate fails. **CE only** (Plus is out of scope). The
seed and every version snapshot are retained as immutable GHCR tags (never
overwritten); the GHCR package is **private**. Full strategy + what is baked:
`.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md` and `RESULTS/02_Results.txt`.

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
   `h.rule_references` for the IP side. `__exit__` resets to baseline.

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
details and [`.ADRs/ADR_04_VM_Smoke_Tests/`](.ADRs/ADR_04_VM_Smoke_Tests/).

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
