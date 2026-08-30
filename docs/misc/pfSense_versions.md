# pfSense version notes

Dev-only reference (not shipped — release archives hold only `src/`). Per-version facts about pfSense CE/Plus affecting pfBlockerNG packaging, deps, ADR-04 smoke-test base image.

How obtained (re-verify — see CLAUDE.md "Investigating the live system"): on live box, `pkg info` (installed set), `pkg info -d <pkg>` (declared deps), `php -v` / `python --version`. Authoritative dep list = port Makefile `RUN_DEPENDS` (`net/pfSense-pkg-pfBlockerNG-edge`, channel devel branch builds — `-devel` recipe retired from ports tree, issue #2166); tables below hand-maintained mirror — confirm against port (or built `.pkg`) when baking image.

## 2.8.x (CE)

### Base facts

Observed on CE **2.8.1** box; 2.8.0 shares same base toolchain.

| Aspect | 2.8.x |
| --- | --- |
| FreeBSD base | 15.0-RELEASE (`FreeBSD:15:amd64` pkg ABI) |
| PHP | 8.3 (`php83`) |
| Python | 3.11 (`python311`) |
| pkg | 1.21.x |
| Unbound | 1.24.x |

> **FreeBSD base + PHP row above also encoded in supported-version matrix.**
> `supported-versions.json` on `ci-metadata` orphan ref = **single source of
> truth**: carries `(freebsd_version, php_version)` pair per pfSense version,
> read at runtime by every workflow, including `resolve-version` job in
> `.github/workflows/build-image.yml` (hard-fails on unmapped version —
> reject-unknown contract from issue #22 preserved). Adding new supported CE
> version: add entry to `supported-versions.json` on `ci-metadata` **and**
> update table here. No workflow edit needed.
>
> **These values must never be restated as literals** in `src/`, `scripts/`, or
> `.github/workflows/` — read from matrix at runtime/generation time
> (`scripts/read-version-matrix.sh`). `scripts/check_version_literals.py`
> (pre-commit + CI) enforces; escape genuine one-off with inline
> `# version-literal-ok: <reason>` comment.
>
> **`arch` retired from matrix (issue #1806).** Every
> `pfSense-pkg-pfBlockerNG` port is `NO_ARCH`, so one wildcard-ABI `.pkg`
> build serves every CPU arch of FreeBSD major — `supported-versions.json`
> entries carry no `arch` field at all (stray one on old row
> tolerated-ignored, never resurrected as default). BUILD matrix
> (`read-version-matrix.sh --print-build`) dedupes to one row per exact
> runtime tuple `(freebsd_major, php_version, py_flavor)` (issue #2926 —
> same-major rows with a differing php/py stay separate rows), gains
> `extra_pkgs` — see below.
>
> **`status` decides whether row may VETO A RELEASE (issue #1855).** Enum is
> `beta | active | GA` (`GA` = legacy alias for `active`). Row gates release
> **iff status is released pfSense version** — `active` or `GA`. Every other
> value non-blocking: `beta` today, anything added later (rc, dev, eol, …), and
> absent or unrecognized status alike. Non-blocking leg **still runs, still
> reports** in release run; just cannot fail it, and each demotion emits loud
> `::warning::` naming row + status so coverage cannot erode silently.
> Predicate lives in exactly one place —
> `scripts/resolve-legs.sh` (`RELEASE_GATE_INPUT=true`, set only by `release.yml`
> via suites' `release_gate` input) — so PR-gate and nightly runs unaffected:
> there, every `ci:true` row still vetoes. Prompted by v4.0.0.alpha.24, which
> Plus 26.07 (`status: beta`, auto-activated to `ci: true` by reconcile
> automation) vetoed over real 26.07-only defect (#1856).

### pfBlockerNG runtime dependencies (port `RUN_DEPENDS`)

Must be present for pfBlockerNG to work. By convention ADR-04 smoke image **bakes** them so harness `pkg add` of branch `.pkg` resolves them from local pkg db **offline** (see `legacy/ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md` §3). Missing dep = `pkg add` "Missing dependency" = bad image, re-bake.

These = port's explicit `RUN_DEPENDS` (10 packages, issue #1806 — fixes pre-existing drift against port Makefile: table had stopped at 9), verified against `net/pfSense-pkg-pfBlockerNG-edge/Makefile`. To bake onto image, run [`scripts/misc/install_deps_CE_2.8.sh`](../../scripts/misc/install_deps_CE_2.8.sh) on box (as root):

> **Built `.pkg` records 13 dependencies, not 10.** Besides these 10,
> `make package` records the three that `USES=php` (`USE_PHP=intl`) and
> `USES=python` inject: `php83` (`lang/php83`), `php83-intl` (`devel/php83-intl`)
> and `python311` (`lang/python311`) on 2.8.x. Not literal
> `RUN_DEPENDS`, but real package deps (confirmed by diffing real
> `make package` artifact). pfSense already ships PHP/Python, so no extra baking
> needed — but table below = **explicit run-deps**, not package's full dep set.

| Package (origin) | Binary probed | Purpose |
| --- | --- | --- |
| `net/libmaxminddb` | `bin/mmdblookup` | GeoIP C library — GeoIP feeds / reports |
| `net/py-maxminddb` (`py311-maxminddb`) | — | Python MaxMind reader — GeoIP in `pfb_unbound.py` |
| `databases/py-sqlite3` (`py311-sqlite3`) | — | Python sqlite3 — DNSBL / reports database |
| `www/lighttpd` | `sbin/lighttpd` | DNSBL sinkhole webserver (block page on VIP) |
| `textproc/jq` | `bin/jq` | JSON processing (feeds, AWS IP-prefix pre-scripts) |
| `net/rsync` | `bin/rsync` | **rsync-format feed lists** (`pfblockerng.inc` → `exec("/usr/local/bin/rsync …")`); also rsync-overlay deploy transport |
| `net-mgmt/grepcidr` | `bin/grepcidr` | CIDR matching on IP path |
| `net-mgmt/iprange` | `bin/iprange` | IP-range aggregation on IP path |
| `textproc/gnugrep` | `bin/ggrep` | GNU grep (vs base BSD grep) for list-processing pipeline |
| `textproc/py-charset-normalizer` (`py311-charset-normalizer`) | — | Character-encoding detection (issue #1806) — see CE-only note below |

Notes:

- **`py311-*` pinned to base Python (3.11 on 2.8.x)** — port uses
  `${PYTHON_PKGNAMEPREFIX}…@${PY_FLAVOR}`, so base moving to Python 3.12
  yields `py312-sqlite3` / `py312-maxminddb` automatically.
- **`rsync` IS hard run-dep** (not merely deploy transport): port declares
  `net/rsync` and pfBlockerNG shells out to it for rsync-format feeds. Bake it
  like rest.
- **PHP and Python interpreter ship with pfSense, not in `RUN_DEPENDS`**,
  but built `.pkg` still depends on `php83` + `php83-intl` + `python311`
  because `USES=php`/`USES=python` inject them (see note above). Unbound is
  base component, not package dep at all.
- **`py311-charset-normalizer` is CE-only from OUR repo (issue #1806).** Netgate's
  own pfSense CE package repo does not carry it (they build for Plus only), so
  `pkg install pfSense-pkg-pfBlockerNG` on stock CE box cannot resolve that
  RUN_DEPENDS from Netgate's mirror. Our self-hosted pkg repo (ADR-17) builds it,
  designed to serve it itself: `supported-versions.json`'s CE entry carries
  `extra_pkgs: ["textproc/py-charset-normalizer"]` (Plus entry carries
  `extra_pkgs: []` — Netgate already ships it there),
  `scripts/build-dep-pkg-portable.py` builds its reproducible NO_ARCH `.pkg`
  from the Ports-pinned sdist and locked Python toolchain, and
  `build-repo-portable.py --dep-pkgs` folds the result into release/nightly
  catalogs of every matching FreeBSD major.
  Release-verification CI gate (release.yml's smoke-suite/ui-suite) proves this
  end to end against built artifacts, and dep `.pkg` IS deliberate
  GitHub Release asset — `attach-pkgs`'s existing `pfBlockerNG-relpkg-*` sweep
  attaches it alongside branch `.pkg`s, and `publish-release`'s healthcheck
  counts it explicitly. Remaining follow-up narrower: separate
  `pfBlockerNG/pkg` repo's `publish.yml` folding attached dep `.pkg` into
  live served catalog not yet wired there.
