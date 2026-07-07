# pfSense version notes

Dev-only reference (not shipped — release archives contain only `src/`).
Per-version facts about pfSense CE/Plus that affect pfBlockerNG packaging, its
dependencies, and the ADR-04 smoke-test base image.

How these were obtained (and how to re-verify — see CLAUDE.md "Investigating the
live system"): on a live box, `pkg info` (installed set), `pkg info -d <pkg>`
(a package's declared deps), `php -v` / `python --version`. The authoritative
dependency list is the port Makefile `RUN_DEPENDS`
(`net/pfSense-pkg-pfBlockerNG-devel`); the tables below are a hand-maintained
mirror — confirm against the port (or a built `.pkg`) when baking an image.

## 2.8.x (CE)

### Base facts

Observed on a CE **2.8.1** box; 2.8.0 shares the same base toolchain.

| Aspect | 2.8.x |
| --- | --- |
| FreeBSD base | 15.0-RELEASE (`FreeBSD:15:amd64` pkg ABI) |
| PHP | 8.3 (`php83`) |
| Python | 3.11 (`python311`) |
| pkg | 1.21.x |
| Unbound | 1.24.x |

> **The FreeBSD base + PHP row above is also encoded in the supported-version
> matrix.** `supported-versions.json` on the `ci-metadata` orphan ref is the
> **single source of truth**: it carries the `(freebsd_version, php_version)` pair
> per pfSense version and is read at runtime by every workflow, including the
> `resolve-version` job in `.github/workflows/build-image.yml` (which hard-fails on
> any unmapped version — the reject-unknown contract from issue #22 is preserved).
> When adding a new supported CE version, add an entry to `supported-versions.json`
> on `ci-metadata` **and** update the table here. No workflow edit needed.
>
> **These values must never be restated as literals** in `src/`, `scripts/`, or
> `.github/workflows/` — read them from the matrix at runtime/generation time
> (`scripts/read-version-matrix.sh`). `scripts/check_version_literals.py`
> (pre-commit + CI) enforces this; escape a genuine one-off with an inline
> `# version-literal-ok: <reason>` comment.

### pfBlockerNG runtime dependencies (port `RUN_DEPENDS`)

These must be present for pfBlockerNG to function. By convention the ADR-04
smoke image **bakes** them so the harness `pkg add` of the branch `.pkg` resolves
them from the local pkg db **offline** (see `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`
§3). A missing dep → `pkg add` "Missing dependency" → bad image, re-bake.

These are the port's explicit `RUN_DEPENDS` (9 packages), verified against
`net/pfSense-pkg-pfBlockerNG-devel/Makefile`. To bake them onto an image, run
[`scripts/misc/install_deps_CE_2.8.sh`](../../scripts/misc/install_deps_CE_2.8.sh)
on the box (as root):

> **The built `.pkg` records 12 dependencies, not 9.** Besides these 9,
> `make package` records the three that `USES=php` (`USE_PHP=intl`) and
> `USES=python` inject: `php83` (`lang/php83`), `php83-intl` (`devel/php83-intl`)
> and `python311` (`lang/python311`) on 2.8.x. They are *not* literal
> `RUN_DEPENDS`, but they are real package dependencies (confirmed by diffing a
> real `make package` artifact). pfSense already ships PHP/Python, so they need no
> extra baking — but the table below is the **explicit run-deps**, not the package's
> full dependency set.

| Package (origin) | Binary probed | Purpose |
| --- | --- | --- |
| `net/libmaxminddb` | `bin/mmdblookup` | GeoIP C library — GeoIP feeds / reports |
| `net/py-maxminddb` (`py311-maxminddb`) | — | Python MaxMind reader — GeoIP in `pfb_unbound.py` |
| `databases/py-sqlite3` (`py311-sqlite3`) | — | Python sqlite3 — DNSBL / reports database |
| `www/lighttpd` | `sbin/lighttpd` | DNSBL sinkhole webserver (block page on the VIP) |
| `textproc/jq` | `bin/jq` | JSON processing (feeds, the AWS IP-prefix pre-scripts) |
| `net/rsync` | `bin/rsync` | **rsync-format feed lists** (`pfblockerng.inc` → `exec("/usr/local/bin/rsync …")`); also the rsync-overlay deploy transport |
| `net-mgmt/grepcidr` | `bin/grepcidr` | CIDR matching on the IP path |
| `net-mgmt/iprange` | `bin/iprange` | IP-range aggregation on the IP path |
| `textproc/gnugrep` | `bin/ggrep` | GNU grep (vs base BSD grep) for the list-processing pipeline |

Notes:

- **`py311-*` are pinned to the base Python (3.11 on 2.8.x)** — the port uses
  `${PYTHON_PKGNAMEPREFIX}…@${PY_FLAVOR}`, so a base that moves to Python 3.12
  yields `py312-sqlite3` / `py312-maxminddb` automatically.
- **`rsync` IS a hard run-dep** (not merely a deploy transport): the port declares
  `net/rsync` and pfBlockerNG shells out to it for rsync-format feeds. It must be
  baked like the rest.
- **PHP and the Python interpreter ship with pfSense and are not in `RUN_DEPENDS`**,
  but the built `.pkg` still depends on `php83` + `php83-intl` + `python311`
  because `USES=php`/`USES=python` inject them (see the note above). Unbound is a
  base component and is not a package dependency at all.
