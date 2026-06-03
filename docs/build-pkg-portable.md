# `build-pkg-portable.py` — off-FreeBSD `.pkg` builder

Build a pfSense-installable FreeBSD package (`.pkg`) for the pfBlockerNG port on
**Linux or macOS, with no FreeBSD host and no ports framework**. It is the
off-box counterpart to [`scripts/build-pkg.sh`](../scripts/build-pkg.sh), which
runs the port's real `make package` on an ABI-matched FreeBSD VM.

It exists because pfBlockerNG is a `NO_BUILD` port: nothing is compiled.
"Building" the package is just (a) laying the production files out at their
install paths, (b) applying the port's textual substitutions, and (c) emitting a
libpkg-format archive with the right manifest. This tool does exactly that.

**Dev-only.** Like the rest of `scripts/`, it is not shipped — release archives
contain only `src/`.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Options reference](#options-reference)
- [The two port layouts](#the-two-port-layouts)
- [Target facts (ABI / Python / PHP)](#target-facts-abi--python--php)
- [Dependency resolution](#dependency-resolution)
- [Fidelity vs `make package`](#fidelity-vs-make-package)
- [Output format](#output-format)
- [Exit status and output streams](#exit-status-and-output-streams)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [See also](#see-also)

## How it works

The tool reads the **same files the real `make package` reads** and replays the
port's own build steps — it does **not** hardcode pfBlockerNG's current file list
or dependencies, so it tracks changes to the port automatically:

1. **Evaluate the port `Makefile`.** A small FreeBSD-ports variable evaluator
   handles `=` / `?=` / `+=` / `:=`, line continuations, `#` comments,
   `${VAR}`/`$(VAR)` expansion and a couple of `:modifiers`. Framework variables
   the port relies on (`PREFIX`, `DATADIR`, `WRKSRC`, `FILESDIR`, the install
   macros, the Python prefix, …) are seeded; `.include <bsd.port.mk>` is ignored.
2. **Acquire the source** (USE_GITHUB ports): fetch the GitHub tarball for
   `GH_TAGNAME`, or use a local checkout (`--local-src`). Classic ports install
   from the port's embedded `files/` directory, so nothing is fetched.
3. **Replay the recipe.** The tool interprets the port's `do-extract`,
   `post-extract` and `do-install` targets with a small command vocabulary
   (`MKDIR`, `INSTALL_DATA`, `INSTALL_SCRIPT`, `INSTALL_PROGRAM`, `MV`, `CP`,
   `LN`, `RM`, `REINPLACE_CMD`/`SED`) into a controlled staging directory — the
   same effect `make` would have, minus the shell. An **unknown recipe command
   is a hard error** (a signal that the port changed in a way the tool must be
   taught — rather than silently producing a broken package).
4. **Validate against `pkg-plist`.** The staged file set must equal the plist's
   file set (a mismatch aborts the build); the plist's `@dir` entries become the
   manifest's directories.
5. **Build the manifest and archive.** Emit `+COMPACT_MANIFEST` and `+MANIFEST`
   (UCL/JSON) plus the payload, as a zstd- (or xz-) compressed tar — a real
   libpkg `.pkg` that `pkg add` installs and registers on pfSense, running the
   package's POST-INSTALL hook just like a port-built `.pkg`.

## Requirements

- **Python 3.11+** (standard library only — no third-party Python packages).
- A **zstd encoder** for the default output compression: either the `zstd`
  binary (`brew install zstd` / `apt install zstd`) or the Python `zstandard`
  module. `--compression xz` uses the standard-library `lzma` and needs neither.
- Network access only when fetching from GitHub (no `--local-src`) or when using
  `--repo-catalogue` with a URL or `auto`.

A clone of [`pfsense/FreeBSD-ports`](https://github.com/pfsense/FreeBSD-ports)
(or the fork carrying the port under test) is required — passed via `--ports`.
It supplies the port directory **and** the dependency ports used to resolve
dependency names/origins.

## Quick start

```sh
# from the pfBlockerNG repo root, building the working tree for pfSense CE 2.8
python3 scripts/build-pkg-portable.py \
    --ports ../FreeBSD-ports \
    --local-src . \
    --abi FreeBSD:15:amd64 \
    --py-flavor py311 \
    --php 8.3 \
    --out /tmp
# -> /tmp/pfSense-pkg-pfBlockerNG-devel-<version>.pkg
```

The built path is printed to stdout; progress goes to stderr. Add `--dry-run` to
print the build plan (files, modes, dependencies) without writing an archive.

## Options reference

### Required

| Option | Description |
| --- | --- |
| `--ports PATH` | FreeBSD-ports checkout. Must contain `net/pfSense-pkg-pfBlockerNG[-devel]` and the dependency ports (e.g. `textproc/jq`, `lang/php83`) used to resolve dependency names. |

### Port selection

| Option | Default | Description |
| --- | --- | --- |
| `--channel devel\|stable` | `devel` | Which port to build: `devel` → `net/pfSense-pkg-pfBlockerNG-devel`, `stable` → `net/pfSense-pkg-pfBlockerNG`. |
| `--port-dir PATH` | — | Build an explicit port directory instead, overriding `--channel`. |

### Target facts (version-dependent; asked if omitted)

These describe the **target pfSense edition/version**, not the ports checkout.
They are never inferred from the ports tree (see
[Target facts](#target-facts-abi--python--php)). If omitted and the terminal is
interactive, the tool prompts; otherwise it exits with an error naming the flag.

| Option | Example | Description |
| --- | --- | --- |
| `--abi ABI` | `FreeBSD:15:amd64` | The package ABI. CE 2.8 = `FreeBSD:15:amd64`; Plus = `FreeBSD:16:amd64`. Sets the manifest `abi`. |
| `--arch TRIPLET` | `freebsd:15:x86:64` | The manifest `arch` triplet. Default: derived from `--abi` (`amd64` → `x86:64`, etc.). |
| `--py-flavor FLAVOR` | `py311` | The Python flavor used in dependency names (`py311-sqlite3`, …) and the `python<XY>` dep. |
| `--php VERSION` | `8.3` | The PHP version for the `USES=php` dependency (`php83`, `php83-intl`). Asked **only** when the port uses PHP. |
| `--freebsd-version N` | `1500068` | The build host's `__FreeBSD_version`, written to the manifest `annotations` block. Optional; the block is omitted if unset. |

### Source (USE_GITHUB ports)

| Option | Description |
| --- | --- |
| `--local-src PATH` | Build from a local pfBlockerNG checkout (its `src/` tree) instead of fetching the GitHub tag. Fast for iterating on code under test. The working tree is never modified (it is copied into the staging area first). |
| `--gh-tagname REF` | Override `GH_TAGNAME` — fetch this commit SHA, tag, or branch from GitHub. Default: the Makefile's `v${PORTVERSION}`. The ref must contain a `src/` tree (see [Troubleshooting](#troubleshooting)). |

### Dependency versions

| Option | Description |
| --- | --- |
| `--repo-catalogue SRC` | Pin exact dependency versions from a binary-repo `packagesite`. `SRC` may be a path or URL to a `packagesite.yaml` or `packagesite.pkg`/`.txz`, or the literal `auto` to fetch FreeBSD.org's catalogue for `--abi`. Without it, versions are best-effort from the ports tree. See [Dependency resolution](#dependency-resolution). |

### Output

| Option | Default | Description |
| --- | --- | --- |
| `--out DIR` | `.` | Directory to write `<pkgname>.pkg` into (created if needed). |
| `--compression zstd\|xz` | `zstd` | Archive compression. `zstd` is the native pkg format; `xz` uses the Python standard library (no external encoder). `pkg add` accepts either regardless of the `.pkg` extension. |
| `--keep-work` | off | Keep the temporary work/staging directory (printed on exit) for inspection. |
| `--dry-run` | off | Print the build plan (metadata, dependency list, file count and sample modes) and exit without writing a `.pkg`. |

## The two port layouts

pfBlockerNG's port has existed in two shapes; the tool detects which from the
`Makefile` and handles both:

| Layout | Branch | Source of files | Build source |
| --- | --- | --- | --- |
| `USE_GITHUB` | `pfblockerng/use-github` | fetched from GitHub (`GH_ACCOUNT`/`GH_PROJECT`/`GH_TAGNAME`), `WRKSRC = <project>-<ver>/src` | the fetched tag, or `--local-src` |
| classic | `devel` (pre-`src/` move) | embedded in the port's `files/` directory (`${FILESDIR}`) | the ports checkout itself |

For the `USE_GITHUB` layout, `--local-src` substitutes a local checkout for the
GitHub fetch — useful to package code under test without cutting a tag.
`--local-src` does not apply to the classic layout (its source is the embedded
`files/`).

## Target facts (ABI / Python / PHP)

The ABI, Python flavor and PHP version are properties of the **target pfSense
release**, not of the ports checkout. They are taken from the command line (or
asked for) and are **never** read from the ports tree's
`Mk/bsd.default-versions.mk`, because that is a single snapshot whose defaults
can differ from what a given pfSense release actually ships — e.g. the fork tree
may default to `PHP_DEFAULT=8.4` while pfSense CE 2.8 ships PHP 8.3, and
`build-pkg.sh` pins `php=8.3` for exactly that reason.

The per-version facts (FreeBSD major / PHP / Python for each pfSense edition) are
recorded in [`misc/pfSense_versions.md`](misc/pfSense_versions.md). Pass the
values for the edition you are targeting.

## Dependency resolution

The manifest's dependencies are what `make package` records, in two parts:

1. **Declared dependencies** — the port's `RUN_DEPENDS` and `LIB_DEPENDS`. Each
   `target:origin[@flavor]` entry is resolved to a package **name** and
   **origin**:
   - A name-form left side (`py311-sqlite3>0`) yields the name directly.
   - A file-form left side (`${LOCALBASE}/bin/ggrep`) is resolved against the
     dependency port's `Makefile` in the ports tree
     (`PKGNAMEPREFIX` + `PORTNAME` + `PKGNAMESUFFIX`) — e.g.
     `textproc/gnugrep` → `gnugrep`, not `grep`.
   - **Flavors** are honoured: the dependency spec's `@flavor` (or the port's
     default `FLAVORS:[1]`) selects the flavored name — `net/rsync` default →
     `rsync`, `net/rsync@python` → `rsync-python`.
2. **`USES`-injected dependencies** — those the ports framework adds and the
   built package records even though they are not in `RUN_DEPENDS`:
   - `USES=python` → `python<XY>` (`lang/python<XY>`).
   - `USES=php` with `USE_PHP=<ext> …` → `php<XY>` (`lang/php<XY>`) and one
     `php<XY>-<ext>` per extension (origin found by globbing the ports tree,
     e.g. `devel/php83-intl`).

### Dependency versions

The version `make package` records for a dependency is the version of the
**installed binary package** on the build host — which tracks the build host's
repo, not the ports tree (the tree may even be behind, e.g. `rsync 3.4.1_6` in
the tree vs `3.4.3` installed). Therefore:

- **Names and origins are always exact** (derived from the port files).
- **Versions are best-effort** from the ports tree by default (correct for most
  ports, including the `PORTREVISION`, e.g. `grepcidr 2.0_1`).
- For **exact** versions, pass `--repo-catalogue` — the tool reads each
  dependency's version (and origin) from the repo `packagesite`, the same source
  `pkg` installs from. `auto` fetches FreeBSD.org's catalogue for `--abi`.

Note that `pkg add` checks that a dependency is **present**, not its exact
version, so dependency versions do not affect installability — they affect
manifest fidelity only.

## Fidelity vs `make package`

The output has been diffed field-by-field against a real `make package` build
(on a FreeBSD CI VM) for the **same commit**. Everything derivable from the port
files matches exactly:

- scalar metadata: `name`, `origin`, `version`, `comment`, `maintainer`, `www`,
  `abi`, `arch`, `prefix`, `flatsize`, `licenselogic`, `licenses`, `categories`,
  `desc`, `annotations`;
- every payload file: path, `sha256` checksum, and **permissions**
  (`INSTALL_DATA` → `0644`, `INSTALL_SCRIPT`/`INSTALL_PROGRAM` → `0555` — FreeBSD
  `BINMODE`);
- `directories`; the `install` and `deinstall` scripts (byte-identical, with the
  trailing newline stripped as `pkg create` does);
- the full dependency set: **names and origins**.

Two values are **not derivable from the port files** and so will not match a
specific past build:

1. **File `mtime`** — the install clock. It differs between any two real builds;
   the tool records `0`.
2. **A few dependency versions** — read from the build host's installed binary
   packages (see [above](#dependency-versions)). `--repo-catalogue` pins them.

## Output format

A `.pkg` is a compressed tar archive (zstd by default; `pkg add` sniffs the
format regardless of extension). Member order matters and is reproduced exactly:

```text
+COMPACT_MANIFEST     # UCL/JSON: metadata only (no files/dirs/scripts)
+MANIFEST             # UCL/JSON: full manifest
/etc/inc/priv/...     # payload files, at absolute paths, root:wheel
/usr/local/pkg/...
...
```

File entries carry `sum` (`1$<sha256hex>`), `uname`/`gname` (`root`/`wheel`),
`perm`, `fflags` and `mtime`; directories carry `uname`/`gname`/`perm`/`fflags`.
The output filename is `<PORTNAME>-<PKGVERSION>.pkg`, where `PKGVERSION` is
`PORTVERSION[_PORTREVISION][,PORTEPOCH]`.

## Exit status and output streams

- **stdout**: on success, the absolute path of the written `.pkg` (nothing else),
  so it is safe to capture in a script (`PKG=$(build-pkg-portable.py …)`). With
  `--dry-run`, stdout carries the plan instead.
- **stderr**: progress (`==> …`) and warnings.
- **exit code**: `0` on success; `1` on a build error (with a
  `build-pkg-portable: <reason>` message on stderr); `2` on bad command-line
  arguments.

## Examples

```sh
# 1) Build the local working tree for CE 2.8 (devel channel), into /tmp.
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports --local-src . \
    --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out /tmp

# 2) Build the stable channel from the FreeBSD-ports embedded files (classic
#    layout — no --local-src needed; the ports tree carries the code).
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports --channel stable \
    --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3

# 3) Build a specific commit (must have a src/ tree) and pin exact dep versions
#    from FreeBSD.org's repo for the ABI.
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports \
    --gh-tagname 3b4b27eb18c12a371d0b80366b8d3f20d201d1d1 \
    --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --repo-catalogue auto

# 4) Target pfSense Plus (FreeBSD 16), xz compression, keep the work dir.
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports --local-src . \
    --abi FreeBSD:16:amd64 --py-flavor py311 --php 8.3 \
    --compression xz --keep-work

# 5) Just inspect the plan.
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports --local-src . \
    --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --dry-run
```

## Troubleshooting

- **`fetched tarball has no src/ dir under <project>-<ref>`** — the fetched ref
  predates the `src/` reorganization (e.g. the `v3.2.x` release tags). Fetch a
  ref that has `src/` (`--gh-tagname <branch-or-commit>`) or build from a working
  tree with `--local-src`.
- **`plist lists files the recipe did not stage` / `recipe staged files not in
  the plist`** — the port's `pkg-plist` and `do-install` disagree (drift). Fix
  the port so the two match; the tool deliberately refuses to guess.
- **`unsupported recipe command ${X}`** — the port's recipe uses a command the
  interpreter does not model yet. Add a handler for it (`_cmd_<x>`); do not work
  around it, so the staging stays faithful.
- **`--abi`/`--py-flavor`/`--php not provided`** in a non-interactive context —
  pass the flag; see [`misc/pfSense_versions.md`](misc/pfSense_versions.md) for
  the right value per target.
- **`repo catalogue is zstd; install zstd …`** — a `packagesite.pkg` is
  zstd-compressed; install the `zstd` binary or the Python `zstandard` module, or
  point `--repo-catalogue` at a plain `packagesite.yaml`.

## Use in CI

The ADR-04 smoke gate builds the branch `.pkg` with this tool on a plain Linux
runner — `.github/workflows/build-pkg-linux.yml` clones the FreeBSD-ports tree and
runs:

```sh
python3 scripts/build-pkg-portable.py \
  --ports "$PORTS" --channel devel --local-src . \
  --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out out
```

It publishes the same `pfBlockerNG-pkg` artifact (`out/*.pkg`) that `smoke.yml`
installs, with no FreeBSD VM / KVM / image cache — so it is far faster than the
FreeBSD build it replaced. Because `pkg add` checks a dependency is *present* (not
its version), the portable `.pkg` installs on the baked-deps smoke image
identically to a `make package` one. The FreeBSD path (`build-pkg.yml`, real
`make package`) is retained as a **dispatch-only fidelity oracle** — dispatch it to
cross-check this tool's output, or repoint `smoke.yml`'s `build-pkg` job to it if
the portable path ever diverges.

## See also

- [`.github/workflows/build-pkg-linux.yml`](../.github/workflows/build-pkg-linux.yml)
  — the Linux smoke build that drives this tool.
- [`scripts/build-pkg.sh`](../scripts/build-pkg.sh) — the on-FreeBSD builder
  (real `make package`), the fidelity oracle (`build-pkg.yml`, dispatch-only).
- [`scripts/README.md`](../scripts/README.md) — overview of the dev scripts and
  the two install paths (rsync overlay vs `.pkg`).
- [`misc/pfSense_versions.md`](misc/pfSense_versions.md) — per-version base facts
  (FreeBSD major, PHP, Python) and the runtime dependencies.
- `tests/test_build_pkg_portable.py` — unit tests for the evaluator, recipe
  interpreter, dependency resolution, and archive emission.
