# Dev scripts

Helper scripts for developing, deploying, and building pfBlockerNG. **Dev-only** —
none of this ships in the release archive (which contains only `src/`).

## Supported-version matrix

The single source of truth for which pfSense versions pfBlockerNG supports lives on
the **`ci-metadata` orphan branch** (its own history, off `main`/`devel`) as
`supported-versions.json`. All CI/build workflows read it at runtime.

| Script | Use |
| --- | --- |
| [`read-version-matrix.sh`](read-version-matrix.sh) | Read the matrix from `ci-metadata` and print/emit the BUILD matrix and CI matrix. |

The `read-version-matrix.sh` reader is also exposed as a composite GH Actions action
(`.github/actions/read-version-matrix/`) that emits two outputs: `build_matrix` (all
entries → one `.pkg` per distinct FreeBSD major) and `ci_matrix` (`ci: true` CE
entries → the smoke-fan-out set, never Plus).

### Schema

```text
{
  "pfsense_version": "2.8",          # pfSense Major.Minor family (CE: Y.Z; Plus: YY.MM)
  "channel":         "CE",           # CE | Plus
  "freebsd_version": "15.0-RELEASE", # full FreeBSD version string (build env)
  "freebsd_major":   "15",           # FreeBSD major (ABI dedup key; artifact suffix)
  "php_version":     "8.3",          # PHP version (pinned so USES=php dep names match)
  "py_flavor":       "py311",        # Python flavor for build-pkg-linux.yml
  "status":          "GA",           # beta | GA
  "ci":              true            # include in smoke CI matrix (false for Plus for now — no licensed CI image)
}
```

### Lifecycle policy

- **Add** when a beta/GA lands (curated — a human edits the JSON via a PR against
  `ci-metadata`). Add immediately on a beta so the build + CI validation starts early;
  the status field distinguishes beta from GA.
- **Drop** the oldest CE entry only when the newest CE goes GA (the window is *previous
  major + current major*, transiently `+1` during a beta).
- **Plus** entries are always `ci: false` — build-only (no licensed CI image is available).

**No workflow YAML change is needed when adding or dropping a version** — the
`resolve-version` job in `build-image.yml` and every other consumer reads from
`ci-metadata` at runtime.

### Build vs CI split

| Channel | `.pkg` build | Live-VM smoke CI |
| --- | --- | --- |
| CE | yes (portable Linux builder by default; FreeBSD `make package` as oracle/fallback) | yes (`ci: true`) |
| Plus | yes (same builders; build needs only the right FreeBSD-major env, no license) | no (no licensed Plus image) |

**Portable Linux builder** (`build-pkg-linux.yml` / `scripts/build-pkg-portable.py`) is the
**default**: it runs on a plain Linux runner and reproduces `make package` from the port's
Makefile + pkg-plist off-FreeBSD. **FreeBSD `make package`** (`build-pkg.yml`) is retained
as the **fidelity oracle / fallback** — selectable per entry; used when the portable
builder diverges from the real package in a way that affects install/behaviour.

### Where `.pkg` artifacts land

A tag push (`vX.Y.Z[-devel]`) triggers `release.yml`, which reads `build_matrix` and
builds one `.pkg` per entry against its `(freebsd_version, php_version)` pair. Artifacts
are attached to the **GitHub Release**, deduplicated by FreeBSD major — one `.pkg` per
distinct major covers every pfSense version on that major. A build failure surfaces in CI
but must **not** block the `ports-pr` step (the ports PR is the real distribution path).

The daily **version-tracker** (`version-tracker.yml`, `0 6 * * *`) also triggers
`build-pkg-linux.yml` for every BUILD matrix entry to validate each entry's build pair
independently of a release tag.

### What happens after a matrix edit (add a CE version)

After `supported-versions.json` is updated on `ci-metadata`, the next
`version-tracker.yml` run (daily, or dispatch) reacts automatically:

1. **`build-pkg-linux.yml`** — validates the new entry's `(freebsd_version, php_version)`
   pair by building an installable `.pkg`. One dispatch per BUILD entry.
2. **`image-refresh.yml`** — upgrade-in-place: pulls the current GHCR tag for the CE
   version, runs `pfSense-upgrade`, applies the **six-check sanity gate**, and publishes
   the new tag to GHCR **only on gate pass** (fail-closed — a bad image is never
   published). One dispatch per `ci: true` CE entry.
3. **`smoke-fanout.yml`** — runs the ADR-04 live-VM smoke suite across **all** `ci: true`
   CE images in parallel (`fail-fast: false`). The **`all-smoke-passed` AND-gate** fails
   if any single leg fails — one failed leg makes the whole gate red, no partial pass.
   Never Plus.

The tracker dispatches steps 2 and 3 only for CE entries (`ci: true`). Plus is
build-only: step 1 runs for Plus, steps 2–3 never do.

### ADR-04 §2 reconciliation (flagged — not edited here)

ADR-04 §2 describes the image-refresh strategy as: "upgrade-in-place for all bumps
(incl. major)" with the note that a **fresh manual re-seed** is the fallback when the
gate fails, and its §3 `Negative / risks` contains the wording *"re-baseline on a
MAJOR version jump"* as a conservative option. ADR-09 refines this: the automated
`image-refresh.yml` handles **all** version jumps uniformly (minor, major) — upgrade
→ sanity gate → publish on pass; manual seed only on gate failure. This supersedes
the "re-baseline on major" as a **default** (the gate is the safety net). A
reconciling edit to ADR-04 §2 is a **follow-up** and is intentionally deferred — the
two ADRs are consistent in practice (gate fail → manual seed is the same fallback),
the wording difference is documentation only.

For the future: if CI infrastructure grows, `supported-versions.json` can move to a
dedicated public `pfBlockerNG-ci-infra` repo (raw URL, no token) — a mechanical swap
in `read-version-matrix.sh`.

## Deploy / install onto a pfSense box

| Script | Use |
| --- | --- |
| [`install-from-repo.sh`](install-from-repo.sh) | **First-time install** onto a clean pfSense from `src/` — no Netgate pkg. |
| [`deploy.sh`](deploy.sh) | Fast code update of an **already-installed** pfBlockerNG: rsync `src/` + restart unbound/nginx. |
| [`setup-hooks.sh`](setup-hooks.sh) | Point git at `.githooks` (run once after cloning). |
| [`update-pfsense-stubs.py`](update-pfsense-stubs.py) | Regenerate `stubs/pfsense/` after a CE bump. |

`install-from-repo.sh` syncs the files then runs the port's real install hook —
`php -f /etc/rc.packages pfSense-pkg-pfBlockerNG-devel POST-INSTALL` (exactly what
`pkg` runs) — which registers the menu/services and runs `pfblockerng_install.inc`.
It is **all local: no internet, no Netgate pkg**, so it works even with egress blocked
(and is also handy for installing onto a local dev VM).

## Build the `.pkg`

Two ways to produce the installable FreeBSD package:

| Script | Runs on | How |
| --- | --- | --- |
| [`build-pkg.sh`](build-pkg.sh) | a FreeBSD VM (ABI-matched) | the port's real `make package` (pins `GH_TAGNAME` to the commit under test). |
| [`build-pkg-portable.py`](build-pkg-portable.py) | **Linux or macOS** (no FreeBSD) | reads the port files and emits the libpkg archive directly. |

`build-pkg-portable.py` exploits the fact that pfBlockerNG is a `NO_BUILD` port:
it executes the port's own `do-extract`/`post-extract`/`do-install` recipe and
reads its `pkg-plist` — so it tracks new files and dependency changes
automatically, rather than hardcoding pfBlockerNG's current layout — then writes
a real `.pkg` (zstd tar: `+COMPACT_MANIFEST` + `+MANIFEST` + payload). It handles
**both** ports layouts: `USE_GITHUB` (branch `pfblockerng/use-github`, source
fetched from GitHub) and the classic embedded-`files/` layout (branch `devel`).

Its output was **diffed field-by-field against a real `make package` build** (CI,
FreeBSD VM) for the same commit: metadata, file set + checksums + perms
(`INSTALL_DATA` `0644`, `INSTALL_SCRIPT` `0555`), directories, the `install`/
`deinstall` scripts, and the **dependency set** all match exactly. Deps are the
9 `RUN_DEPENDS`/`LIB_DEPENDS` **plus** the ones `USES` injects, which `make
package` also records: `USES=python` → `python<XY>`, `USES=php`+`USE_PHP=intl` →
`php<XY>` + `php<XY>-intl` (12 total). Flavored ports are resolved from the dep
spec (`net/rsync` default → `rsync`, `@python` → `rsync-python`).

Two things are **not** derivable from the port files and so are *not* expected to
match a specific build: file `mtime` (the install clock — even two real builds
differ), and a few dep **versions** that `make package` reads from the build
host's *installed binary packages* (e.g. `rsync 3.4.3` from the repo vs `3.4.1_6`
in the ports tree). Dep **names/origins** are always exact; for exact **versions**
pass `--repo-catalogue` — a path/URL to a repo `packagesite.yaml`/`.pkg`, or
`auto` to fetch FreeBSD.org's catalogue for the ABI (the same source `pkg`
installs from). Without it, versions are best-effort from the ports tree.

Version-dependent **target** facts are never guessed from the ports tree (a
single, possibly-mismatched snapshot — e.g. its `PHP_DEFAULT=8.4` need not match
the target's PHP): the ABI, Python flavor and PHP version are passed in, or asked
for if omitted — see
[`../docs/misc/pfSense_versions.md`](../docs/misc/pfSense_versions.md).
`--freebsd-version` sets the `annotations` block.

```sh
# build from a local working tree (fast dev iteration), targeting CE 2.8
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports \
    --local-src . --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out /tmp

# or build exactly what the port fetches (a commit/tag with a src/ tree), targeting Plus
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports \
    --gh-tagname <commit> --abi FreeBSD:16:amd64 --py-flavor py311 --php 8.3
```

Needs only python3 (stdlib) + a zstd encoder (`zstd` / `brew install zstd` /
`apt install zstd`); `--compression xz` needs neither. `--dry-run` prints the
plan (files, modes, deps) without writing the archive.

Full reference (every option, the fidelity comparison, troubleshooting):
[`../docs/build-pkg-portable.md`](../docs/build-pkg-portable.md).

## Image pipeline (ADR-04 smoke base)

The CI smoke harness — see [`../.ADRs/ADR_04_VM_Smoke_Tests/`](../.ADRs/ADR_04_VM_Smoke_Tests/) —
boots a real pfSense CE VM. **No Packer**: pfBlockerNG compiles nothing.

| Script | Use |
| --- | --- |
| [`image-publish.sh`](image-publish.sh) | Export a powered-off VM's ZFS zvol → compressed (zstd) qcow2 → `oras push` to GHCR by CE version. Old tags kept. |
| [`image-upgrade.sh`](image-upgrade.sh) | Pull a tag → boot a **copy** → `pfSense-upgrade` → power off → publish a new version tag. Source image untouched. |

### Driving from your machine

Both scripts run **from your laptop** against a remote Proxmox/KVM host — pass
`--proxmox [user@]host` (+ `--proxmox-port` / `--proxmox-ssh-key`, or the
`PROXMOX_SSH_HOST`/`USER`/`PORT`/`KEY` env vars). The **native** steps
(`qm`/`pvesm`/`qemu-img`/`qemu-system` — all shipped with Proxmox VE) run there
over SSH; **`oras` runs locally**, so no GHCR creds and nothing extra need
installing on Proxmox. The image is converted/compressed on Proxmox and
**streamed** over SSH. For `image-upgrade.sh` the guest is reached by **jumping
through Proxmox** (`ProxyCommand -W`), so the guest SSH key never leaves your
machine. Omit `--proxmox` to run directly on the host, as before.

```sh
# publish the seed image (driving a remote Proxmox host)
./scripts/image-publish.sh 2.8.1 --proxmox root@pve.lan

# bump a published image to a newer CE release
./scripts/image-upgrade.sh --from 2.8.1 --proxmox pve.lan --ssh-key ~/.ssh/smoke_key

# or set the host once and call bare
export PROXMOX_SSH_HOST=pve.lan PROXMOX_SSH_USER=root
./scripts/image-publish.sh 2.8.1
```

## Two install paths: CI/local vs release

| | `install-from-repo.sh` (rsync + hook) | Real `.pkg` (`pkg add`) |
| --- | --- | --- |
| Use | CI smoke + local dev | GitHub Release artifact |
| Deps | none (no VM, no internet) | FreeBSD build VM |
| Tests | runtime behaviour | the shipping artifact + the real `pkg` path |
| Catches pkg-plist drift | no (rsync copies everything) | **yes** |

For the smoke matrix, `install-from-repo.sh` is enough and faster. Build the real
`.pkg` for the GitHub Release artifact and as a higher-fidelity packaging gate.

## ABI: what actually matters for the `.pkg`

pfBlockerNG ships no compiled files, but the port (`net/pfSense-pkg-pfBlockerNG-devel`)
**run-depends on `net/libmaxminddb`** (a compiled C lib, `mmdblookup`) and does **not**
set `NO_ARCH`, so the package is ABI-tagged `FreeBSD:<major>:<arch>` (e.g.
`FreeBSD:15:amd64`).

- `pkg` gates installs on the **OS major**. A `FreeBSD:15` package on a `FreeBSD:16`
  system is **refused by default**; `pkg add -f` forces it — functionally safe here
  (no binaries of ours; the smoke image bakes pfBlockerNG's run-deps incl.
  `libmaxminddb`, so `pkg add` resolves them locally/offline).
- So **build one `.pkg` per distinct FreeBSD major**, on a FreeBSD VM pinned to that
  major. One build covers every pfSense version on that major. Rebuild only on a
  **FreeBSD-major jump** (rare; coincides with raising the minimum supported version).
- `NO_ARCH` would wildcard the **arch**, not the OS major — it does not make the
  package cross-major.
- pfSense **Plus** artifacts build fine without a Plus license (you only need the
  right FreeBSD-major build env); Plus is **build-only** — it can't be tested in CI
  (no licensed image).

### Support matrix → builds

| Target | FreeBSD major | `.pkg` build | CI smoke |
| --- | --- | --- | --- |
| Previous CE major (e.g. 2.7.x) | 14 | yes | yes |
| Current CE major (e.g. 2.8.x) | 15 | yes | yes |
| Current Plus major | 15 (today) | only if its major diverges | no (licensing) |

Artifacts = **one per distinct FreeBSD major**; CI = one image per CE minor, never Plus.
The scheduled version-tracking + release-automation design is its own ADR.
