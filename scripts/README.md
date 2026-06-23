# Dev scripts

Helper scripts for developing, deploying, and building pfBlockerNG. **Dev-only** —
none of this ships in the release archive (which contains only `src/`).

## Supported-version matrix

The single source of truth for which pfSense versions pfBlockerNG supports lives on
the **`ci-metadata` orphan branch** (its own history, off `main`/`devel`) as
`supported-versions.json`. All CI/build workflows read it at runtime.

| Script | Use |
| --- | --- |
| [`read-version-matrix.sh`](read-version-matrix.sh) | Read the matrix from `ci-metadata` and print/emit the BUILD, CI, and ROUTE matrices. |

The `read-version-matrix.sh` reader is also exposed as a composite GH Actions action
(`.github/actions/read-version-matrix/`) that emits these outputs:

- `build_matrix` — `role=build` entries (absent role treated as `build`) → one `.pkg` per
  distinct FreeBSD major. Excludes `role=route-only` (served from frozen `.pkg`, not rebuilt).
- `ci_matrix` — every `ci: true` entry (CE **and** Plus, ADR-24) within the BUILD matrix →
  the smoke-fan-out set, each carrying its resolved `image_name` (default `pfsense-ce`) + `mac`.
  Excludes `role=route-only` (same exclusion as build; no smoke leg for a frozen version).
- `python_versions` — the DISTINCT python versions derived from each BUILD entry's `py_flavor`
  (`pyN` + `MM` → `N.MM`; e.g. `py311` → `3.11`, `py39` → `3.9`), sorted + deduped.
- `php_versions` — the DISTINCT `php_version` values across the BUILD entries, sorted + deduped.

`python_versions` / `php_versions` are the **supported-only** test matrices (only the
versions the matrix actually ships): `test.yml`'s `read-matrix` job feeds them into the
pytest job (`strategy.matrix.python-version`) and the four PHP jobs
(`strategy.matrix.php-version`) via `fromJSON`, so the test gates fan out over exactly the
supported set — no hardcoded version list. The reader also has a `--print-test` mode that
prints both to stdout (mirroring `--print-build` / `--print-ci`), and a `--print-route` mode
for the ROUTE matrix (see below).

### Schema

```text
{
  "pfsense_version": "2.8",          # pfSense Major.Minor family (CE: Y.Z; Plus: YY.MM)
  "channel":         "CE",           # CE | Plus
  "freebsd_version": "15.0-RELEASE", # full FreeBSD version string (build env)
  "freebsd_major":   "15",           # FreeBSD major (ABI dedup key; artifact suffix)
  "php_version":     "8.3",          # PHP version (pinned so USES=php dep names match)
  "py_flavor":       "py311",        # Python flavor for build-pkg-linux.yml
  "arch":            "amd64",        # OPTIONAL; ABI arch (amd64 | aarch64). Omit => amd64. aarch64 = Netgate ARM appliances, Plus-only (issue #199)
  "status":          "GA",           # beta | GA
  "ci":              true,           # include in the smoke CI fan-out (CE + Plus; Plus from a private licensed image, ADR-24)
  "role":            "build"         # OPTIONAL; "build" (default, absent => build) | "route-only"
}
```

The `role` field controls how the catalog generator treats an entry:

- **Absent or `"build"`** (today's behaviour; back-compat): the entry is built, smoke-tested,
  and its `release/<varver>/<arch>/` catalog is regenerated from the fresh build each run. An
  absent `role` is always treated as `"build"` — no existing entry needs to change.
- **`"route-only"`**: the entry's release catalog is regenerated from its **last frozen `.pkg`**
  (a GitHub Release asset) and served at `release/<varver>/<arch>/` — but it is **not** rebuilt,
  not included in `--print-build` / `--print-ci` / `--print-test`, and not smoke-tested. This
  is the EOL state: a pfSense version that has left the build matrix still gets its route served
  so existing boxes can `pkg install`/`upgrade`. A truly dropped entry (no route at all) is
  simply absent from the JSON.

`--print-route` emits the **ROUTE matrix** — the BUILD matrix UNION `role=route-only` entries.
This is every entry with an actively served `release/<varver>/<arch>/` catalog. The publish
pipeline uses `--print-route` minus `--print-build` to enumerate the `route-only` entries whose
frozen `.pkg` it needs to feed to the catalog generator.

> **`ci-metadata` schema note:** the `role` field is applied by a PR against the `ci-metadata`
> orphan branch (edit `supported-versions.json` there, same as adding/dropping a version). No
> real version is currently `route-only` — the field is added to the schema so the machinery is
> in place when the min supported pfSense first advances (ADR-27 Part 2).

The reader resolves `arch` to `amd64` when omitted (or empty), so a pre-#199 matrix
builds exactly as before. The build path keys on `(freebsd_major, arch)`, so an
`aarch64` entry produces its own `FreeBSD:N:aarch64` `.pkg` alongside the amd64 one.
ARM is **Plus-only** (pfSense CE is amd64-only). Live-VM smoke stays amd64 — no ARM
image yet, so an `aarch64` entry should set `ci: false` (build + distribute only).

### Lifecycle policy

- **Add** when a beta/GA lands (curated — a human edits the JSON via a PR against
  `ci-metadata`). Add immediately on a beta so the build + CI validation starts early;
  the status field distinguishes beta from GA.
- **Drop** an entry when it should be fully removed (no catalog served). For an EOL version
  that still has users, set `role: "route-only"` instead of dropping it — the last `.pkg` keeps
  being served. Drop only when you want a clean 404 (no route).
- **Plus** entries set `ci: true` to run the smoke fan-out from a **PRIVATE, licensed** GHCR
  image (`pfsense-plus`, ADR-24); their VM identity comes from the `SMOKE_PLUS_*` secrets,
  never the matrix, and is redacted from the uploaded diagnostics.

**No workflow YAML change is needed when adding or dropping a version** — the
`resolve-version` job in `build-image.yml` and every other consumer reads from
`ci-metadata` at runtime.

### Build vs CI split

| Channel / role | `.pkg` build | Live-VM smoke CI | Catalog served |
| --- | --- | --- | --- |
| CE — `build` (default) | yes (portable Linux builder) | yes (`ci: true`) | yes |
| Plus — `build` (default) | yes (portable Linux builder; build needs only the right FreeBSD-major target, no license) | yes (`ci: true`, from a private licensed image — ADR-24) | yes |
| Any — `route-only` | **no** (frozen `.pkg` reused) | **no** | yes (from frozen `.pkg`) |

**Portable Linux builder** (`build-pkg-linux.yml` / `scripts/build-pkg-portable.py`) is the
**sole** `.pkg` builder for both CI and releases: it runs on a plain Linux runner and
reproduces `make package` from the port's Makefile + pkg-plist off-FreeBSD. Because
pfBlockerNG is a `NO_BUILD` port (nothing compiles) and `pkg add` checks a dependency is
*present* (not its version), the portable `.pkg` installs identically to a real
`make package` one — so the FreeBSD `make package` workflow was retired.

### Where `.pkg` artifacts land

A tag push (`vX.Y.Z[-devel]`) triggers `release.yml`, which reads `build_matrix` and
builds one `.pkg` per entry against its `(freebsd_version, php_version)` pair. Artifacts
are attached to the **GitHub Release**, deduplicated by FreeBSD major × arch — one `.pkg`
per distinct `(major, arch)` covers every pfSense version on that major. A build failure surfaces in CI
but must **not** block the `ports-pr` step (the ports PR is the real distribution path).

The `sync-ports-fork` job in `release.yml` also updates `PORTREVISION` on the ports fork using
`scripts/portrevision-rebuild.sh`: when the release tag carries the same PORTVERSION already
committed on the fork (a repackage/rebuild), it auto-increments `PORTREVISION` (`_1`, `_2`, …);
when the PORTVERSION changes, `PORTREVISION` is removed (pkg orders `4.0.0 < 4.0.0_1 < 4.0.1`).
The builder (`build-pkg-portable.py`) already reads and emits `_N` from the Makefile — no
builder change is needed for rebuild bumps.

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
   entries — **CE and Plus** (ADR-24) — in parallel (`fail-fast: false`). The
   **`all-smoke-passed` AND-gate** fails if any single leg fails — one failed leg makes the
   whole gate red, no partial pass.

The tracker dispatches step 1 (build) and step 3 (smoke) for every `ci: true` entry,
CE and Plus. Step 2 (`image-refresh.yml`) is **CE-only** — the Plus image is refreshed
**manually** with `scripts/image-publish.sh` (re-export + push the licensed qcow2).

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

Produce the installable FreeBSD package:

| Script | Runs on | How |
| --- | --- | --- |
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
| [`image-publish.sh`](image-publish.sh) | Export a powered-off VM's ZFS zvol → compressed (zstd) qcow2 → `oras push` to GHCR. `--type ce\|plus\|civm` derives the image ref, qcow2 filename, description + artifact-type from the type + version. Old tags kept. |
| [`publish-smoke-image.sh`](publish-smoke-image.sh) | Interactive front-end for `image-publish.sh` — asks only type, version, VM id and Proxmox host/port; derives everything else. |
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
./scripts/image-publish.sh 2.8.1 --type ce --proxmox root@pve.lan

# bump a published CE image to a newer release (CE is the default --type)
./scripts/image-upgrade.sh --from 2.8.1 --proxmox pve.lan --ssh-key ~/.ssh/smoke_key
# bump a Plus image (its 8-MAC + SMBIOS identity comes from the SMOKE_PLUS_* secrets)
./scripts/image-upgrade.sh --from 26.03 --type plus --proxmox pve.lan --ssh-key ~/.ssh/smoke_key

# or set the host once and call bare
export PROXMOX_SSH_HOST=pve.lan PROXMOX_SSH_USER=root
./scripts/image-publish.sh 2.8.1 --type ce

# …or just answer the prompts (type, version, VM id, host/port)
./scripts/publish-smoke-image.sh
```

`image-publish.sh` always takes the version as a positional argument and, for the
three real images, a `--type ce|plus|civm` that derives the image ref
(`ghcr.io/pfblockerng/<name>`), the qcow2 filename (`pfSense-CE_2.8.qcow2`, …),
the description (`pfSense CE 2.8`, …) and the OCI artifact-type. Without `--type`,
`--image`, `--description` and `--artifact-type` are all required (no defaults).

### pfSense Plus images (private — licensed)

Plus images publish with the same scripts, with these deltas:

- **Image name is all-lowercase** — an OCI/GHCR repository name MUST be lowercase:
  `ghcr.io/pfblockerng/pfsense-plus`. Tags use the Plus version scheme `YY.MM`
  (e.g. `26.03`). Select it with `--type plus` on either `image-publish.sh` or
  `image-upgrade.sh` (it derives that lowercase ref, the description and the
  artifact-type).
- **Keep the GHCR package PRIVATE.** The Plus image is Netgate-licensed; verify the
  package's visibility is private after the first push and never make it public.
  CI **pulls** this private image (never publishes it) — the smoke fan-out runs Plus
  from it (`ci: true`, ADR-24), authenticating with the `SMOKE_GHCR_*` creds.
- **MAC pinning (license-critical).** The qcow2 carries no MAC — the MACs live in the
  VM/QEMU config, so publishing is unaffected — but **every boot of the Plus image
  must reuse the Plus source-VM's full identity**: pfSense assigns interfaces by MAC,
  and the Plus license/NDI registration is keyed to **all 8 NIC MACs + the SMBIOS uuid**.
  `boot_vm.sh` and `image-upgrade.sh` take the MACs from `SMOKE_VM_MAC` (a NEWLINE-separated
  8-MAC list, one per NIC net0..net7) and the uuid from `SMOKE_VM_SMBIOS_UUID`; CE defaults
  to the committed public list (net0 `BC:24:11:37:9C:AC`). For **Plus**, `image-upgrade.sh
  --type plus` takes the identity from the `SMOKE_PLUS_MAC` (8-MAC list) + `SMOKE_PLUS_SMBIOS_UUID`
  secrets and **REFUSES to boot unless the effective MAC set and uuid equal those secrets**
  (a wrong NDI can burn the license). In CI it is **never** hardcoded or in the matrix — the
  smoke/UI workflows set `SMOKE_VM_MAC`/`SMOKE_VM_SMBIOS_UUID` from the `SMOKE_PLUS_*` secrets
  and redact them from diagnostics (ADR-24).
- With `--type plus` the description, artifact-type and stored qcow2 filename
  (`pfSense-Plus_<tag>.qcow2`) are all labelled for Plus automatically — no `--out`
  override needed. `image-publish.sh` and `image-upgrade.sh` share `scripts/image-lib.sh`,
  so an upgrade-and-publish produces a **byte-identical** artifact to `image-publish.sh
  --type plus <tag>` run by hand.

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
  right FreeBSD-major build env); Plus is also **smoke-tested in CI** from a private,
  licensed GHCR image (ADR-24).

### Support matrix → builds

| Target | FreeBSD major | `.pkg` build | CI smoke |
| --- | --- | --- | --- |
| Previous CE major (e.g. 2.7.x) | 14 | yes | yes |
| Current CE major (e.g. 2.8.x) | 15 | yes | yes |
| Current Plus major | 16 (today) | only if its major diverges | yes (private licensed image) |

Artifacts = **one per distinct FreeBSD major**; CI smoke = every `ci: true` image, CE **and** Plus.
The scheduled version-tracking + release-automation design is its own ADR.

## Catalog generator — release retention and rollback

`build-repo-portable.py --build-matrix` generates the self-hosted `pkg` repository tree
(ADR-17). By default it keeps only the **latest** release of each channel per
`(version, arch)` — identical to the pre-ADR-27 behaviour. Three flags enable rollback:

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `--release-keep-devel N` | `1` (latest-only) | Retain the N newest devel releases per `(version, arch)` in the `release/` catalog. Set `>1` to list older versions so users can pin to them. |
| `--release-keep-stable M` | `1` (latest-only) | Same for the stable channel. |
| `--release-extra-pkgs PATH` | (none) | Pre-built older-release `.pkg` to fold into the release pool alongside the fresh build (repeatable — pass one per file). The generator prunes the merged pool to `N` / `M` after folding. |

`--release-keep-devel 0` / `--release-keep-stable 0` is the **unbounded** sentinel (keep all).

### How the publish pipeline uses these flags

`pfBlockerNG/pkg`'s `publish.yml` passes:

- one `--release-extra-pkgs <path>` per older `.pkg` it downloaded from GitHub Releases
  (pre-release assets → devel pool; full-release assets → stable pool), and
- `--release-keep-devel N` / `--release-keep-stable M` at the configured retention depth
  (default 10 when retention is enabled; overridable via `workflow_dispatch` inputs).

The generator is the backstop: even if `publish.yml` passes more `.pkg` files than the
retention depth, it prunes to the newest N/M before writing the catalog.

### Rolling back a release or devel install

When the retention depth is `>1`, the catalog lists multiple versions. A user can pin:

```sh
# Roll back to a specific devel build (-f forces the downgrade over a newer installed build)
pkg install -f pfSense-pkg-pfBlockerNG-devel-3.2.15

# Roll back to a specific stable build
pkg install -f pfSense-pkg-pfBlockerNG-3.2.14
```

`-f` is required: `pkg install` never downgrades over a newer already-installed build, so the
pin is a no-op without it (deps still resolve from the catalog, unlike `pkg add <url>`).
`pkg install <name>` (no version) still resolves the **highest** listed version
(newest-wins, `pkg` version ordering). Rollback is available **only for the N/M most recent
releases** — releases older than the retention window are absent from the catalog.

> **Config-schema note:** rolling back across a schema-changing release may leave the stored
> `config.xml` in a format the older code cannot read. Test first in a non-production VM.
