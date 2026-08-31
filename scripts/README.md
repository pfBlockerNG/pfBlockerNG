# Dev scripts

Helper scripts for developing, deploying, and building pfBlockerNG. **Dev-only** —
none of this ships in the release archive (which contains only `src/`).

## Agent configuration

| Script | Use |
| --- | --- |
| [`agent/check-agent-config-parity.sh`](agent/check-agent-config-parity.sh) | Verify bidirectional Claude/Codex skill and workflow parity, resolvable adapter references, and Codex role models against `.agents/model-tiers.conf`. The pre-commit hook runs it for staged agent-configuration changes; shellspec pins the real inventory for CI. |

## Release channel contract

Release authoring follows issue #2140. All channels publish the exact package identity
`pfSense-pkg-pfBlockerNG`; channel is metadata carried in each distinct release's immutable
`pfBlockerNG-Release-Channel: <stable|testing|edge>` tag trailer, never a package-name suffix.
The tag and trailer must agree with the deterministic rule below. Every operation uses a
pinned source SHA. For prereleases, `Z == 0` selects Edge and `Z != 0` selects Testing.

- Stable uses `vX.Y.Z` / `X.Y.Z`.
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` with the exact package version when
  `Z != 0`.
- Edge uses the same prerelease grammar when `Z == 0`.
- Nightly is an independent untagged snapshot from a pinned source SHA with no GitHub Release or release
  notes. Every invocation builds version `YYYYMMDDHHMMSS.<7-character source SHA>` using UTC.
  Failed runs stay failed; rerun by dispatching another Nightly. No durable state or counter exists.
  Identity includes source SHA, FreeBSD-ports SHA, and matrix/dependency digest.

Keep the Ports recipe static: no routine version commit, no target final, and no PORTEPOCH.
Timestamped Nightly versions intentionally outrank semantic releases; reverse movement requires an
explicit repo-qualified downgrade. `scripts/release-version.sh` remains the parser; callers
pass channel context, and the parser rejects any context that disagrees with the patch-zero
Edge / nonzero-patch Testing rule.

## Supported-version matrix

The single source of truth for which pfSense versions pfBlockerNG supports lives on
the **`ci-metadata` orphan branch** (its own history, off `main`/`devel`) as
`supported-versions.json`. All CI/build workflows read it at runtime.

The file's canonical on-disk format is `jq .` output (normalized in PR #1835): the
reconcile's matrix auto-PRs rewrite it through `jq`, so hand edits should be piped
through `jq .` before committing or the next auto-PR carries formatting churn.

| Script | Use |
| --- | --- |
| [`read-version-matrix.sh`](read-version-matrix.sh) | Read the matrix from `ci-metadata` and print/emit the BUILD, CI, and ROUTE matrices. |

The `read-version-matrix.sh` reader is also exposed as a composite GH Actions action
(`.github/actions/read-version-matrix/`) that emits these outputs:

- `build_matrix` — `role=build` entries (absent role treated as `build`) → one `.pkg` per
  exact `(freebsd_major, php_version, py_flavor)` runtime tuple (issue #2926). Excludes `role=route-only` (served from frozen `.pkg`, not rebuilt).
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
  "freebsd_major":   "15",           # FreeBSD-major component of the BUILD tuple
  "php_version":     "8.3",          # PHP version (pinned so USES=php dep names match)
  "py_flavor":       "py311",        # Python flavor for build-pkg-linux.yml
  "extra_pkgs":      [],             # OPTIONAL; port origins to build+fold in as deps (issue #1806, e.g. ["textproc/py-charset-normalizer"] for CE). Omit => []
  "status":          "active",       # beta | active (legacy alias: GA) — the reconcile flip PR writes "active"
  "ci":              true,           # include in the smoke CI fan-out (CE + Plus; Plus from a private licensed image, ADR-24)
  "role":            "build"         # OPTIONAL; "build" (default, absent => build) | "route-only"
}
```

Served catalogs live at `<channel>/<varver>/`, where `<channel>` is `stable`,
`testing`, `edge`, or `nightly`; this distribution channel is distinct from the
matrix row's CE/Plus `channel` field above.

The `role` field controls how the catalog generator treats an entry:

- **Absent or `"build"`** (today's behaviour; back-compat): the entry is built, smoke-tested,
  and its catalog is regenerated from the fresh build each run and published to the applicable
  `<channel>/<varver>/` paths. An absent `role` is always treated as `"build"` — no existing
  entry needs to change.
- **`"route-only"`**: the entry's release catalog is regenerated from its **last frozen `.pkg`**
  (a GitHub Release asset) and published to the applicable `<channel>/<varver>/` paths — but it is
  **not** rebuilt,
  not included in `--print-build` / `--print-ci` / `--print-test`, and not smoke-tested. This
  is the EOL state: a pfSense version that has left the build matrix still gets its route served
  so existing boxes can `pkg install`/`upgrade`. A truly dropped entry (no route at all) is
  simply absent from the JSON.

Route-only starts with release assets produced by issue #1806. Older tags contain
concrete-ABI `.pkg` files, but the current catalog is arch-less and cannot serve them safely.
Those pre-#1806 tags are **unservable as route-only**: `build-repo-portable.py` rejects the
asset explicitly instead of emitting a single-architecture catalog. Drop the matrix entry
when no post-#1806 wildcard-ABI asset exists; do not repackage the frozen tag at EOL.

> **KNOWN GAP / owner call:** a post-#1806 wildcard-ABI frozen `.pkg` may still declare
> dependencies represented by the family's `extra_pkgs`. Route-only catalogs do not fold in
> `--dep-pkgs`; whether they must do so remains undecided in issue #1828.

`--print-route` emits the **ROUTE matrix** — build-role-eligible entries (one row per version,
never deduped) UNION `role=route-only` entries. This is every entry with an actively served
`<channel>/<varver>/` catalog. The publish pipeline uses `--print-route` minus `--print-build`
to enumerate the `route-only` entries whose frozen `.pkg` it needs to feed to the catalog
generator.

> **`ci-metadata` schema note:** the `role` field is applied by a PR against the `ci-metadata`
> orphan branch (edit `supported-versions.json` there, same as adding/dropping a version). No
> real version is currently `route-only` — the field is added to the schema so the machinery is
> in place when the min supported pfSense first advances (ADR-27 Part 2).

**There is no `arch` field (issue #1806 — supersedes issue #199's ARM/aarch64 plan).** Every
`pfSense-pkg-pfBlockerNG` port is `NO_ARCH`: one wildcard-ABI `.pkg` build serves every CPU
arch of a FreeBSD major, so the catalog is arch-less and the BUILD matrix (`--print-build`)
dedupes to **one row per exact runtime tuple** `(freebsd_major, php_version, py_flavor)`
(issue #2926) — same-major rows with a differing php/py are DISTINCT build targets and stay
separate rows, and `extra_pkgs` unions across the merged rows. The CI matrix (`--print-ci`)
and ROUTE matrix (`--print-route`)
stay **one row per version** (never deduped — a smoke/UI leg needs every version's own
identity). A stray `arch` key on an old row is tolerated-ignored, never resurrected as a
default.

### Lifecycle policy

- **Add** via a PR against `ci-metadata` — hand-written, or the daily reconcile's
  auto-PR (issue #1823: when the booted image's `pfSense-repoc -p` lists a branch whose
  family the matrix lacks, the reconcile opens a PR adding the entry with the observed
  status and `ci: false`; verify the seeded FreeBSD fields, then merge — the next
  reconcile run builds and publishes the image; the reconcile also PRs the beta→GA
  status flip when it sees a final build). The matrix is the desired state; the box is
  the source of truth.
- **Drop** an entry when it should be fully removed (no catalog served). For an EOL version
  that still has users, set `role: "route-only"` only when its last tag has a post-#1806
  wildcard-ABI `.pkg`; otherwise it is unservable and must be dropped. Drop also when you
  intentionally want a clean 404 (no route).
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
| Any — `route-only` | **no** (post-#1806 frozen `.pkg` reused) | **no** | yes (wildcard-ABI asset required) |

**Portable Linux builder** (`build-pkg-linux.yml` / `scripts/build-pkg-portable.py`) is the
**sole** `.pkg` builder for both CI and releases: it runs on a plain Linux runner and
reproduces `make package` from the port's Makefile + pkg-plist off-FreeBSD. Because
pfBlockerNG is a `NO_BUILD` port (nothing compiles) and `pkg add` checks a dependency is
*present* (not its version), the portable `.pkg` installs identically to a real
`make package` one — so the FreeBSD `make package` workflow was retired.

### Where `.pkg` artifacts land

A Stable, Testing, or Edge release dispatch triggers `release.yml`, which reads `release_matrix` —
one row per build-role Variant/pfSense version — and builds one `.pkg` per row against its
`(freebsd_version, php_version)` pair. Row-qualified artifacts are attached to the **GitHub
Release** as `pfSense-pkg-pfBlockerNG-<version>-<Variant>-<pfsense_version>.pkg`; each archive's
bytes and native manifest stay unchanged. A build failure blocks the tag, Release, and
`sync-ports-fork` gates.

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
2. **`image-refresh.yml`** (`Upgrade pfSense smoke images`) — the generation engine of
   the daily reconcile loop (issue #1823). The reconcile job in `version-tracker.yml`
   boots the newest published image(s) per channel, reads the truth from the box
   (`/etc/version`, `pfSense-repoc -p`, `pfSense-upgrade -c` as the second source), and
   dispatches each planned move as a fully-specified `direct_leg` (patch republish under
   the same floating tag, first build of a merged beta entry, GA-final refresh). Each
   leg runs `scripts/image-upgrade.sh --type ce|plus` (with `--branch <name>` for branch
   switches — every pfSense version move is one), applies the health gate, and publishes
   to GHCR **only on gate pass** (fail-closed). A `self_refresh=true` dispatch is the
   manual operator re-publish; a bare dispatch plans nothing. Published images carry the
   full `/etc/version` as the `io.github.pfblockerng.pfsense-version` OCI annotation
   (provenance).
3. **`smoke.yml`** — runs the ADR-04 live-VM smoke suite across **all** `ci: true`
   entries — **CE and Plus** (ADR-24) — in parallel (`fail-fast: false`). The
   **`all-smoke-passed` AND-gate** fails if any single leg fails — one failed leg makes the
   whole gate red, no partial pass.

The tracker's react job dispatches step 1 (build) and step 3 (smoke); step 2 legs are
dispatched per-action by the reconcile job (`direct_leg`). The Plus leg takes its
license/NDI identity from the `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` secrets.
`scripts/image-publish.sh` remains the manual fallback (gate failure, or the initial
Plus image seed).

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
| [`setup-hooks.sh`](setup-hooks.sh) | Mandatory post-clone setup: install/patch Graphify, point git at `.githooks`, and initialize CodeGraph when installed. |
| [`agent/ensure-graphify.sh`](agent/ensure-graphify.sh) | Shared Graphify install/upgrade plus temporary `.inc=php` patch entry point. |
| [`agent/resolve-graphify.sh`](agent/resolve-graphify.sh) | Prefer the PATH-selected Graphify launcher, otherwise resolve uv's direct launcher and validate its owning Python without trusting arbitrary wrappers. |
| [`agent/patch-graphify.sh`](agent/patch-graphify.sh) | Idempotently apply Graphify-Labs/graphify#3075; fails closed when the selected launcher cannot identify its package. |
| [`agent/ensure-codegraph.sh`](agent/ensure-codegraph.sh) | Idempotently create an exact-root CodeGraph index for one checkout. |
| [`git-no-docs.sh`](git-no-docs.sh) | Local doc-free history views: run a read-only git command (default `log -p`) with the `.gitattributes` `linguist-documentation` trees (`legacy/ADRs/`, `docs/`) excluded from its pathspec. |
| [`update-pfsense-stubs.py`](update-pfsense-stubs.py) | Regenerate `stubs/pfsense/` after a CE bump. |

`install-from-repo.sh` syncs the files then runs the selected static recipe's real
install hook — for example
`php -f /etc/rc.packages pfSense-pkg-pfBlockerNG-testing POST-INSTALL` (exactly what
`pkg` runs) — which registers the menu/services and runs `pfblockerng_install.inc`.
It is **all local: no internet, no Netgate pkg**, so it works even with egress blocked
(and is also handy for installing onto a local dev VM).

## Build the `.pkg`

Produce the installable FreeBSD package:

| Script | Runs on | How |
| --- | --- | --- |
| [`build-pkg-portable.py`](build-pkg-portable.py) | **Linux or macOS** (no FreeBSD) | reads the port files and emits the libpkg archive directly. |
| [`build-dep-pkg-portable.py`](build-dep-pkg-portable.py) | **Linux or macOS** (no FreeBSD) | builds a pure-wheel dependency from its Ports-pinned sdist with the locked Python toolchain. |

`build-pkg-portable.py` exploits the fact that pfBlockerNG is a `NO_BUILD` port:
it executes the port's own `do-extract`/`post-extract`/`do-install` recipe and
reads its `pkg-plist` — so it tracks new files and dependency changes
automatically, rather than hardcoding pfBlockerNG's current layout — then writes
a real `.pkg` (zstd tar: `+COMPACT_MANIFEST` + `+MANIFEST` + payload). It handles
**both** source layouts used by the four static native recipes: `USE_GITHUB`
(recipe-defined source ref, fetched from GitHub) and embedded `files/` content.

Native mode preserves the recipe identity: Stable, Testing, Edge, and Nightly
emit `pfSense-pkg-pfBlockerNG`, `pfSense-pkg-pfBlockerNG-testing`,
`pfSense-pkg-pfBlockerNG-edge`, and `pfSense-pkg-pfBlockerNG-nightly`. Project
mode takes `--build-record JSON|PATH` plus `--pkgversion` and always emits the
canonical `pfSense-pkg-pfBlockerNG`. The normalized record carries channel,
release line, classification, source tag/SHA, canonical version, native and
emitted identities, matrix row, Ports SHA, route, `SOURCE_DATE_EPOCH`, the
dependency-builder toolchain/`uv.lock` identity, and a deterministic input
digest. Clean Git source/Ports attestations and the full post-write
identity/payload validation are mandatory.
Project mode requires a `USE_GITHUB` recipe plus a clean local source checkout; native-only annotation,
catalogue, and FreeBSD-version overrides are rejected. Output uses an atomic
no-clobber boundary: identical bytes are reusable, while divergent bytes or a
symlink/non-regular destination fail without replacing prior output. Nightly
versions are explicit `YYYYMMDDHHMMSS.<7-character source SHA>`. The builder publishes nothing and does
not start workflow/catalogue jobs.

`build-dep-pkg-portable.py` requires `uv sync --locked --only-group
dep-pkg-build`, exact `--ports-sha`, and a source-derived
`--source-date-epoch`. It disables PEP-517 build isolation/network resolution,
rejects interpreter/backend drift and non-pure wheel metadata, normalizes
staged member mtimes and ordering, and records origin/version/distfile
SHA/size, ABI, epoch, and toolchain in `pfb_dep_build_record`.

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
# build from a local working tree (fast dev iteration), targeting CE 2.8/testing
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports \
    --channel testing --local-src . --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out /tmp

# or build exactly what the port fetches (a commit/tag with a src/ tree), targeting Plus
# (flag values from the target version's ci-metadata matrix entry)
python3 scripts/build-pkg-portable.py --ports ../FreeBSD-ports \
    --gh-tagname <commit> --abi FreeBSD:16:amd64 --py-flavor py311 --php 8.5
```

Needs only python3 (stdlib) + a zstd encoder (`zstd` / `brew install zstd` /
`apt install zstd`); `--compression xz` needs neither. `--dry-run` prints the
plan (files, modes, deps) without writing the archive.

Full reference (every option, the fidelity comparison, troubleshooting):
[`../docs/build-pkg-portable.md`](../docs/build-pkg-portable.md).

## Image pipeline (ADR-04 smoke base)

The CI smoke harness — see [`../legacy/ADRs/ADR_04_VM_Smoke_Tests/`](../legacy/ADRs/ADR_04_VM_Smoke_Tests/) —
boots a real pfSense CE VM. **No Packer**: pfBlockerNG compiles nothing.

| Script | Use |
| --- | --- |
| [`image-publish.sh`](image-publish.sh) | Export a powered-off VM's ZFS zvol → compressed (zstd) qcow2 → `oras push` to GHCR. `--type ce\|plus\|civm` derives the image ref, qcow2 filename, description + artifact-type from the type + version. Old tags kept. |
| [`publish-smoke-image.sh`](publish-smoke-image.sh) | Interactive front-end for `image-publish.sh` — asks only type, version, VM id and Proxmox host/port; derives everything else. |
| [`image-upgrade.sh`](image-upgrade.sh) | Pull a tag → boot a **copy** → `pfSense-upgrade` → power off → publish a new version tag. Source image untouched. |
| [`box-facts.sh`](box-facts.sh) | Daily reconcile fact gatherer (issue #1823): boot a published smoke image as a throwaway overlay and record `/etc/version`, `pfSense-repoc -p`, and `pfSense-upgrade -c` verbatim. |
| [`reconcile-plan.py`](reconcile-plan.py) | Daily reconcile planner (issue #1823): pure box-facts + matrix → action list (republish / publish_new / matrix PRs). |

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

## CI / local-smoke shared scripts (ADR-47)

Workflows are thin dispatch wrappers — all step logic lives in shared scripts that run
identically locally and in CI.

| Script | Use |
| --- | --- |
| [`resolve-legs.sh`](resolve-legs.sh) | Seven subcommands: `legs` (scope ladder + THREE-WAY jq + `-k` derivation), `image-ref`, `digest`, `pull`, `exact-image-name`, `vm-identity`, `scrub`. Called from `smoke.yml`, `smoke-single.yml`, `ui-tests.yml`. |
| [`parity-guard.sh`](parity-guard.sh) | Lint workflows for build-parity (Rules 1-3: build-leg.sh) and test-parity (Rules 4-5: run-smoke.sh) violations. Run in CI (test.yml shell-tests job). |
| [`git-env-scrub-guard.sh`](git-env-scrub-guard.sh) | Meta-assertion: no raw `unset GIT_DIR` outside the lib; every git-using spec calls `scrub_git_env`. |
| [`lib/git-env-scrub.sh`](lib/git-env-scrub.sh) | Sourceable lib exporting `pfb_scrub_git_env()` — unsets the six GIT_\* vars the pre-commit hook exports. |
| [`impacted-tests.sh`](impacted-tests.sh) | Derive a pytest `-k` expression from the test modules changed vs a base ref. |
| [`shard-modules.sh`](shard-modules.sh) | Module splitter dividing a test dir's direct-child `test_*.py` modules into N shards for the live-VM smoke suite's module-level parallelism (issue #797) — duration-balanced greedy LPT when the dir has a `module-durations.txt` table, else deterministic round-robin (issue #816). |
| [`module-durations.sh`](module-durations.sh) | Builds the per-module duration table (`tests/smoke/module-durations.txt`) from pytest `--durations=0` CI log output, so the shard splitter can balance shards by measured load (issue #816). |
| [`select-box.sh`](select-box.sh) | Lease an LXC smoke box; `--print-id` mints a deterministic RUN_ID without a real lease. |
| [`smoke-on-box.sh`](smoke-on-box.sh) | On-box smoke entrypoint: checkout, ports update, image pull, build, run. |
| [`run-smoke.sh`](run-smoke.sh) | Canonical pytest argv emitter for the smoke suite (same script CI and local use). |
| [`build-leg.sh`](build-leg.sh) | Build a `.pkg` for a specific leg (ABI, channel, version). |
| [`nightly-pkgversion.sh`](nightly-pkgversion.sh) | `YYYYMMDDHHMMSS.<7-sha>` for `--channel nightly`. Called from `nightly.yml`, `smoke-single.yml`, and `smoke-on-box.sh` (from the just-checked-out HEAD). `local-smoke.sh` forwards an explicit override only — it does not derive from the orchestrator clone, which can diverge from `--git-remote` (issue #2754). |
| [`sparse-clone-ports.sh`](sparse-clone-ports.sh) | Blobless sparse clone of FreeBSD-ports to the needed port dirs only. |

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

pfBlockerNG ships no compiled files of its own — every `net/pfSense-pkg-pfBlockerNG*`
port sets `NO_ARCH` (issue #1806). A `RUN_DEPENDS` on a compiled C lib (`net/libmaxminddb`,
`mmdblookup`) doesn't change that: `NO_ARCH` describes THIS port's own payload
(scripts/PHP/Python, no arch-specific files), and `pkg` resolves that dependency
separately against the box's own arch. A real package's manifest ABI is therefore
CPU-wildcarded — `FreeBSD:<major>:*` (e.g. `FreeBSD:15:*`) — never a concrete
`FreeBSD:<major>:<arch>`.

- `pkg` gates installs on the **OS major**; the wildcarded CPU segment matches every
  arch of that major. A `FreeBSD:15` package on a `FreeBSD:16` system is **refused by
  default**; `pkg add -f` forces it — functionally safe here (no binaries of ours; the
  smoke image bakes pfBlockerNG's run-deps incl. `libmaxminddb`, so `pkg add` resolves
  them locally/offline).
- So **build one `.pkg` per exact runtime tuple** `(freebsd_major, php_version,
  py_flavor)` (issue #2926) — `build-pkg-portable.py --abi
  FreeBSD:<major>:<cpu>` on ANY host (no FreeBSD VM needed; the portable Linux builder
  is the sole builder). The `<cpu>` segment is an INERT placeholder for a NO_ARCH port
  (the builder wildcards the stamp regardless of what's given); one build covers every
  arch and every pfSense edition/version sharing that tuple. Rows on the same major with
  different PHP or Python values require distinct builds; identical tuples share one.
- The self-hosted catalog (ADR-17) is **arch-less**: `<channel>/<varver>/` holds the
  catalog directly (no arch subdirectory) — one varver directory serves every arch of
  its FreeBSD major.
- pfSense **Plus** artifacts build fine without a Plus license (you only need the
  right FreeBSD-major build env); Plus is also **smoke-tested in CI** from a private,
  licensed GHCR image (ADR-24).

### Support matrix → builds

| Target | FreeBSD major | `.pkg` build | CI smoke |
| --- | --- | --- | --- |
| Previous CE major (e.g. 2.7.x) | 14 | yes | yes |
| Current CE major (e.g. 2.8.x) | 15 | yes | yes |
| Current Plus major | 16 (today) | shared only when its exact runtime tuple matches | yes (private licensed image) |

Artifacts = **one per exact `(freebsd_major, php_version, py_flavor)` runtime tuple**; CI smoke = every `ci: true` image, CE **and** Plus.
The scheduled version-tracking + release-automation design is its own ADR.

## Catalog generator — release retention

`build-repo-portable.py --build-matrix` generates the self-hosted `pkg` repository tree
(ADR-17; arch-less catalogs, issue #1806). By default it keeps only the **latest** release
of each channel per varver, plus the newest package of each major/minor line (line pins,
below) — the window itself is identical to the pre-ADR-27 behaviour. Three flags control
retention:

Its default source-build seam accepts repeatable `--build-record PATH` values,
matches each record's channel route and complete matrix row exactly, and forwards
that record, its variant, and canonical package version to
`build-pkg-portable.py`. Missing, duplicate, or mismatched records fail closed;
an injected custom builder remains responsible for its own inputs.

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `--release-keep-testing N` | `1` (latest-only) | Retain the N newest Testing releases per varver in the `release/` catalog. |
| `--release-keep-stable M` | `1` (latest-only) | Same for the stable channel. |
| `--release-extra-pkgs PATH` | (none) | Pre-built older-release `.pkg` to fold into the release pool alongside the fresh build (repeatable — pass one per file). The generator prunes the merged pool to `N` / `M` after folding. |

`--release-keep-testing 0` / `--release-keep-stable 0` is the **unbounded** sentinel (keep all).

**Line pins are retained on top of the N/M window** (issue #1676): the newest package of
every pfBlockerNG major/minor line survives per channel even when it falls outside the
rolling window, so an aged-out release stays installable by exact version. A catalog can
therefore hold more than `N` + `M` packages — budget for one extra per aged-out line per
channel. Pins are per channel, so a Testing pin never satisfies or evicts a stable one; the
`0` sentinel and the nightly subtree are unaffected.

### How the publish pipeline uses these flags

`pfBlockerNG/pkg`'s `publish.yml` passes:

- one `--release-extra-pkgs <path>` per older `.pkg` it downloaded from GitHub Releases
  (pre-release assets → Testing pool; full-release assets → stable pool), and
- `--release-keep-testing N` / `--release-keep-stable M` at the configured retention depth
  (default 10 when retention is enabled; overridable via `workflow_dispatch` inputs).

The generator is the backstop: even if `publish.yml` passes more `.pkg` files than the
retention depth, it prunes to the newest N/M before writing the catalog.

### Retained-version boundary

`pkg install <name>` (no version) still resolves the **highest** listed version
(newest-wins, `pkg` version ordering). Versions older than the N/M retention window are absent
from the catalog unless retained as a line pin.

> **Compatibility note:** retention is artifact availability, not supported downgrade. Older
> packages may not understand current state; configuration or enforcement may fail. Restore a
> pre-upgrade configuration backup or
> reinstall the current package and continue forward if recovery is needed.
