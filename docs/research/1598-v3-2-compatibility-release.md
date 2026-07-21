# v3.2 compatibility-release and dual-channel publication mechanics

Issue: [Research v3.2 compatibility-release and dual-channel publication mechanics](https://github.com/pfBlockerNG/pfBlockerNG/issues/1598)

Research date: 2026-07-21

## Conclusion

Publish one frozen v3.2 compatibility source line and build it twice, once as
`pfSense-pkg-pfBlockerNG` and once as `pfSense-pkg-pfBlockerNG-devel`. Keep this outside the
normal `main`/`devel` release workflow, store all matrix-specific packages in one immutable
GitHub Release, and publish them in a separate `compat/` package catalog. The v4 downgrade
action should select that repository explicitly with `pkg install -r`; it must not rely on an
explicit lower version in the normal release catalog.

This preserves the existing meaning of `main`, `devel`, their tags, the two normal package
names, and the `release/` catalog. It also gives v4 a durable, exact v3.2 target after newer v4
stable and prerelease artifacts exist.

## Exact source baselines

The repository has two imported v3.2 tags:

| Target | Baseline | Commit | Evidence |
| --- | --- | --- | --- |
| Stable | `v3.2.15` | `0846aa7c090f96e62b5322d7dea70e80b1f31b63` | Root commit; `info.xml` registers `pfBlockerNG`. |
| Devel | `v3.2.16` | `0676cd1c7ed79d49a0644070151c4fffa39ea409` | One child of `v3.2.15`; `info.xml` registers `pfBlockerNG-devel`. |

The sole `v3.2.15..v3.2.16` commit changes seven paths. Besides the package-registration
rename, it contains real DNSBL/Python fixes and tests. Therefore the compatibility source
should start from `v3.2.16`, not independently patch `v3.2.15` and `v3.2.16`. Both package
names can then use the same corrected source and settings schema; package identity is injected
at build time.

The current ports recipes expect production files below `src/`, while both imported v3 tags
use appliance-root paths. The compatibility branch must first apply the mechanical tree move
represented by [`815ef64c`](https://github.com/pfBlockerNG/pfBlockerNG/commit/815ef64c97570e569baabeb484d829e5c7380af5), then parameterize `info.xml` as represented by
[`513cd572`](https://github.com/pfBlockerNG/pfBlockerNG/commit/513cd5721b7e2f5217286029793d76a1fcc2d3f1).
Do not use either commit as a behavioral baseline: they are packaging adaptations only.

Evidence:

```text
$ git show --no-patch --format='%H %P %s' v3.2.15 v3.2.16
0846aa7c090f96e62b5322d7dea70e80b1f31b63  pfBlockerNG 3.2.15 - initial commit
0676cd1c7ed79d49a0644070151c4fffa39ea409 0846aa7c... pfBlockerNG-devel 3.2.16

$ git rev-list --count v3.2.15..v3.2.16
1

$ git diff --name-status v3.2.15 v3.2.16
M etc/inc/priv/pfblockerng.priv.inc
M usr/local/pkg/pfblockerng/pfb_unbound.py
M usr/local/pkg/pfblockerng/pfblockerng.inc
A usr/local/pkg/pfblockerng/tests/__init__.py
A usr/local/pkg/pfblockerng/tests/conftest.py
A usr/local/pkg/pfblockerng/tests/test_pfb_unbound.py
R085 usr/local/share/pfSense-pkg-pfBlockerNG/info.xml
     usr/local/share/pfSense-pkg-pfBlockerNG-devel/info.xml
```

## Minimal v3.2 backport

Use a dedicated protected maintenance branch, provisionally `compat/3.2`, rooted at
`v3.2.16`. Its production diff should contain only:

1. The `src/` layout and `%%PKGNAME%%` `info.xml` parameterization needed by current package
   tooling.
2. The Software page, its privilege entry, and the one-line tab insertion on v3.2 pages.
3. Only the package/version/provenance helpers used by that page. Do not transplant the full
   v4 helper block or unrelated v4 migrations.
4. The v3 post-install restore consumer defined by the backup/restore specification.
5. Tests for both package identities, page rendering/actions, and the restore path.

The current Software page deliberately delegates package replacement to pfSense's Package
Manager so the page is not destroyed while hosting its own long-running operation. Preserve
that architecture. The original v4 page landed in
[`8ea77385`](https://github.com/pfBlockerNG/pfBlockerNG/commit/8ea77385874b5c874cb0b67c9de85a69f21c7d26),
but it is not a safe cherry-pick onto v3.2: it spans 21 files and depends on later v4 config,
provenance, update-cache, privilege, and rendering work. Port its final behavior at the v3.2
seams instead.

The package recipe must include the new page in both `do-install` and `pkg-plist`. At
FreeBSD-ports commit
[`0a12ea26`](https://github.com/pfBlockerNG/FreeBSD-ports/commit/0a12ea264e673ae3eb41bdfc3077e10ba55e7f67),
the stable port is still `3.2.15_2` and does **not** list `pfblockerng_software.php`; the devel
port is `4.0.0.alpha.21` and does. A compatibility build must not temporarily repoint the live
devel port away from v4. Use two compatibility recipe directories (or one generated template)
whose `PORTNAME` values remain the canonical stable/devel package names and whose origins remain
`net/pfSense-pkg-pfBlockerNG` and `net/pfSense-pkg-pfBlockerNG-devel`.

## Version, tag, and branch constraints

The normal release contract is intentionally narrow:

- `vX.Y.Z` is Stable from `main`.
- `vX.Y.Z.alpha.N`, `.beta.N`, or `.rc.N` is Devel from `devel`.
- `.github/workflows/release.yml` maps the tag class back to exactly `main` or `devel`, then
  updates the matching live port.

Sources: [`scripts/release-version.sh`](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb28386825d01dcdfe21aff2d9a93ee62c/scripts/release-version.sh) and
[`release.yml`](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb28386825d01dcdfe21aff2d9a93ee62c/.github/workflows/release.yml).

Do not weaken that classifier or make `main`/`devel` point back to v3. Use a small compatibility
workflow with these inputs fixed in source:

```text
source ref:     compat/3.2
release tag:   compat-v3.2.17
package version: 3.2.17
channels built: stable, devel
GitHub latest: false
```

`3.2.17` sorts above Stable `3.2.15_2` and Devel `3.2.16`, but below v4. The namespaced Git tag
is deliberately outside `release-version.sh`, so an ordinary v4 release can neither select nor
mutate this line accidentally. The package version remains a normal v3.2 patch release; the tag
namespace records that this is the special dual-package publication path.

The compatibility workflow should reuse the current matrix reader and portable builder, but
build both package identities from the same checked-out source and explicit `--pkgversion
3.2.17`. It should create a draft Release, attach the source archive and every expected `.pkg`,
verify the complete matrix, then publish. That ordering is required because this repository uses
immutable Releases: after publication, tags and assets cannot be changed. GitHub's primary
documentation confirms those protections and recommends draft → attach → publish:
[Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

The 2026-07-21 build matrix requires three artifacts per package name:

```text
CE 2.8       FreeBSD:15:amd64  PHP 8.3  py311
Plus 26.03   FreeBSD:16:amd64  PHP 8.5  py311
Plus 26.03   FreeBSD:16:aarch64 PHP 8.5 py311
```

Thus the first compatibility Release needs six `.pkg` assets plus its source archive. A future
matrix entry cannot be appended to that immutable Release; publish a new v3.2 compatibility
patch and advance the pinned compatibility tag instead.

## Retention and exact selection

The current publisher at
[`463cec50`](https://github.com/pfBlockerNG/pkg/blob/463cec509feee399ffedd7edd8d0c3af8799683c/.github/workflows/publish.yml#L164-L225)
downloads only the newest published non-prerelease and newest published prerelease. The catalog
builder then defaults to retaining one Stable and one Devel version. Therefore merely adding a
v3.2 Release to the existing `release/` pool is not durable: later v4 releases displace it.

More importantly, keeping both versions in the normal catalog does not provide reliable exact
selection. FreeBSD's [`pkg-repository(5)`](https://man.freebsd.org/cgi/man.cgi?query=pkg-repository&sektion=5)
states that when several repositories expose versions of the same package, `pkg` selects the
highest version even when the command names a lower version. It recommends `-r` to restrict the
operation to a repository. [`pkg-install(8)`](https://man.freebsd.org/cgi/man.cgi?query=pkg-install)
also defines `pkg-name-version`, `-r`, dependency resolution, `-f`, and `-n` dry-run behavior.

Publish a dedicated tree:

```text
compat/ce-2.8/amd64/
compat/plus-26.03/amd64/
compat/plus-26.03/aarch64/
```

Each catalog contains exactly the two v3.2 package identities from the pinned compatibility
Release. The normal `release/` catalog continues to contain only current Stable/Devel. Add a
`pfblockerng-compat` repository definition pointing to the matching `compat/<varver>/<arch>`
path; it may remain disabled for normal upgrades because `pkg install -r pfblockerng-compat ...`
selects it explicitly irrespective of enabled status.

The v4 downgrade preflight should run the equivalent of:

```sh
pkg update -r pfblockerng-compat
pkg install -n -r pfblockerng-compat pfSense-pkg-pfBlockerNG-3.2.17
# after backup/preflight/confirmation succeeds:
pkg install -y -r pfblockerng-compat pfSense-pkg-pfBlockerNG-3.2.17
```

Use the `-devel` name for the Devel target. Whether `-f` is required when switching between
conflicting package names must be proven on a live pfSense box; do not infer it from package
metadata. The dry run must show removal/replacement of only the installed pfBlockerNG package
and required dependency changes before the destructive action is authorized.

The publisher must download the compatibility Release by an explicit pinned tag, fail if any
matrix asset is missing, and generate `compat/` from those assets only. Do not use “latest,”
publication date, cache retention, or the normal Stable/Devel pruning knobs for this tree.

## Publication order

1. Land the compatibility-source branch and its tests.
2. Land compatibility recipes and the dedicated compatibility release workflow.
3. Change `pfBlockerNG/pkg` to consume the pinned compatibility tag and publish the isolated
   `compat/` catalogs; test repository selection and normal-catalog non-regression.
4. Publish `compat-v3.2.17` as a complete immutable Release containing both package names for
   every active matrix entry.
5. Republish and verify all compatibility catalogs before exposing any v4 downgrade button.
6. Publish/install the Stable and Devel v3.2 compatibility packages. Their Software pages can
   then guide users forward through the normal `release/` repository.

The compatibility package publication must be idempotent up to the final Release publish, like
the normal release workflow. After publication, replacement means a new patch version/tag; never
overwrite an asset or move the tag.

## Risks and required gates

- **Wrong source shape:** the v3 tags have no `src/`; a current port fetch against them cannot
  satisfy its `WRKSRC`. Gate the compatibility source archive layout before package builds.
- **Package identity drift:** build both names from one commit and assert manifest `name`,
  `origin`, `version`, ABI, dependencies, `info.xml` registration name, and mutual conflicts.
- **Normal-channel contamination:** prove normal `release/` still resolves latest v4 Devel (and
  v4 Stable when it exists) before and after compatibility publication.
- **Wrong target:** prove `pkg install -n -r pfblockerng-compat <name>-3.2.17` selects only the
  requested name/version on every matrix leg.
- **Incomplete immutable Release:** require six expected `.pkg` assets for the present matrix;
  publish only after the count and manifests pass.
- **Future pfSense variants:** immutable assets cannot be appended. A matrix expansion requires a
  new compatibility patch release or an explicit decision that the new variant cannot downgrade.
- **Port/package scripts:** both compatibility recipes must carry the same pre/post lifecycle
  hooks. Verify native Package Manager, Software page, and CLI paths; no `-I`/`--no-scripts`.
- **Switching names:** Stable and Devel packages conflict. Exercise both Stable→Devel and
  Devel→Stable v3.2 targets on-box, including the restore hook and rollback after package failure.

## Recorded command evidence

```text
$ gh api repos/pfBlockerNG/pfBlockerNG/releases?per_page=100 ...
# 20 published Releases, all v4.0.0.alpha.*; no v3.2 Release assets exist.

$ gh api .../pfSense-pkg-pfBlockerNG/Makefile?ref=pfblockerng/use-github
PORTVERSION= 3.2.15
PORTREVISION= 2
GH_TAGNAME= v${PORTVERSION}
WRKSRC= ${WRKDIR}/${GH_PROJECT}-${PORTVERSION}/src

$ gh api .../pfSense-pkg-pfBlockerNG-devel/Makefile?ref=pfblockerng/use-github
PORTVERSION= 4.0.0.alpha.21
GH_TAGNAME= v${PORTVERSION}
WRKSRC= ${WRKDIR}/${GH_PROJECT}-${PORTVERSION}/src

$ scripts/read-version-matrix.sh --print-build
# CE 2.8/FreeBSD 15 amd64; Plus 26.03/FreeBSD 16 amd64+aarch64.
```

## Newly surfaced decisions

1. Define and policy-check the maintenance branch/tag namespace and the one-off dual-package
   compatibility workflow (`compat/3.2`, `compat-v3.2.17`, package version `3.2.17`).
2. Specify the isolated `pfblockerng-compat` repository lifecycle: installation of its config,
   disabled/default state, update command, and cleanup after downgrade.
3. Prove the exact on-box `pkg` transaction for same-name downgrade and cross-name Stable/Devel
   replacement, including whether `-f` is needed.
4. Decide how a future supported pfSense matrix entry triggers a new immutable v3.2 compatibility
   patch release and advances the pinned compatibility tag.
