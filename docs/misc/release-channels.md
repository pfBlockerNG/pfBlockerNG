# Release channels and version order

Issue #2140 defines the authoring contract used by later release automation. It does not
publish packages, create releases, select branches, or change the on-box update client.

## Package identity

Every channel publishes the same package identity:

```text
pfSense-pkg-pfBlockerNG
```

Channel is metadata and catalog placement, never a package-name suffix. This preserves the
single-package model established by issues #1806 and #1828: the package remains architecture
independent where the port permits it, and EOL `route-only` catalog behavior remains unchanged.

## Channel shapes

Given target final version `X.Y.Z`:

| Channel | Source | Version or tag | GitHub Release | Notes |
| --- | --- | --- | --- | --- |
| Stable | `release/X.Y` | tag `vX.Y.Z` | final | required |
| Testing | `release/X.Y` | tag `vX.Y.Z.alpha.N`, `.beta.N`, or `.rc.N` | prerelease | required |
| Edge | configured `release/X.Y` | tag `vX.Y.Z.edge.YYYYMMDD.N` | prerelease | required |
| Nightly | `devel` | no tag | none | none |

Stable and Testing tags are selected by a human. Edge and Nightly identifiers are generated
from an immutable source commit, UTC date, and daily count. Edge notes use the same authored
changelog path as Stable and Testing; there is no separate generated-notes path. Nightly is an
untagged `devel` snapshot and therefore cannot create a GitHub Release or release notes.

The canonical parser result records package, channel, stage, target final, source line, tag,
version, package version, prerelease/final flags, notes requirement, and GitHub Release kind.
Nightly has `tag = None` and GitHub Release kind `none`.

## FreeBSD package order

The package versions targeting one final release are:

```text
X.Y.(Z-1)
X.Y.Z.alpha.N
X.Y.Z.beta.N
X.Y.Z.rc.N
X.Y.Z.snapshot.1.YYYYMMDD.N   # Edge
X.Y.Z.snapshot.2.YYYYMMDD.N   # Nightly
X.Y.Z
```

The required strict order is:

```text
previous final < alpha < beta < rc < Edge < Nightly < target final
```

Within Edge or Nightly, a later UTC date sorts after an earlier date and a higher same-day
count sorts after a lower count. Code must not reproduce this comparison with SemVer, lexical,
or tuple logic. Mutation callers supply the result observed from FreeBSD `pkg`/libpkg.

The external oracle was run on 2026-08-03 against every supported FreeBSD/pkg family:

| pfSense | FreeBSD | `pkg` | Result |
| --- | --- | --- | --- |
| CE 2.8 | 15 | 1.21.3 | full adjacent-pair table passed |
| Plus 26.03 | 16 | 2.7.5 | full adjacent-pair table passed |
| Plus 26.07 | 16 | 2.7.5 | full adjacent-pair table passed |

The smoke oracle invokes `/usr/local/sbin/pkg version -t` directly on each appliance. Unit
tests pin the exact generated strings; they do not claim to implement libpkg ordering.

## Snapshot generation

Snapshot generation is deterministic and fail-closed:

- The caller selects the source line before generation. Edge must receive the configured exact
  `release/X.Y`; Nightly must receive `devel`. The generator never lists or sorts branches.
- The source is an exact lowercase 40- or 64-hex commit ID. Mutable names are rejected.
- The date is an explicit UTC `date`. The first new source on a date receives count `1`; each
  different source on that date receives the next count; a later date restarts at `1`.
- Repeating the same channel, target, line, and source returns its original result, including
  when retried on a later date. Conflicting records for one source fail.
- A date older than an existing relevant snapshot fails. Duplicate versions, package versions,
  or source records with conflicting content fail.
- After final `X.Y.Z`, the next development target is `X.Y.(Z+1)` until a human chooses a
  different maintained release line.

The channel-specific generated values are:

```text
Edge tag:       vX.Y.Z.edge.YYYYMMDD.N
Edge version:   X.Y.Z.edge.YYYYMMDD.N
Edge pkg:       X.Y.Z.snapshot.1.YYYYMMDD.N

Nightly tag:    none
Nightly version:X.Y.Z.nightly.YYYYMMDD.N
Nightly pkg:    X.Y.Z.snapshot.2.YYYYMMDD.N
```

## Mutation preconditions

Later publication code must call the mutation boundary before its first write. The boundary
permits a mutation only when all caller-observed facts are valid:

- package identity and selected source line exactly match the canonical result;
- the immutable source commit is reachable and an existing tag has not moved;
- an existing published Release or draft with assets is never modified;
- only an assetless draft at the exact tag and source is eligible for safe recovery;
- `pkg`/libpkg reports the candidate newer than the current package version;
- one package version cannot map to different artifact bytes; identical bytes are a no-op.

Missing or malformed observations fail closed. The mutation callback is invoked only after all
checks pass. This seam authorizes no publication in issue #2140; later publisher issues provide
the observations and side effects.

## Maintained release lines and fixes

Stable and Testing may coexist for every maintained `release/X.Y` line. Exactly one release line
is configured as active Edge. Supporting simultaneous Edge streams requires an owner decision
and separate/equal-priority catalogs; branch-name ordering is never a substitute for that choice.
Nightly always follows `devel`.

Fixes start on the oldest affected maintained release line. Land that line through its own PR and
gates, then cherry-pick forward with `git cherry-pick -x` through each newer maintained release
line and finally `devel`. Each forward port gets its own PR, conflict resolution, and gates. A
`devel`-only fix stays on `devel`. Merge commits are not used.

## Compatibility and follow-ups

The shell parser keeps its first five legacy assignments for existing workflows and appends the
canonical fields. Temporary `main`/`devel` branch aliases are restricted to Stable/Testing legacy
callers. Issue #2143 owns workflow migration to canonical release lines and generation.
Builder, publisher, catalog, and client/UI behavior belongs to issues #2144–#2148.
FreeBSD-ports changes belong to issue #2141. None of those surfaces change in #2140.
