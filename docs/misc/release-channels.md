# Release channels and version order

Issue #2140 defines the release authoring contract consumed by later automation. It does
not publish packages, discover release lines, or change the on-box update client.

## Shared identity and explicit channel

Every channel publishes the exact package identity:

```text
pfSense-pkg-pfBlockerNG
```

Channel is metadata and catalog placement, never a package-name suffix. Channel and release
line are explicit/configured. The tag trailer carries the channel, using
`pfBlockerNG-Release-Channel: <stable|testing|edge>`; the parser derives the exact
`release/X.Y` line from the tag and validates it against the configured line. The explicit
channel must agree with the tag rule. Every operation uses a pinned source SHA.

## Channel shapes

| Channel | Source | Tag / package version | GitHub Release | Notes |
| --- | --- | --- | --- | --- |
| Stable | configured `release/X.Y` | `vX.Y.Z` / `X.Y.Z` | final | required |
| Testing | configured `release/X.Y` | `vX.Y.Z.aN`, `.bN`, or `.rN` with `Z != 0` / exact | prerelease | required |
| Edge | configured `release/X.Y` | `vX.Y.0.aN`, `.bN`, or `.rN` / exact | prerelease | required |
| Nightly | explicit pinned source SHA | untagged date counter | none | none |

Stable, Testing, and Edge may share a release line. For a prerelease tag, `Z == 0` selects Edge
and `Z != 0` selects Testing.

## Version and tag rules

- Stable `vX.Y.Z` maps to package version `X.Y.Z`.
- Testing `vX.Y.Z.aN`, `vX.Y.Z.bN`, and `vX.Y.Z.rN` with `Z != 0` map to the exact matching
  package versions. Edge uses the same grammar with `Z == 0`.
- The immutable tag trailer records the selected channel. The configured release line is
  validated against the line derived from the tag. Source identity, package version,
  artifact bytes, checksum, and provenance are one immutable record.
- Stable, Testing, and Edge create at most one Release for an exact tag. Published Releases
  are immutable; retry only the exact same identity without rebuilding.

## Destination tuple

Each tagged release emits one native `.pkg` source asset per build-role matrix row, named with
the package version, Variant, and pfSense version. The tuple is not stored in the package
manifest, build record, or a separate metadata file. A reviewed publication callback derives
the tuple from the tag's own shape on every run, unconditionally (issue #2251): Edge patch-zero
prereleases route to `(edge,)`; Testing prereleases route to `(testing, edge)`; final tags route
to `(stable, testing, edge)`. Every channel catalogue therefore strictly contains its slower
channels' files — safe because `pkg` orders versions numerically, component-wise, so an
older-family artifact never displaces a faster channel's latest. The
package publisher receives that tuple, strips the row suffix from the source asset name, and
copies the same `.pkg` bytes to each listed catalogue folder. No follower state, rebuild, or
second Release is created for fan-out.

## Nightly generation

Nightly is independent and untagged. It creates no GitHub Release and no release notes. Generate
it when the pinned source input changes:

- the first changed input on a UTC date uses `YYYYMMDD`;
- another changed input on that date uses `YYYYMMDD_1`, then `YYYYMMDD_2` and so on; and
- an unchanged input or skipped day is a no-op.

Nightly identity includes the source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
The Ports recipe remains static: no routine version commit, no target final, and no PORTEPOCH.
Bare date versions intentionally outrank semantic releases. Reverse movement requires an
explicit repo-qualified downgrade; no branch or suffix inference may select one.

## Package order

FreeBSD `pkg` is the ordering oracle. The intended order for one target is:

```text
previous final < alpha < beta < rc < target final < bare Nightly date
```

Edge and Nightly use the exact package version emitted by their selected channel contract.
Callers must ask FreeBSD `pkg`/libpkg to compare versions rather than reimplementing ordering
with lexical, SemVer, or tuple comparisons.

## Inputs and provenance

The caller selects the source line before generation. Stable, Testing, and Edge receive their
configured `release/X.Y`; Nightly receives an explicit pinned source SHA. Source identity is
immutable and exact.
Every generated artifact records source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
The immutable input digest also binds one trusted-tools commit SHA and one pinned
`ci-metadata` commit SHA used for both BUILD and ROUTE rows.
Missing, malformed, conflicting, or changed observations fail closed before mutation.

The branch-independent workflow in `.github/workflows/nightly.yml` uses the same pinned-input
path for scheduled and manual runs. Scheduled runs require repository variable
`NIGHTLY_SOURCE_REF`; manual runs require `source_ref`. The workflow serializes allocation,
build, validation, and handoff, stores completed allocation/artifact identities in the
`nightly-state` branch, and uploads `nightly-handoff.json` for the publisher. It does not
publish a catalog, create a tag or Release, or mutate the FreeBSD-ports tree.

## Maintained lines and fixes

Stable, Testing, and Edge destinations derive from each tagged package's grammar and exact
callback inputs; no branch-bound follower line or stored Edge state selects a destination. Nightly uses an
explicit pinned source SHA; no branch inference selects it.

Fixes start on the oldest affected maintained line. Land that line through its own PR and
gates, then cherry-pick forward with `git cherry-pick -x` through newer maintained lines and
finally `devel`, with separate PRs, conflict resolution, and gates. Merge commits are not
used.

## Scope and follow-ups

This contract updates the classifier and existing release workflow consumers. New builder,
publisher, catalog, client/UI, and Ports mechanisms belong to their separately scoped
follow-up issues.
