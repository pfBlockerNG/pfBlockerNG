# Release channels and version order

Issue #2140 defines the release authoring contract consumed by later automation. It does
not publish packages, discover release lines, or change the on-box update client.

## Shared identity and explicit channel

Every channel publishes the exact package identity:

```text
pfSense-pkg-pfBlockerNG
```

Channel is metadata and catalog placement, never a package-name suffix. The channel and
release line are explicit/configured and carried in an immutable tag trailer. The channel is
explicit and configured; `pfBlockerNG-Release-Channel: <stable|testing|edge>` is the trailer
key, and a parser must never infer channel from a suffix. Every operation uses a pinned source
SHA.

## Channel shapes

| Channel | Source | Tag / package version | GitHub Release | Notes |
| --- | --- | --- | --- | --- |
| Stable | configured `release/X.Y` | `vX.Y.Z` / `X.Y.Z` | final | required |
| Testing | configured `release/X.Y` | `vX.Y.Z.aN`, `.bN`, or `.rN` / exact | prerelease | required |
| Edge | configured `release/X.Y` | same Testing grammar / exact | prerelease | required |
| Nightly | explicit pinned source SHA | untagged date counter | none | none |

Stable, Testing, and Edge share a maintained release-line target. Edge follows Testing only when no distinct target
exists; distinct-target Edge uses its configured target/line. In that
case, reuse the exact existing Testing Release and
artifact bytes, checksums, source, provenance, tag, and notes. This preserves the same Release
and artifact bytes, with no second Release and no rebuild. When the target becomes Stable, Edge
continues to follow Testing until a new target is configured.

## Version and tag rules

- Stable `vX.Y.Z` maps to package version `X.Y.Z`.
- Testing `vX.Y.Z.aN`, `vX.Y.Z.bN`, and `vX.Y.Z.rN` map to the exact matching package
  versions. Edge uses this same grammar and mapping.
- The immutable tag trailer records the selected channel and release line. Source identity,
  package version, artifact bytes, checksum, and provenance are one immutable record.
- Stable, Testing, and Edge create at most one Release for an exact tag. Published Releases
  are immutable; retry only the exact same identity without rebuilding.

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
previous final < alpha < beta < rc < Edge < Nightly < target final
```

Edge and Nightly use the exact package version emitted by their selected channel contract.
Callers must ask FreeBSD `pkg`/libpkg to compare versions rather than reimplementing ordering
with lexical, SemVer, or tuple comparisons.

## Inputs and provenance

The caller selects the source line before generation. Stable, Testing, and Edge receive their
configured `release/X.Y`; Nightly receives an explicit pinned source SHA. Source identity is
immutable and exact.
Every generated artifact records source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
Missing, malformed, conflicting, or changed observations fail closed before mutation.

## Maintained lines and fixes

Stable and Testing may coexist for each maintained `release/X.Y`; exactly one explicitly
configured line supplies Edge. Supporting simultaneous Edge lines requires an owner decision
and separate/equal-priority catalogs; branch sorting is never a substitute. Nightly uses an
explicit pinned source SHA; no branch inference selects it.

Fixes start on the oldest affected maintained line. Land that line through its own PR and
gates, then cherry-pick forward with `git cherry-pick -x` through newer maintained lines and
finally `devel`, with separate PRs, conflict resolution, and gates. Merge commits are not
used.

## Scope and follow-ups

This contract authorizes no publication or workflow implementation by itself. Existing
workflow consumers remain current at the issue #2140 base revision. Builder, publisher,
catalog, client/UI, and Ports changes belong to their separately scoped follow-up issues.
