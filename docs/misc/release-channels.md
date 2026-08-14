# Release channels and version order

Issue #2140 define release authoring contract for later automation. Not publish packages, not discover release lines, not change on-box update client.

## Shared identity and explicit channel

Every channel publish exact package identity:

```text
pfSense-pkg-pfBlockerNG
```

Channel = metadata + catalog placement, never package-name suffix. Channel and release line explicit/configured; the tag trailer carries the channel: `pfBlockerNG-Release-Channel: <stable|testing|edge>`. Parser derive exact `release/X.Y` line from tag, validate against configured line. Explicit channel must agree with tag rule. Every operation use pinned source SHA.

## Channel shapes

| Channel | Source | Tag / package version | GitHub Release | Notes |
| --- | --- | --- | --- | --- |
| Stable | configured `release/X.Y` | `vX.Y.Z` / `X.Y.Z` | final | required |
| Testing | configured `release/X.Y` | `vX.Y.Z.aN`, `.bN`, or `.rN` with `Z != 0` / exact | prerelease | required |
| Edge | configured `release/X.Y` | `vX.Y.0.aN`, `.bN`, or `.rN` / exact | prerelease | required |
| Nightly | explicit pinned source SHA | `YYYYMMDDHHMMSS.<7-character source SHA>` | none | none |

Stable, Testing, Edge may share release line. For prerelease tag: `Z == 0` selects Edge, `Z != 0` selects Testing.

## Version and tag rules

- Stable `vX.Y.Z` maps to package version `X.Y.Z`.
- Testing `vX.Y.Z.aN`, `vX.Y.Z.bN`, `vX.Y.Z.rN` with `Z != 0` map to exact matching package versions. Edge use same grammar with `Z == 0`.
- Immutable tag trailer record selected channel. Configured release line validated against line derived from tag. Source identity, package version, artifact bytes, checksum, provenance = one immutable record.
- Stable, Testing, Edge create at most one Release per exact tag. Published Releases immutable; retry only exact same identity, no rebuild.

## Destination tuple

Each tagged release emit one native `.pkg` source asset per build-role matrix row, named with package version, Variant, pfSense version. Tuple not stored in the package manifest, build record, or separate metadata file. Reviewed publication callback derive tuple from tag's own shape every run, unconditionally (issue #2251): Edge patch-zero prereleases route to `(edge,)`; Testing prereleases route to `(testing, edge)`; final tags route to `(stable, testing, edge)`. Every channel catalogue therefore strictly contain its slower channels' files — safe because `pkg` order versions numerically, component-wise, so older-family artifact never displace faster channel's latest. Package publisher receive that tuple, strip row suffix from source asset name, copy same `.pkg` bytes to each listed catalogue folder. No follower state, no rebuild, no second Release for fan-out.

## Nightly generation

Nightly is untagged and independent. Creates no GitHub Release or release notes. Every scheduled or manual invocation builds one snapshot. Version = preparation time in UTC, down to seconds, then the first seven characters of the source commit: `YYYYMMDDHHMMSS.<7-character source SHA>`. Failed runs remain failed; dispatch another run when wanted. No counter, deduplication, recovery ledger, or durable Nightly state exists.

Nightly identity include source SHA, FreeBSD-ports SHA, matrix/dependency digest. Ports recipe stay static: no routine version commit, no target final, no PORTEPOCH. Reverse movement need explicit repo-qualified downgrade; no branch or suffix inference may select one.

## Package order

FreeBSD `pkg` = ordering oracle. Intended order for one target:

```text
previous final < alpha < beta < rc < target final < timestamped Nightly
```

Edge and Nightly use exact package version emitted by their selected channel contract. Callers must ask FreeBSD `pkg`/libpkg to compare versions, not reimplement ordering with lexical, SemVer, or tuple comparisons.

## Inputs and provenance

Caller select source line before generation. Stable, Testing, Edge get their configured `release/X.Y`; Nightly get explicit pinned source SHA. Source identity immutable and exact.
Every generated artifact record source SHA, FreeBSD-ports SHA, matrix/dependency digest. Immutable input digest also bind one trusted-tools commit SHA and one pinned `ci-metadata` commit SHA used for both BUILD and ROUTE rows.
Missing, malformed, conflicting, or changed observations fail closed before mutation.

Branch-independent workflow in `.github/workflows/nightly.yml` uses the same pinned-input path for scheduled and manual runs. Scheduled runs need repository variable `NIGHTLY_SOURCE_REF`; manual runs need `source_ref`. Workflow pins inputs, derives the version directly, builds, validates the same-run handoff, and publishes the catalogue. It stores no cross-run state and does not create a tag or Release or mutate the FreeBSD-ports tree.

## Maintained lines and fixes

Stable, Testing, Edge destinations derive from each tagged package's grammar and exact callback inputs; no branch-bound follower line, no stored Edge state selects destination. Nightly use explicit pinned source SHA; no branch inference select it.

Fixes start on oldest affected maintained line. Land that line through its own PR and gates, then cherry-pick forward with `git cherry-pick -x` through newer maintained lines, finally `devel` — separate PRs, conflict resolution, gates each. No merge commits.

## Scope and follow-ups

This contract update classifier and existing release workflow consumers. New builder, publisher, catalog, client/UI, Ports mechanisms belong to their separately scoped follow-up issues.
