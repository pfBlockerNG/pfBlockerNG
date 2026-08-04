---
name: release
description: >
  Prepare a Stable, Testing, or configured Edge release by validating its explicit
  channel and release line, then dispatching the current release workflow. Nightly
  is an independent untagged snapshot and is not handled by this skill.
---

# Release

Use for a request to prepare a Stable, Testing, or Edge release. Require an explicit
channel and configured `release/X.Y` source line. The channel is explicit and configured;
store `pfBlockerNG-Release-Channel: <stable|testing|edge>` in each distinct release's
immutable tag trailer. It must agree with the tag's prerelease patch rule.
Use a pinned source SHA for every channel.

## Contract

- Stable uses `vX.Y.Z` / `X.Y.Z`.
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` when `Z != 0`; the package version
  is the exact `X.Y.Z.aN`, `X.Y.Z.bN`, or `X.Y.Z.rN` value.
- Edge uses the same prerelease grammar when `Z == 0`. In short, `Z == 0` selects Edge and
  `Z != 0` selects Testing.
- Nightly is untagged, has no GitHub Release, and has no release notes. It is generated
  independently from its pinned source when its input changes. A changed input uses UTC date
  `YYYYMMDD`; another changed input on the same date uses `YYYYMMDD_1`, then `_2`. An
  unchanged input or skipped day is a no-op.
- Nightly identity includes source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
  Keep the Ports recipe static: no routine version commit, no target final, and no
  PORTEPOCH. Bare date versions intentionally outrank semantic releases; a reverse
  movement requires an explicit repo-qualified downgrade.

## Procedure

1. Validate the tag with `scripts/release-version.sh` and the explicit channel/source
   line. Do not reimplement its grammar.
2. Confirm the selected line is current, the immutable source and tag trailer agree, and
   no published Release already owns the tag.
3. Confirm the required checks are green for that source. A docs-only tip may inherit the
   nearest checked ancestor; do not silently ignore a failed check.
4. For Stable, Testing, or Edge, dispatch the current release workflow from its supported
   workflow ref. The workflow
   builds and verifies exact artifacts before creating a tag and draft Release; do not
   create or push a tag by hand.
5. Stop at the complete draft. Report its URL and state that notes and publication remain
   for `release-with-changelog`.

`release.yml` at the current repository revision is authoritative for inputs and job
names. If it contradicts this contract, stop and report the contradiction instead of
inventing a compatibility path.
