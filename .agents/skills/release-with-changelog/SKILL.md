---
name: release-with-changelog
description: >
  Finish a Stable, Testing, or configured Edge release after the release workflow
  leaves a verified draft: author notes from the commit range, write them to the
  draft, and publish after confirmation. Nightly has no Release or notes.
---

# Release with changelog

Use after `release` has produced a verified draft for Stable, Testing, or Edge. Nightly
is an independent untagged snapshot with no GitHub Release and no release notes, so this
skill must refuse a Nightly request.

## Release contract

- Stable uses `vX.Y.Z` / `X.Y.Z`.
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` with `Z != 0` and the exact matching
  package version.
- Edge uses the same prerelease grammar with `Z == 0`. In short, `Z == 0` selects Edge and
  `Z != 0` selects Testing.

The channel is explicit and configured, and `pfBlockerNG-Release-Channel: <stable|testing|edge>`
is carried in each distinct release's immutable tag trailer and must agree with the tag's
prerelease patch rule. Every operation uses a pinned source SHA.

## Notes procedure

1. For Stable, Testing, or Edge, run the `release` skill first and wait for the draft. Confirm
   the draft URL, assets, and
   immutable source identity.
2. Resolve the previous same-channel tag from the current workflow's rules. Use the exact
   commit range and omit internal tooling, tests, ADRs, and workflow mechanics from notes.
3. Write concise `## Features`, `## Improvements`, and `## Bug Fixes` sections as needed.
   Link only issue or PR numbers present in commit subjects. Keep the title date supplied
   by the draft and add a short summary.
4. Show the rendered title and notes for confirmation. Write them to the draft, read the
   draft back, and verify every asset remains attached.
5. Publish only after confirmation, using the workflow's channel flag. A published Release
   is immutable; a mistake requires the next version.

Nightly input identity includes source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
Its changed-input counter uses UTC `YYYYMMDD`, then `YYYYMMDD_1`/`_2` for same-day changes;
unchanged or skipped days are no-ops. Keep its Ports recipe static: no routine version
commit, no target final, and no PORTEPOCH. Bare date versions intentionally outrank semantic
releases; a reverse movement requires an explicit repo-qualified downgrade.

Never commit notes to the repository. If publication stops, report the draft URL and the
remaining action.
