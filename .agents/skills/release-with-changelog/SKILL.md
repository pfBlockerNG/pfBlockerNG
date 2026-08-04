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
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` with the exact matching package
  version.
- Edge uses the same Testing grammar. Edge follows Testing only when no distinct target
  exists; distinct-target Edge uses its configured target/line. Without a distinct Edge
  target, use the exact Testing Release and artifact bytes,
  checksums, source, provenance, tag, and notes; this means the same Release and artifact
  bytes, no second Release, and no rebuild.
  When the target becomes Stable, continue following Testing until a new target exists.

The channel is explicit and configured, and `pfBlockerNG-Release-Channel: <stable|testing|edge>`
is carried in each distinct release's immutable tag trailer; channel is never inferred from
a suffix. A follower Edge reuses the Testing tag and its `testing` trailer. Every operation
uses a pinned source SHA.

The same Release and artifact bytes are reused when Edge follows Testing; no second Release
or rebuild is permitted.

## Notes procedure

Follower Edge must not dispatch `release.yml` or enter this notes procedure. Reuse the
existing Testing Release and notes. Catalog routing is owned by #2144; until that path
exists, stop and report the missing route instead of creating another draft.

1. For Stable, Testing, or distinct-target Edge, run the `release` skill first and wait for
   the draft. Confirm the draft URL, assets, and
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
