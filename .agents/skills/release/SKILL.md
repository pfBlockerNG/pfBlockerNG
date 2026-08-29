---
name: release
description: >
  Prepare one Stable, Testing, or configured Edge release by validating its explicit
  channel and release line, then dispatching the current release workflow. Nightly
  is an independent untagged snapshot and is an explicit no-op for this skill.
---

# Release

Use for a request to prepare a Stable, Testing, or Edge release. The only mutating outcome
is one draft: one tag creates one draft.
Destination fan-out never creates another Release. Require explicit channel,
explicit release target, configured `release/X.Y` source line, and admitted branch.
The channel is explicit and configured; the tag trailer stores
`pfBlockerNG-Release-Channel: <stable|testing|edge>` and must agree with the tag's
prerelease patch rule. Use a pinned source SHA for every channel.

## Contract

- Stable uses `vX.Y.Z` / `X.Y.Z`.
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` when `Z != 0`; the package version
  is the exact `X.Y.Z.aN`, `X.Y.Z.bN`, or `X.Y.Z.rN` value.
- Edge uses the same prerelease grammar when `Z == 0`. In short, `Z == 0` selects Edge and
  `Z != 0` selects Testing.
- Tag shape alone does not select a target: validate explicit channel and release target
  with `scripts/release-version.sh`. Primary kind is the workflow output: Stable for a
  final tag, Edge for a patch-zero prerelease, and Testing for a nonzero-patch prerelease.
- The ordered destination tuple is catalogue routing only, and unconditional (issue #2251):
  a Stable primary always routes to `(stable, testing, edge)`; a Testing primary always
  routes to `(testing, edge)`; a distinct-target Edge primary always routes to `(edge,)`.
  Every channel catalogue strictly contains its slower channels' files. Copies reuse the
  same tag, Release, notes, assets, and provenance.
- Nightly is untagged, has no GitHub Release, and has no release notes. Every scheduled or
  manual invocation builds `YYYYMMDDHHMMSS.<7-character source SHA>` using UTC. Failed runs stay
  failed; dispatch another when wanted. No counter, deduplication, or durable state exists.
- Nightly identity includes source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
  Keep the Ports recipe static: no routine version commit, no target final, and no
  PORTEPOCH. Timestamped Nightly versions intentionally outrank semantic releases; a reverse
  movement requires an explicit repo-qualified downgrade.

## Procedure

0. Reject Nightly as an explicit no-op before tag, Release, workflow-run, or range lookup.
   Nightly performs no lookup and no mutation here.
1. Resolve trusted inputs: exact tag, explicit channel and release target, configured
   source line, admitted source branch (`release/X.Y`), supported workflow ref, and pinned source
   SHA. Validate the tag with `scripts/release-version.sh`; do not reimplement its grammar.
2. Dispatch the current `release.yml` workflow with those inputs and **explicitly set
   `dry_run=false`**. The workflow default is `true`; omitting this field is invalid for a
   real release. Record its exact workflow run ID and attempt; never substitute a newer run,
   branch tip, or local result. The dispatch shape is:
   `gh workflow run release.yml --ref <workflow-ref> -f tag=<tag> -f channel=<channel> -f source=<release/X.Y> -f dry_run=false`.
3. Read final `draft-healthcheck` job outputs: `primary_kind`, ordered
   `destination_tuple`, `previous_tag`, `base_tag`, `base_sha`, `commit_range`, pinned
   `source_sha`, admitted `source_branch`, `draft_url`, and JSON `assets`. Verify the run completed successfully,
   the admitted branch and immutable tag trailer agree, the tag resolves to the pinned SHA,
   verify exact source SHA, and every expected exact asset is attached to the one draft. A
   missing, stale, changed, or contradictory output stops without publication.
4. Confirm required checks are green for that pinned source. A docs-only tip may inherit the
   nearest checked ancestor; do not silently ignore a failed check. Confirm no published
   Release already owns the tag.
5. Stop at the complete draft. Report run ID/attempt, primary kind, destination tuple,
   pinned SHA, draft URL, and verified assets; do not create or push a tag by hand. Notes,
   review, confirmation, reread, and publication belong to `release-with-changelog`. The
   terminal state is complete: stop at the complete draft.

`release.yml` at the current repository revision is authoritative for inputs and job
names. If it contradicts this contract, stop and report the contradiction instead of
inventing a compatibility path.
