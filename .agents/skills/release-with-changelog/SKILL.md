---
name: release-with-changelog
description: >
  Finish a Stable, Testing, or configured Edge release after the release workflow
  leaves a verified draft: author notes from the commit range, write them to the
  draft, and publish after confirmation. Nightly is an explicit no-op and has no
  Release or notes.
---

# Release with changelog

Use after `release` has produced one verified draft for Stable, Testing, or Edge. Nightly
is an independent untagged snapshot with no GitHub Release and no release notes, so this
skill must refuse a Nightly request as an explicit no-op before any lookup.

## Release contract

- Stable uses `vX.Y.Z` / `X.Y.Z`.
- Testing uses `vX.Y.Z.aN`, `vX.Y.Z.bN`, or `vX.Y.Z.rN` with `Z != 0` and the exact matching
  package version.
- Edge uses the same prerelease grammar with `Z == 0`. In short, `Z == 0` selects Edge and
  `Z != 0` selects Testing.

The channel is explicit and configured, and `pfBlockerNG-Release-Channel: <stable|testing|edge>`
is carried in each distinct release's immutable tag trailer and must agree with the tag's
prerelease patch rule. Every operation uses a pinned source SHA.

## Primary kind and destination tuple

The tag shape alone does not select Testing versus Edge. Require the explicit channel,
release target, admitted `release/X.Y` branch, and workflow output. The workflow's primary
kind owns the one Release and notes run. Destination tuple is catalogue fan-out only, and
unconditional (issue #2251): Stable primary always also routes to Testing and Edge, and
Testing primary always also routes to Edge — never creating a second Release, running notes twice,
or changing the primary kind.

- Stable primary keeps Stable notes across every destination.
- Testing primary keeps Testing notes across every destination.
- A distinct-target Edge primary uses the same authored path and its own one Release.
- When Edge follows Testing, reuse the existing Testing tag, GitHub prerelease, authored
  notes, package artifact, and provenance; do not generate or publish another Edge Release.

## Commit-range selection

Resolve family from the trusted `release/X.Y` source line before examining tags. Candidate
sets are primary-kind scoped and family scoped; a newer tag in another family never wins.
“Nearest preceding” means the closest candidate on that release line, not the latest tag
globally.

- Stable: previous Stable in the same family. For the first Stable in a family, use the
  previous family's last Stable.
- Testing: nearest preceding Stable or Testing-primary in the same family.
- Edge: nearest preceding Stable or Edge-primary in the same family. If the family has
  neither, use the previous family's last Stable.

Use exact `commit_range` from final `draft-healthcheck` output after checking that
`base_tag` has required family and primary kind. If no valid base exists, use an empty range;
do not invent a predecessor or use an unrelated global tag. Omit empty or internal-only sections from notes.

## Notes procedure

1. Run `release` first and wait for its exact workflow run. Read final
   `draft-healthcheck` outputs and confirm run ID/attempt, `primary_kind`,
   `destination_tuple`, admitted source branch, `source_sha`, `source_branch`, `draft_url`, JSON `assets`,
   `previous_tag`, `base_tag`, and `commit_range`. Nightly performs no lookup or mutation.
2. Verify the family-scoped base and exact commit range against the pinned tag. Wrong
   branch or kind, stale draft, missing asset, changed SHA, empty/internal range used as non-empty,
   or contradictory workflow output stops without publication. Reject any
   fabricated issue or PR link or withheld confirmation.
3. From that range, keep only user-visible Features, Improvements, and Bug Fixes. Omit
   internal CI, tests, tooling, ADR-only changes, empty sections, and fabricated issue or
   PR links. Generate notes with `scripts/release-notes-prompt.txt`.
4. Preserve the draft-supplied title date. Show rendered title and body for review and
   confirmation before mutation. Update only the intended draft, reread the draft, and
   verify its tag, title, body, pinned source identity, and every asset remain unchanged.
5. Publish only after explicit confirmation, using the workflow's channel flag. Stable
   publishes final/latest; Testing-primary and Edge-primary publish prerelease. A published
   Release is immutable; a mistake requires the next version.

Nightly input identity includes source SHA, FreeBSD-ports SHA, and matrix/dependency digest.
Every scheduled or manual invocation builds `YYYYMMDDHHMMSS.<7-character source SHA>` using UTC.
Failed runs stay failed; dispatch another when wanted. No counter, deduplication, or durable
state exists. Keep its Ports recipe static: no routine version commit, no target final, and
no PORTEPOCH. Timestamped Nightly versions intentionally outrank semantic releases; a reverse
movement requires an explicit repo-qualified downgrade.

Never commit notes to the repository. If publication stops, report the draft URL and the
remaining action.
