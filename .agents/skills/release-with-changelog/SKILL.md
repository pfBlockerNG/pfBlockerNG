---
name: release-with-changelog
description: Write curated pfBlockerNG release notes and dispatch the release workflow. Use for "release with notes", "write the changelog and release", or "play the model and cut a release".
---

# Release with curated notes

Read `../../../.claude/skills/release-with-changelog/SKILL.md`. Create the committed release
notes from the defined commit range, then invoke `$release`; preserve the workflow
as the only tagger/publisher. Do not substitute a generic model-generated summary
for the required repository release-note format.
