---
name: release
description: Validate and dispatch a pfBlockerNG release through the repository release workflow. Use for "cut a release", "release vX.Y.Z", or "publish the alpha".
---

# Release

Follow `../../../.claude/skills/release/SKILL.md`; its `CLAUDE.md` references are the
canonical shared policy and `AGENTS.md` translates only runtime surfaces.
Validate the tag with the repository script and dispatch `release.yml`; do not
create or push a tag by hand. Keep the channel-branch and CI checks, dry-run
semantics, and bounded workflow observation intact.
