# Copilot review instructions — pfBlockerNG

- Do **not** review anything under `.claude/skills/ponytail/` or
  `.claude/skills/caveman/`. These are vendored third-party plugin trees,
  copied **byte-identical** from their MIT upstreams (each directory carries
  an `UPSTREAM` provenance file naming the exact upstream commit) and
  refreshed wholesale by `scripts/update-vendored-skills.py`. Style, wording,
  or lint findings on them are not actionable in this repository — fixes
  belong upstream, and local edits would silently drift until the next
  refresh reverts them. The only reviewable properties are byte-identity with
  the pinned upstream ref and the `UPSTREAM` provenance itself.
- Everything else follows `CLAUDE.md` (code standards, test-coverage
  mandate, commit style).
