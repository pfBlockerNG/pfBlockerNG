---
name: release-with-changelog
description: >
  Cut a pfBlockerNG release WITH hand-authored release notes: play the role of the
  GitHub Models step — write docs/release-notes/<tag>.md from the commit range using the
  same prompt the workflow feeds the model — commit it on the channel branch, then hand
  off to the /release skill to validate + push the tag. Because the file is committed, the
  workflow's GitHub Models step is skipped and the release body comes from your file. Use
  this when Models is unavailable (e.g. the org hasn't enabled it), when you want curated
  notes, or when the user says "write the changelog and release", "release with notes",
  "play the model and cut the release", or invokes /release-with-changelog.
  Args: <tag> (e.g. v4.0.0.alpha.1).
---

You author the release notes yourself, commit them, then cut the release. The release
workflow uses a committed `docs/release-notes/<tag>.md` **in preference to** GitHub Models
(it skips the Models step when the file exists), so providing the file IS "playing the
model". The actual tag validation + push is delegated to **`/release`** — do not
re-implement it.

`scripts/release-notes-prompt.txt` is the **same system prompt** the workflow feeds the
model; you apply it by hand here. `scripts/release-version.sh` classifies the tag/channel.

## Arguments

- `<tag>` — required, e.g. `v4.0.0.alpha.1` (must start with `v`).

## Steps

1. **Classify the tag + pick the channel branch.** `sh scripts/release-version.sh <tag>` →
   `channel`/`prerelease`. `devel` for a prerelease, `main` for stable. A malformed tag stops
   here (show its error). Don't push anything yet.

2. **Resolve the compare base (previous same-channel release).** Mirror `release.yml`'s
   `prev_tag`: `git fetch origin --tags`; the highest-version tag of the **same channel** that
   is an ancestor of the channel-branch tip (classify each candidate with
   `release-version.sh`), falling back to the highest ancestor tag of any channel, then the
   next-lower version tag. Call it `PREV`. The compare link is
   `https://github.com/<owner>/<repo>/compare/<PREV>...<tag>` (or `…/commits/<tag>` when there
   is no `PREV`).

3. **Gather the commits the "model" sees.**
   `git log <PREV>..origin/<branch> --no-merges --pretty='%h %s' -- src/ scripts/`.
   For a **genesis release of a new series** (the first `X.0.0.alpha.1`, whose `PREV` is an
   old-scheme tag), also describe the headline features of the whole series — the narrow
   `PREV..HEAD` range alone undersells it; read prior notes / ADR titles for the arc.

4. **Author the notes by applying `scripts/release-notes-prompt.txt`.** Produce exactly what
   the model would: keep only user-relevant changes (drop CI / tests / tooling / lint /
   internal refactors / dev-docs); group under `## Features`, `## Improvements`, `## Bug Fixes`
   (omit an empty group); link each item's PR/issue as `([#N](…/issues/N))` when the subject
   references `#N` (the `/issues/` path resolves for PRs too); **never name internal ADRs** —
   describe the user-facing change. Professional, engineer-like tone; precision over flash.
   End the body with the exact compare link from step 2.

5. **Write `docs/release-notes/<tag>.md`.** First line is the title marker
   `<!-- SUMMARY: <three-word summary> -->` (the workflow turns it into the Release title
   suffix `pfBlockerNG <version> — <summary>` and strips it from the rendered body); then the
   grouped body. Lint it: `npx markdownlint-cli2 docs/release-notes/<tag>.md` → 0 errors.

6. **Confirm the rendered notes with the user.** Show the title + body. This is the public
   release body — get a nod before committing (cheap to revise now, immutable after release).

7. **Commit the notes file on the channel branch.** It must be on the channel branch **before**
   the tag, so the tagged checkout contains it. Commit `docs: add release notes for <tag>`
   (docs-only ⇒ CI-skipped) and land it on the channel branch via the repo's normal flow
   (managed-remote: a docs PR to `devel`/`main`; off-appliance: the worktree flow). Wait until
   it is merged so the channel-branch tip carries the file.

8. **Cut the release — delegate to `/release`.** Invoke **`/release <tag>`**. It re-validates
   the channel↔branch scheme, checks CI is green on the release commit (now including the notes
   commit), and pushes the tag. The release workflow then sees the committed file, **skips the
   Models step**, and publishes the Release with your notes as the body and the `SUMMARY` as the
   title suffix.

## Guardrails

- **The notes file must land on the channel branch before the tag** — a tag whose commit
  predates the file means the workflow won't see it (it would fall through to Models, or a
  placeholder). Order matters: notes commit first, tag second.
- **Inherit every `/release` guardrail** — channel↔branch enforcement, immutable tags (cut the
  next `.N` instead of moving one), tag-only pushes (never a direct `main`/`devel` push). This
  skill only adds the notes-authoring + commit in front.
- **Don't fabricate PR/issue numbers.** Link a `#N` only when a commit subject references it;
  otherwise describe the change without a link.
- **Keep ADRs out of the public notes** — neutral, user-facing wording only.
