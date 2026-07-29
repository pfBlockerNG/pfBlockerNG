---
name: release-with-changelog
description: >
  Cut a pfBlockerNG release END TO END: invoke /release <tag> (scheme validation +
  workflow dispatch + wait for the run to reach the drafted state), then author the
  release notes and title from the commit range using scripts/release-notes-prompt.txt,
  write them onto the DRAFT Release, and publish it. Release notes are never files in
  the repository — they are authored onto the Release itself, and publishing is what
  fires the pkg-repo republish. This is the full path when
  Claude is driving, and the one to use when the user says "write the changelog and
  release", "release with notes", "cut and publish vX.Y.Z", or invokes
  /release-with-changelog.
  Args: <tag> (e.g. v4.0.0.alpha.1).
---

You cut the release **and finish it**. `/release` gets you a complete DRAFT; this skill is
that plus the finish step: author the notes + title, put them on the draft, publish.

The split is deliberate. `release.yml` deliberately stops at a draft — release notes are
**not files in this repository** (a committed changelog forces a changelog commit, which
forces a push to the channel branch and a re-generation whenever `devel` moves), and
in-pipeline LLM drafting has no working free option, so a human or Claude writes them.
Publishing the draft is what emits `release: published`, which fires
`release-published.yml` (the pkg-repo republish; the FreeBSD-ports `PORTVERSION` bump is
already done — it is the release run's terminal job).

`scripts/release-notes-prompt.txt` is the authoring template — apply it by hand here.
`scripts/release-version.sh` classifies the tag/channel. **Never re-implement `/release`'s
dispatch mechanics**; delegate them.

## Arguments

- `<tag>` — required, e.g. `v4.0.0.alpha.1` (must start with `v`).

## Steps

1. **Cut the release — delegate to `/release`.** Invoke **`/release <tag>`**. It validates
   the channel↔branch scheme, checks CI is green on the release commit, and **dispatches
   `release.yml` with `dry_run=false`** — the workflow pins the channel-branch tip, builds
   every `.pkg` from it, verifies them, pushes the tag on that pinned SHA, and leaves a
   complete **DRAFT** Release. Wait for the run to reach that state and capture the draft
   URL. If the run fails, stop: nothing was tagged or drafted, and the same tag can be
   re-dispatched once the fix lands.

2. **Resolve the compare base (previous same-channel release).** Mirror `release.yml`'s
   `prev_tag`: `git fetch origin --tags`; the highest-version tag of the **same channel** that
   is an ancestor of the release commit (classify each candidate with `release-version.sh`),
   falling back to the highest ancestor tag of any channel, then the next-lower version tag.
   Call it `PREV`. The compare link is
   `https://github.com/<owner>/<repo>/compare/<PREV>...<tag>` (or `…/commits/<tag>` when there
   is no `PREV`) — the same link already sitting in the draft's placeholder body.

3. **Gather the commits the notes cover.**
   `git log <PREV>..<tag> --no-merges --pretty='%h %s' -- src/ scripts/`.
   When **no prior tag exists** (`PREV` empty — the very first release), drop the range:
   `git log <tag> --no-merges --pretty='%h %s' -- src/ scripts/`.
   For a **genesis release of a new series** (the first `X.0.0.alpha.1`, whose `PREV` is an
   old-scheme tag), also describe the headline features of the whole series — the narrow
   `PREV..<tag>` range alone undersells it; read prior Releases / ADR titles for the arc.

4. **Author the notes by applying `scripts/release-notes-prompt.txt`.** Follow its shape:
   keep only user-relevant changes (drop CI / tests / tooling / lint /
   internal refactors / dev-docs); group under `## Features`, `## Improvements`, `## Bug Fixes`
   (omit an empty group); link each item's PR/issue as `([#N](…/issues/N))` when the subject
   references `#N` (the `/issues/` path resolves for PRs too); **never name internal ADRs** —
   describe the user-facing change. Professional, engineer-like tone; precision over flash.
   End the body with the exact compare link from step 2.

5. **Compose the title.** `<YYYY-MM-DD> - <version> — <three-word summary>`, keeping the ISO
   date the draft already carries (it keeps GitHub's alphabetical release sort chronological)
   and appending the summary. There is no `SUMMARY` marker anywhere any more: the workflow
   derives no title suffix, so this step owns the final title.

6. **Confirm the rendered notes with the user.** Show the title + body. This is the public
   release body — get a nod before writing it (cheap to revise now; the Release is immutable
   once published).

7. **Write them onto the draft.** It stays a draft while you do:

   ```sh
   gh release edit <tag> --title "<title>" --notes-file <path-to-body>
   ```

   Re-read it (`gh release view <tag>`) and confirm the body rendered as intended and every
   asset is still attached.

8. **Publish.** This is the irreversible, public step, and it locks the Release immutable:

   ```sh
   gh release edit <tag> --draft=false --prerelease   # stable: --latest instead
   ```

   Publishing fires `release-published.yml`, which dispatches the `pfBlockerNG/pkg`
   republish so the build appears at `pfblockerng.github.io/pkg`. (The FreeBSD-ports
   `PORTVERSION` bump already happened, as the terminal job of the release run.) Point at
   that run and report the published Release URL.

## Guardrails

- **Never publish a draft you have not read.** The body and the asset list are frozen by
  immutability the moment you publish.
- **Never leave a release drafted silently.** If you stop before step 8 (the user asked to
  review, something failed), say so explicitly and name the draft URL — a drafted release
  ships nothing to users: no pkg-repo refresh. (The ports fork is already bumped to that
  version, so an abandoned draft leaves the fork ahead of what actually shipped until the
  next cut overwrites it.)
- **Prerelease flag matches the channel** — `--prerelease` for `alpha`/`beta`/`rc`,
  `--latest` for a stable `vX.Y.Z`. `release-version.sh` classifies it; the draft was already
  created with the right flag, so only re-assert it, never flip it.
- **Inherit every `/release` guardrail** — channel↔branch enforcement, immutable published
  releases (cut the next `.N` instead of re-releasing), never a direct `main`/`devel` push.
  This skill only adds the notes-authoring + publish behind it.
- **Don't fabricate PR/issue numbers.** Link a `#N` only when a commit subject references it;
  otherwise describe the change without a link.
- **Keep ADRs out of the public notes** — neutral, user-facing wording only.
- **Never commit release notes to the repository.** They live on the Release.
