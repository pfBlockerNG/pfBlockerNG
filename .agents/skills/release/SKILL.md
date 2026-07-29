---
name: release
description: >
  Cut a pfBlockerNG release by validating the tag scheme, then DISPATCHING
  .github/workflows/release.yml — the workflow builds and VERIFIES first, then
  pushes the tag and leaves a complete DRAFT Release (source archive + .pkg
  assets, placeholder body). It stops there: this skill never writes notes and
  never publishes. Report the draft URL; /release-with-changelog is the path that
  writes the notes onto that draft and publishes it. You do NOT push a tag by
  hand. Enforces the scheme before
  dispatch: prereleases (vX.Y.Z.alpha.N | .beta.N | .rc.N) cut from `devel` only,
  stable (vX.Y.Z) from `main` only — the same rule release-version.sh, the
  workflow's prepare-release job, and the pre-push hook enforce, so a bad tag is
  refused locally instead of failing in CI. Args: <tag> (e.g. v4.0.0.alpha.1)
  [--dry-run]. Use when the user says "cut a release", "release vX.Y.Z…", "tag a
  release", "publish the alpha", or invokes /release.
---

You cut a pfBlockerNG release **up to the draft**. **`release.yml` is
`workflow_dispatch`-only and does everything up to that point** — its `prepare-release`
job validates the scheme, asserts CI is green, **pins the channel-branch tip** and mints
the tag locally; the workflow then builds every `.pkg` from that pinned SHA, runs the
verification suites against those exact artifacts and that exact source, and only **when
green** pushes the tag (on the pinned SHA), creates the Release **as a DRAFT**, attaches
the assets and health-checks it. So you do **not** `git tag`/`git push` a tag by hand; you
**dispatch the workflow** with `dry_run=false`. Everything below is the friendly pre-check
that the tag + commit are correct **before** that dispatch.

**The workflow never publishes.** It hands you a complete draft with a placeholder body.
Writing the real notes + title onto that draft and publishing it is a separate, explicit
step — **`/release-with-changelog`** does exactly that (it invokes this skill first). If
the user asked for `/release`, stop at the draft and say so; do not publish.

**A failed run leaves nothing behind** — no tag, no draft, nothing pushed to any branch.
The version number is not burned, so re-dispatching the SAME tag after fixing the cause is
the normal recovery.

**Which channels verify live.** `alpha` and `beta` tags **skip** the live smoke/UI suites —
their mandatory gate is CI green on the release commit. `rc` and stable run the suites in
full and tag only on green. Add `-f force_suites=true` to run them for an alpha/beta too.
Independently, only a matrix row whose ci-metadata `status` is a released pfSense version
(`active`/`GA`) can veto; a `beta`-status row (e.g. a pfSense Plus beta) still runs and
reports, loudly demoted, but cannot fail the release.

`scripts/release-version.sh` is the single source of truth for the scheme; **call it,
never re-implement the regex.** The workflow's `prepare-release` job re-validates the
scheme, and `.githooks/pre-push` re-validates the tag the workflow pushes — so this skill
is the pre-check, those are the backstops.

## Arguments

- `<tag>` — required, e.g. `v4.0.0.alpha.1` (must start with `v`).
- `--dry-run` — dispatch the workflow's no-publish harness
  (`gh workflow run release.yml -f tag=<tag> -f dry_run=true`) to validate the scheme,
  build the `.pkg` artifacts, and render the release body — publishing nothing, tag never
  created. The real release is the same dispatch with `dry_run=false`.

## The scheme (enforced, not advisory)

| Tag | Channel | Cut from | Result |
| --- | --- | --- | --- |
| `vX.Y.Z.alpha.N` / `.beta.N` / `.rc.N` | devel | **`devel` only** | GitHub **pre-release** |
| `vX.Y.Z` | stable | **`main` only** | full release |

Refuse — do not push — when the tag's channel does not match the branch it would sit
on: an `alpha`/`beta`/`rc` tag whose commit is on `main`, or a bare `vX.Y.Z` whose
commit is only on `devel`. This is the "no alpha/beta/rc off main, no production off
devel" guard, applied before the tag exists.

## Steps

1. **Classify the tag.** Run `sh scripts/release-version.sh <tag>` (no branch arg).
   A non-zero exit ⇒ malformed tag — stop and show its error. Capture `channel`,
   `prerelease`, `portversion`.

2. **Pick the channel branch.** `devel` for a prerelease, `main` for stable. This is
   the branch the tag must be cut from.

3. **Fetch + locate the commit.** `git fetch origin --tags`. The release commit is the
   **tip of the channel branch** (`origin/devel` or `origin/main`) unless the user named
   a specific commit; that commit must be reachable from the channel branch.
   - Re-assert the scheme against the resolved branch: `sh scripts/release-version.sh
     <tag> <branch>` must exit 0. (This is exactly what the pre-push hook and the
     workflow's metadata step run.)
   - For a **stable** tag, the commit must be on `origin/main`. For a **prerelease**,
     the commit must be on `origin/devel` but **not** already on `origin/main` (a
     prerelease of code that is already stable makes no sense) — mirror the pre-push
     hook's `merge-base --is-ancestor` checks.

4. **Pre-flight gates** (stop on any failure, report which):
   - **No PUBLISHED release for the tag.** A published GitHub Release is immutable+final
     → refuse (bump the version). A tag that exists with **no release yet** (or only a
     DRAFT) is a run that crashed *after* tagging — that is FINE **as long as the channel
     branch has not moved since**: `tag-release` reuses a tag that already points at the
     SHA this run verified, and refuses (loudly, without moving it) a tag pointing at any
     other commit. If the branch has moved, delete the unpublished tag or bump the
     version. Only a **published** release is an outright blocker (`gh release view <tag>`
     ⇒ if it exists and is not a draft, stop).
   - The local channel branch is up to date with its remote (the notes commit, if any, is
     already pushed — the workflow tags the **remote** branch tip, so an un-pushed local
     commit would be missed).
   - **CI is green on the release commit** — the `All tests passed` check-run on the
     channel-branch tip must be `success`. NOTE: the workflow's `verify-checks` walks back
     first-parent ancestors past docs-only commits (a docs-only tip skips CI via
     `paths-ignore` and carries no check-run), so check the nearest ancestor
     **with** a check-run. Read via `gh api repos/<owner>/<repo>/commits/<sha>/check-runs`.
     If pending, wait; if failed, stop.
   - Git hooks are active (`git config core.hooksPath` = `.githooks`); if not, run
     `sh scripts/setup-hooks.sh` so the pre-push backstop (on the tag the workflow pushes)
     is armed.

5. **Notes.** Nothing to prepare: release notes are **not files in this repository**. The
   workflow gives the draft a deterministic placeholder body ending in the compare link, and
   the title `YYYY-MM-DD - VERSION`. The real notes and the final title are written onto the
   draft afterwards by **`/release-with-changelog`** (or by a human), which then publishes
   it. Don't author notes here.

6. **Confirm, then dispatch.** Dispatching with `dry_run=false` **becomes** irreversible
   once verification is green — it pushes the tag and drafts the Release. It still publishes
   nothing, and a run that fails before the tag leaves no trace at all.
   Confirm the tag + channel-branch tip with the user, then dispatch — **do not push a tag
   by hand**:

   ```sh
   gh workflow run release.yml --ref <default-branch> -f tag=<tag> -f dry_run=false
   ```

   Add `-f force_suites=true` to run the live smoke/UI suites for an `alpha`/`beta` tag
   (they always run for `rc`/stable).

   Add `-f retag=true` to **re-cut a tag that is already pushed** — the recovery for a run
   that crashed after pushing its tag while the channel branch moved on, or simply when you
   want a clean cut on the current tip. It deletes the existing tag (and an **assetless**
   draft Release for it) before pinning. It **refuses** when the tag has a **published**
   Release — that is immutable, and the only way forward is the next `.N` — and when its
   draft **already has assets**, where the right move is to finish that draft (write the
   notes, publish) rather than throw it away. Leave it `false` for a normal cut.

   The workflow pins the channel-branch tip, tags **that** commit after verification, and
   the `pre-push` hook re-validates the tag as it pushes. On `--dry-run`, the
   same dispatch with `dry_run=false` → `dry_run=true` (publishes nothing). Dispatch is
   only allowed from the default branch (`devel`), but the workflow operates on the
   resolved channel branch regardless. After dispatching, find the run
   (`gh run list --workflow=release.yml`) to report/watch it.

7. **Report the DRAFT.** After dispatch, point at the running `Release` workflow (Actions
   tab) and state what it will produce:
   - a **DRAFT** GitHub Release (`pre-release` for alpha/beta/rc), title
     `YYYY-MM-DD - <version>`, body a placeholder ending in the compare link;
   - one **`.pkg` per FreeBSD major** (plus each major's `extra_pkgs` dependency packages)
     attached to that draft, alongside the `src/` source archive;
   - the **port bump** on `pfBlockerNG/FreeBSD-ports@pfblockerng/use-github`, as the run's
     terminal job — so when the run ends the only things left are the changelog and the
     publish;
   - **nothing published**: the pkg-repo republish fires when the release is actually
     published, from `release-published.yml`.

   Offer to watch the run. When it finishes, report the **draft Release URL** (the
   `draft-healthcheck` job prints it in the run summary; `gh release view <tag> --json url`
   also works) and say plainly that the release is **drafted pending notes** — someone must
   write the notes + title onto it and publish it, which `/release-with-changelog` does.

## Guardrails

- **Never** dispatch a release whose channel/branch pairing
  `release-version.sh <tag> <branch>` rejects. The scheme is non-negotiable; the
  workflow's `prepare-release` (and the pre-push hook on the tag it pushes) will reject it
  anyway, so catch it here.
- **Don't push a tag by hand** — dispatching the workflow is the whole job; it creates and
  pushes the tag, and only after the build and the verification suites are green. A
  hand-pushed tag now *blocks* the run unless it happens to point at the exact commit the
  run pinned (the check fires in `prepare-release`, before the build).
- **Never publish from this skill.** It stops at the draft. Publishing is
  `/release-with-changelog`'s last step, after the notes are written.
- **Never** re-release a tag with a **published** Release — cut the next `.N`
  (e.g. `.alpha.2`) instead. A tag with no/draft release is resumable, not a re-release.
- **A run that failed verification burned nothing** — no tag, no draft, the version number
  is still available. Fix the cause, land it, re-dispatch the same tag.
- **Never** push directly to `main`/`devel` from this skill — code reaches the channel
  branch through the normal PR/landing flow first; this skill only dispatches the workflow.
- The dry-run dispatch publishes nothing — use it freely to validate before the real cut.
