---
name: release
description: >
  Cut a pfBlockerNG release by validating the tag scheme, then DISPATCHING
  .github/workflows/release.yml — the workflow itself creates+pushes the tag and
  publishes (GitHub Release + .pkg artifacts + self-hosted pkg-repo publish +
  FreeBSD-ports bump). You do NOT push a tag by hand. Enforces the scheme before
  dispatch: prereleases (vX.Y.Z.alpha.N | .beta.N | .rc.N) cut from `devel` only,
  stable (vX.Y.Z) from `main` only — the same rule release-version.sh, the
  workflow's prepare-release job, and the pre-push hook enforce, so a bad tag is
  refused locally instead of failing in CI. Args: <tag> (e.g. v4.0.0.alpha.1)
  [--dry-run]. Use when the user says "cut a release", "release vX.Y.Z…", "tag a
  release", "publish the alpha", or invokes /release.
---

You cut a pfBlockerNG release. **`release.yml` is `workflow_dispatch`-only and does it
all** — its `prepare-release` job resolves the channel-branch tip, commits the changelog
when absent, **creates and pushes the tag itself**, then builds + publishes. So you do
**not** `git tag`/`git push` a tag by hand; you **dispatch the workflow** with
`dry_run=false`. Everything below is the friendly pre-check that the tag + commit are
correct **before** that irreversible dispatch.

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
     DRAFT) is a half-finished prior run — that is FINE: the workflow's `tag_state` step
     **resumes** it (reuses the tag, updates the draft in place). So a bare pre-existing
     tag is not a blocker; only a published release is. (`gh release view <tag>` ⇒ if it
     exists and is not a draft, stop.)
   - The local channel branch is up to date with its remote (the notes commit, if any, is
     already pushed — the workflow tags the **remote** branch tip, so an un-pushed local
     commit would be missed).
   - **CI is green on the release commit** — the `All tests passed` check-run on the
     channel-branch tip must be `success`. NOTE: the workflow's `verify-checks` walks back
     first-parent ancestors past docs-only commits (a `docs/release-notes/<tag>.md` commit
     skips CI via `paths-ignore` and carries no check-run), so check the nearest ancestor
     **with** a check-run. Read via `gh api repos/<owner>/<repo>/commits/<sha>/check-runs`.
     If pending, wait; if failed, stop.
   - Git hooks are active (`git config core.hooksPath` = `.githooks`); if not, run
     `sh scripts/setup-hooks.sh` so the pre-push backstop (on the tag the workflow pushes)
     is armed.

5. **Notes source.** The release body comes from `docs/release-notes/<tag>.md` when that file
   is committed on the channel branch — it is **authoritative**, and the GitHub Models step is
   **skipped** (an optional first-line `<!-- SUMMARY: … -->` marker becomes the title suffix,
   stripped from the body). When no file exists, GitHub Models (`openai/gpt-4.1`) drafts it from
   the commit range and the `persist-notes` job records it. To author/curate the notes yourself
   (or to "play the model" when Models is unavailable), use **`/release-with-changelog`** — it
   writes the file, commits it, then calls this skill. Don't author notes here unless asked.

6. **Confirm, then dispatch.** Dispatching with `dry_run=false` is **irreversible and
   public** (the workflow creates+pushes the tag, cuts a GitHub Release, publishes the
   `.pkg`, republishes the pkg repo, and bumps the ports fork). Confirm the
   tag + channel-branch tip with the user, then dispatch — **do not push a tag by hand**:

   ```sh
   gh workflow run release.yml --ref <default-branch> -f tag=<tag> -f dry_run=false
   ```

   The workflow tags the channel-branch tip itself (resuming a pre-existing un-released
   tag), and the `pre-push` hook re-validates that tag as it pushes. On `--dry-run`, the
   same dispatch with `dry_run=false` → `dry_run=true` (publishes nothing). Dispatch is
   only allowed from the default branch (`devel`), but the workflow operates on the
   resolved channel branch regardless. After dispatching, find the run
   (`gh run list --workflow=release.yml`) to report/watch it.

7. **Report.** After dispatch, point at the running `Release` workflow (Actions tab),
   and state what it will produce:
   - a GitHub **Release** (`pre-release` for alpha/beta/rc), title
     `pfBlockerNG <version> — <3-word summary>`, body grouped Features / Improvements /
     Bug Fixes ending in the compare link;
   - one **`.pkg` per variant × FreeBSD major × arch**, named
     `pfSense-pkg-pfBlockerNG[-devel]-<portversion>-<varslug>-FreeBSD-<major>-<arch>.pkg`
     (e.g. `…-4.0.0.alpha.1-ce-2.8-FreeBSD-15-amd64.pkg`), attached to the Release;
   - the **self-hosted pkg repo** republish (`pfBlockerNG/pkg`) so the build appears at
     `pfblockerng.github.io/pkg` within minutes;
   - the **port bump** on `pfBlockerNG/FreeBSD-ports@pfblockerng/use-github`.

   Offer to watch the workflow and report its result.

## Guardrails

- **Never** dispatch a release whose channel/branch pairing
  `release-version.sh <tag> <branch>` rejects. The scheme is non-negotiable; the
  workflow's `prepare-release` (and the pre-push hook on the tag it pushes) will reject it
  anyway, so catch it here.
- **Don't push a tag by hand** — dispatching the workflow is the whole job; it creates and
  pushes the tag. (A hand-pushed tag is tolerated only because `tag_state` resumes an
  un-released tag — but the workflow is the intended tagger.)
- **Never** re-release a tag with a **published** Release — cut the next `.N`
  (e.g. `.alpha.2`) instead. A tag with no/draft release is resumable, not a re-release.
- **Never** push directly to `main`/`devel` from this skill — code reaches the channel
  branch through the normal PR/landing flow first; this skill only dispatches the workflow.
- The dry-run dispatch publishes nothing — use it freely to validate before the real cut.
