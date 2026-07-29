---
name: release
description: >
  Cut a pfBlockerNG release by validating the tag scheme, then DISPATCHING
  .github/workflows/release.yml — the workflow builds and VERIFIES first, then
  creates+pushes the tag and publishes (GitHub Release + .pkg artifacts +
  self-hosted pkg-repo publish + FreeBSD-ports bump); a failed run leaves no tag
  and no draft behind. You do NOT push a tag by hand. Enforces the scheme before
  dispatch: prereleases (vX.Y.Z.alpha.N | .beta.N | .rc.N) cut from `devel` only,
  stable (vX.Y.Z) from `main` only — the same rule release-version.sh, the
  workflow's prepare-release job, and the pre-push hook enforce, so a bad tag is
  refused locally instead of failing in CI. Args: <tag> (e.g. v4.0.0.alpha.1)
  [--dry-run]. Use when the user says "cut a release", "release vX.Y.Z…", "tag a
  release", "publish the alpha", or invokes /release.
---

You cut a pfBlockerNG release. **`release.yml` is `workflow_dispatch`-only and does it
all** — its `prepare-release` job resolves the channel-branch tip, commits the changelog
when absent and **pins the release SHA**; the workflow then builds every `.pkg` from that
pinned SHA, runs the verification suites against those exact artifacts, and only **when
green** creates + pushes the tag (on the pinned SHA) and publishes. So you do **not**
`git tag`/`git push` a tag by hand; you **dispatch the workflow** with `dry_run=false`.
Everything below is the friendly pre-check that the tag + commit are correct **before**
that dispatch.

**A failed run leaves nothing on GitHub** (issue #1855): no tag, no draft — only the
docs-only notes commit, which the retry reuses. The version number is not burned, so
re-dispatching the SAME tag after fixing the cause is the normal recovery.

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
     first-parent ancestors past docs-only commits (a `docs/release-notes/<tag>.md` commit
     skips CI via `paths-ignore` and carries no check-run), so check the nearest ancestor
     **with** a check-run. Read via `gh api repos/<owner>/<repo>/commits/<sha>/check-runs`.
     If pending, wait; if failed, stop.
   - Git hooks are active (`git config core.hooksPath` = `.githooks`); if not, run
     `sh scripts/setup-hooks.sh` so the pre-push backstop (on the tag the workflow pushes)
     is armed.

5. **Notes source.** The release body comes from `docs/release-notes/<tag>.md` when that file
   is committed on the channel branch — it is **authoritative** (an optional first-line
   `<!-- SUMMARY: … -->` marker becomes the title suffix, stripped from the body). When no file
   exists, the workflow writes a deterministic placeholder body instead (GitHub Models drafting
   was removed — it never produced a working result; release run 30379645002). To author the
   real notes, use **`/release-with-changelog`** — it writes the file, commits it, then calls
   this skill. Don't author notes here unless asked.

6. **Confirm, then dispatch.** Dispatching with `dry_run=false` **becomes** irreversible and
   public once verification is green (tag, GitHub Release, `.pkg` assets, pkg-repo
   republish, ports-fork bump) — a run that fails before that point publishes nothing.
   Confirm the tag + channel-branch tip with the user, then dispatch — **do not push a tag
   by hand**:

   ```sh
   gh workflow run release.yml --ref <default-branch> -f tag=<tag> -f dry_run=false
   ```

   Add `-f force_suites=true` to run the live smoke/UI suites for an `alpha`/`beta` tag
   (they always run for `rc`/stable).

   The workflow pins the channel-branch tip, tags **that** commit after verification, and
   the `pre-push` hook re-validates the tag as it pushes. On `--dry-run`, the
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
  pushes the tag, and only after the build and the verification suites are green. A
  hand-pushed tag now *blocks* the run unless it happens to point at the exact commit the
  run verified.
- **Never** re-release a tag with a **published** Release — cut the next `.N`
  (e.g. `.alpha.2`) instead. A tag with no/draft release is resumable, not a re-release.
- **A run that failed verification burned nothing** — no tag, no draft, the version number
  is still available. Fix the cause, land it, re-dispatch the same tag.
- **Never** push directly to `main`/`devel` from this skill — code reaches the channel
  branch through the normal PR/landing flow first; this skill only dispatches the workflow.
- The dry-run dispatch publishes nothing — use it freely to validate before the real cut.
