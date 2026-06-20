---
name: release
description: >
  Cut a pfBlockerNG release by validating and pushing a version tag — the tag
  push is what triggers .github/workflows/release.yml (GitHub Release + .pkg
  artifacts + self-hosted pkg-repo publish + FreeBSD-ports bump). Enforces the
  tag scheme BEFORE the tag is pushed: prereleases (vX.Y.Z.alpha.N | .beta.N |
  .rc.N) cut from `devel` only, stable (vX.Y.Z) from `main` only — the same
  rule release-version.sh, the pre-push hook, and the workflow enforce, so a
  bad tag is refused locally instead of failing in CI. Args: <tag> (e.g.
  v4.0.0.alpha.1) [--dry-run]. Use when the user says "cut a release", "release
  vX.Y.Z…", "tag a release", "publish the alpha", or invokes /release.
---

You cut a pfBlockerNG release. The tag push is the trigger — there is no separate
"publish" button. Everything below is about making sure the tag is correct and the
commit is ready **before** the irreversible push, then pushing it.

`scripts/release-version.sh` is the single source of truth for the scheme; **call it,
never re-implement the regex.** The `.githooks/pre-push` hook re-validates on push as
the final gate — so this skill is the friendly pre-check, the hook is the backstop.

## Arguments

- `<tag>` — required, e.g. `v4.0.0.alpha.1` (must start with `v`).
- `--dry-run` — do NOT push the tag. Instead dispatch the workflow's no-publish
  harness (`gh workflow run release.yml -f tag=<tag> -f dry_run=true`) to validate the
  scheme, build the `.pkg` artifacts, and render the release body — publishing nothing.

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
   - The tag does not already exist (`git tag -l <tag>` empty, and no remote
     `refs/tags/<tag>`). Releases are immutable — never move an existing tag.
   - Working tree is clean and the local channel branch is up to date with its remote
     (no un-pushed release commit).
   - **CI is green on the release commit** — the `All tests passed` check-run must be
     `success` (the workflow's `verify-checks` job will hard-fail otherwise). Read it
     via the GitHub MCP tools / `gh api repos/<owner>/<repo>/commits/<sha>/check-runs`.
     If it is pending, wait or tell the user to wait; if it failed, stop.
   - Git hooks are active (`git config core.hooksPath` = `.githooks`); if not, run
     `sh scripts/setup-hooks.sh` so the pre-push backstop is armed.

5. **Optional — curated notes.** The release body is auto-drafted by GitHub Models
   (`openai/gpt-4.1`) from the commit range and persisted to `docs/release-notes/<tag>.md`.
   If the user wants hand-written notes instead, they commit `docs/release-notes/<tag>.md`
   on the channel branch first — the workflow falls back to it when present and inference
   is unavailable. Do not author it unless asked.

6. **Confirm, then push.** Pushing a release tag is **irreversible and public** (it cuts
   a GitHub Release, publishes the `.pkg`, and bumps the ports fork). Confirm the
   tag + commit + channel with the user, then:

   ```sh
   git tag -a <tag> <commit> -m "<tag>"
   git push origin <tag>            # pre-push hook re-validates here
   ```

   On `--dry-run`, skip the tag entirely and dispatch the harness instead:
   `gh workflow run release.yml -f tag=<tag> -f dry_run=true` (dispatchable only from
   the default branch).

7. **Report.** After the push, point at the running `Release` workflow (Actions tab),
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

- **Never** push a tag whose channel/branch pairing `release-version.sh <tag> <branch>`
  rejects. The scheme is non-negotiable; the hook will reject it anyway, so catch it here.
- **Never** move or delete an existing release tag to "re-release" — cut the next `.N`
  (e.g. `.alpha.2`) instead.
- **Never** push directly to `main`/`devel` from this skill — it only creates and pushes
  a **tag**. Code reaches the channel branch through the normal PR/landing flow first.
- The dry-run dispatch publishes nothing — use it freely to validate before the real tag.
