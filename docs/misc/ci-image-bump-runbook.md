# CI runner image bump — runbook

Scope: changing and publishing the CI runner images. Load when: touching
`.github/docker/**`, `composer.json`, `composer.lock`, or `tests/smoke/requirements.txt`.

How to change `ghcr.io/pfblockerng/ci-runner` (and `ci-runner-vm`) and land the change.
Read this before editing anything under `.github/docker/`, `composer.json`,
`composer.lock`, or `tests/smoke/requirements.txt` — those are the paths that decide
what the image contains.

The short version: **the image is published before the pull request that uses it can go
green, from that same branch, by a manual dispatch.** The bump and the repin travel in one
commit; the publish happens first.

## Why it works this way

The published tag is immutable by construction. `ci-images.yml` refuses to push a tag the
registry already carries, so any change to the image content must bump
`.github/docker/VERSION`. Every workflow pins that series by literal
(`image: ghcr.io/pfblockerng/ci-runner:<N>`), and
`tests/test_issue2231_workflow_hygiene.py::test_workflows_pin_the_current_ci_runner_series`
requires `VERSION` and every pin to agree **in one commit**.

That rules out splitting the work across two pull requests: a PR that bumps `VERSION`
without repinning fails the guard, and a PR that repins to a series nobody published
cannot start a single containerised job. `ci-images.yml` resolves it by allowing a manual
`workflow_dispatch` to publish from **any** ref — a deliberate act by someone with write
access, which a pull request cannot provoke, and which the overwrite guard still confines
to series the registry does not yet carry.

## Procedure

1. **Change the image and bump the series in one commit.** Edit the Dockerfile (or
   whichever build input changed), set `.github/docker/VERSION` to the next integer, and
   repoint every consumer to it. Do not hand-derive the list:

   ```sh
   files=$(grep -rl "ci-runner\(-vm\)\?:<OLD>\([^0-9]\|$\)" --exclude-dir=.git --exclude-dir=legacy .)
   printf '%s\n' "$files" | xargs sed -i '' -E 's#(ci-runner(-vm)?):<OLD>([^0-9]|$)#\1:<NEW>\3#g'
   ```

   Consumers include the workflows, `.github/docker/ci-runner-vm.Dockerfile`'s
   `BASE_IMAGE`, `scripts/local-smoke.sh` and the shell specs that assert those literals.
   `scripts/run-in-docker.sh` needs no edit: it reads `VERSION`.

2. **Build and test it locally first.** The series you publish is permanent, so do not
   publish one you have not run:

   ```sh
   PFB_BUILD=1 scripts/run-in-docker.sh true                  # builds the new series locally
   PFB_IMAGE=ghcr.io/pfblockerng/ci-runner:<NEW>-<arch> scripts/agent/run-gates.sh
   ```

   The local build runs the in-Dockerfile self-check, so a missing or broken baked tool
   fails here rather than after publication.

3. **Push the branch, then publish the series from it.**

   ```sh
   gh workflow run ci-images.yml --ref <branch>
   ```

   Wait for it, then confirm both images exist before relying on them:

   ```sh
   docker manifest inspect ghcr.io/pfblockerng/ci-runner:<NEW>
   docker manifest inspect ghcr.io/pfblockerng/ci-runner-vm:<NEW>
   ```

4. **Open the pull request as usual.** Its jobs now resolve the new series, so CI can go
   green and the change lands through the normal flow in
   [`landing.md`](../../.agents/policy/landing.md). The `CI runner images` run that fires
   on the eventual merge to `devel` is a no-op: the marker matches what the dispatch
   already published, and it reports `already published from these exact build inputs`.

## Things that will bite

- **A published series is never rewritten.** If the image needs another change after you
  published it, bump again. Deleting tags to "republish" lands in the workflow's
  partly-published branch, which fails loudly and tells you to delete *every* tag of the
  series (`<N>`, `<N>-amd64`, `<N>-arm64`, `<N>-<marker>`) or bump.
- **The marker decides whether a rebuild happens at all.** It fingerprints the
  `.github/docker` tree plus every build-context path the Dockerfiles COPY —
  `tests/smoke/requirements.txt`, `composer.json`, `composer.lock`. Adding a new `COPY`
  source without adding it to that fingerprint makes a change to that file invisible: the
  run goes green having rebuilt nothing.
  `tests/test_ci_runner_images.py::test_the_marker_is_produced_as_well_as_consumed`
  derives the requirement from the Dockerfiles, so a new COPY source fails there first.
- **Composer metadata is part of the image.** The vendor tree is baked, so changing
  `composer.json` or `composer.lock` is an image change and takes this whole procedure.
  `scripts/ci-vendor.sh` fails every PHP leg loudly when a checkout's metadata has moved
  past the baked tree — including autoload-only edits, which leave `composer.lock`
  byte-identical.
