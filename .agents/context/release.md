# Branches and releases

Scope: channels, tag scheme, release pipeline, self-hosted pkg repo. Load when: cutting a
release or touching `release.yml`, ports plumbing, or the pkg-repo publish path.

| Branch | Channel | Ships to |
| ------ | ------- | -------- |
| `main` | Stable | `net/pfSense-pkg-pfBlockerNG` |
| `devel` | Development | `net/pfSense-pkg-pfBlockerNG-devel` |

**Tag scheme (single source of truth: `scripts/release-version.sh`; behaviour pinned by
`tests/test_release_version.py`).** Semver core `X.Y.Z`: pre-releases
`vX.Y.Z.alpha.N`/`.beta.N`/`.rc.N` cut from **`devel` only** → GitHub pre-release (FreeBSD
pkg orders the stage keywords natively below the bare release; the tag maps to `PORTVERSION`
verbatim); stable `vX.Y.Z` from **`main` only** (typically the final rc's commit; `devel`
then opens `X.(Y+1).0.alpha.1`). `release.yml` and `.githooks/pre-push` both consume the
script, so the rule never drifts — `pre-push` only ever sees a tag pushed by hand, since the
runner's checkout sets no `core.hooksPath`. A release is a **dispatch**, never a
hand-pushed tag: one `release.yml` run builds, verifies, tags, drafts and finally bumps the
port on our **`pfBlockerNG/FreeBSD-ports` fork** (self-hosted distribution, no upstream PR).
See *Pipeline order* below. **Nightly builds get no GitHub Release.**

## Pipeline order — build, verify, tag, DRAFT — then stop (issue #1855)

`release.yml` is one dispatch, one run, and it never publishes:

1. **`prepare-release`** (real only) — validate the tag↔channel scheme, refuse an already
   **published** release, assert **CI green on the release commit** (`release-ci-gate.sh`,
   walking past docs-only commits), **pin** the channel-branch tip as the release commit and
   **mint the annotated tag on it locally**. *Nothing is pushed* — not the tag, not the
   branch. Minting early is what turns a conflicting tag into a five-second failure instead
   of an hour-long one.
2. **Build + verify** — `resolve-stamp` / `build-pkgs-portable` (per-major `.pkg`s +
   `extra_pkgs` dep packages) build **from the pinned SHA** as *workflow* artifacts, then
   `ui-suite` / `smoke-suite` verify **those exact artifacts** (`pkg_artifact_prefix:
   pfBlockerNG-relpkg`) **from that same source tree** (`checkout_ref`, issue #1859) — never
   Release assets, so they need no tag and no Release.
3. **`tag-release`** — the FIRST irreversible step: pushes the tag **on the pinned SHA** (not
   on "the branch tip now"), gated on the build and, when they ran, on **both** suite
   AND-gates.
4. **`release` → `attach-pkgs` → `draft-healthcheck` → `sync-ports-fork`** — create the
   Release as a **DRAFT** with a deterministic placeholder body, attach the assets, assert
   the draft is complete, then bump the port's `PORTVERSION` on our FreeBSD-ports fork.
   **The draft is the end state**: when the run finishes, the only things left are *write
   the changelog* and *publish*.

A failed run leaves **nothing** behind: no tag, no draft, nothing pushed to any branch —
re-dispatch the same tag once the cause is fixed. `tag-release` is the single seam for the
suite gate; everything after it inherits that transitively. The resume path is narrowed to
the **crash-after-tag** window: a pre-existing tag on the pinned SHA is reused, a tag on any
other commit is refused loudly and never moved.
`tests/test_release_tag_after_verify.py` walks the whole `needs:` graph, so neither the
pre-#1855 order nor an in-pipeline publish can come back silently.

**Which channels verify live.** `prekind` (from `release-version.sh`) decides:
`alpha`/`beta` **skip** the live smoke/UI suites — the mandatory gate is the CI-green
assertion above; `rc` and stable run them in full. One code path: for an alpha/beta the
verification phase is simply empty, not a parallel pipeline. The `force_suites` dispatch
input (default `false`) forces them on for an alpha/beta; it can only ever *add* verification.

**Which rows may veto.** A matrix row gates a release **iff its ci-metadata `status` is a
released pfSense version** (`active`, or its legacy alias `GA`). Every other value — `beta`,
anything added later, absent/unrecognized — is non-blocking: the leg still runs and still
reports, emits a loud demotion warning naming the row and its status, and cannot fail the
release. Predicate + warning live in `scripts/resolve-legs.sh`, switched on by the suites'
`release_gate` input (release-only; PR/nightly gating is unchanged). Demoting rows one at a
time is safe; demoting **all** of them is not — legs to run but not one able to veto makes
the whole live phase advisory inside a green run, so that case is a hard `::error::` and a
distinct **exit 3**, not a warning.

**Dry-run** (`dry_run=true`, the default) builds and verifies off the **dispatch ref**, then
stops: no tag, no Release, no push. `prepare-release` is skipped **wholesale**, so a dry run
pins nothing (every downstream job falls back to the dispatch ref's HEAD) and gets none of
that job's gates either: no CI-green assertion, no published-release refusal, no tag-state
report, no early stale-tag conflict check, and `retag` does nothing at all — its only
implementation lives inside the skipped job. What survives is the scheme check, at
`read-matrix`'s `release-version.sh` classification, so a malformed tag still fails it.

**Re-cutting a tag that is already pushed** — `retag=true` (dispatch input, default
`false`). The pin is the channel-branch tip, so a run that crashed *after* pushing its tag,
on a branch that has since moved, would otherwise pin a new commit and reject its own tag as
stale. `retag=true` deletes the existing tag first and re-cuts it on the freshly pinned tip.
It is obeyed only when that is provably safe, and refuses loudly otherwise:

| State of the tag's Release | `retag=true` does |
| --- | --- |
| **published** | **refuses** — a published Release is immutable; retagging cannot rescue it, cut the next `.N` |
| **draft with assets** | **refuses** — assets do not prove a finished cut (`release` attaches the source archive before `attach-pkgs` adds the `.pkg`s), so it never deletes them: re-dispatch with `retag=false` to finish that draft, or delete it by hand to start over |
| draft with no assets | deletes the draft **and** the tag (an orphaned draft would collide with this run's own) |
| no Release | deletes the tag |
| no tag at all | no-op |

This is the only place the pipeline removes anything from GitHub; it lives in
`prepare-release` (the sole reason that job holds `contents: write`), runs before the pin,
and never fires in a dry run.

**One trust rule, wherever a release workflow executes a script:** anything run as shell
comes from a second, sparse checkout pinned to `github.workflow_sha` (`pfblockerng-src/`) —
the revision the workflow itself came from — never from the tree being released. That covers
`release-version.sh` + `release-ci-gate.sh` in `prepare-release`, `release-version.sh` in the
`release` job, `portrevision-rebuild.sh` in `sync-ports-fork`, and `release-version.sh` in
`release-published.yml`'s `resolve`. It holds even where the job currently carries no
credential worth stealing: the blast radius is a property of a job's present body, not of the
design. The rule is mechanical rather than per-call — "this one runs before the branch reset,
so it is fine" is what let two `contents: write` jobs execute the released tree's scripts.
*Exempt by nature:* `build-pkgs-portable` and the live suites do run scripts out of the
released tree, because building and testing that tree is the whole point; they hold no write
credential and persist no checkout credentials. `read-matrix` classifies the tag from the
dispatch ref's own tree, which is the trusted revision already.

## Release notes — authored onto the Release, never committed

**There are no release-notes files in this repository.** A committed changelog forces a
changelog commit, which forces a push to the channel branch and a re-generation whenever
`devel` moves — and the released source tree should not carry its own changelog. Past
releases' bodies live on their GitHub Release pages; that is the record.

`release.yml` gives the draft a **deterministic placeholder body** ending in the compare link
(`prev_tag` classifies each tag's channel via `release-version.sh` to find the previous
same-channel release for that link) and the title `YYYY-MM-DD - VERSION` (ISO date prefixed
so GitHub's alphabetical release sort stays chronological). In-pipeline LLM drafting is
wanted but no free option has worked — GitHub Models was removed after never producing a
working result (release run 30379645002); **do not add one**.

The real notes and the final title are authored **onto the draft**, from the commit range,
using the template in `scripts/release-notes-prompt.txt` (group user-facing changes under
**Features / Improvements / Bug Fixes** with PR/issue links, CI/test/tooling/ADR noise
filtered) — by a human, or by Claude via **`/release-with-changelog`**. Publishing the draft
is that same step's last action.
**Nightly builds get no GitHub Release.**

## Publishing, and what it triggers

Publishing is deliberately **outside** `release.yml` — but so is almost nothing else. The
FreeBSD-ports `PORTVERSION` bump is the **terminal job of the release run**
(`sync-ports-fork`, gated on `draft-healthcheck` and on `dry_run == 'false'`): a devel
release bumps `-devel` and `-nightly` in one commit, and `GH_TAGNAME` is `v${PORTVERSION}`
in the Makefile, so it self-resolves to the matching tag.

The only thing that genuinely has to wait for the publish is **`repo-publish`** in
**`.github/workflows/release-published.yml`** (`on: release: types: [published]`): it
dispatches `pfBlockerNG/pkg`'s `publish.yml`, which enumerates this repo's **published**
Releases and downloads their assets, so the new build appears at `pfblockerng.github.io/pkg`
within seconds (its daily schedule is the backstop). Its `resolve` job still classifies the
published tag and fails loudly, with the reason, on an off-scheme one.

`pfBlockerNG/pkg` derives the **nightly** version from the `-nightly` port's `PORTVERSION`,
so it must never read the fork before the bump lands. That used to be a `needs:` edge; it is
now **structural** — the bump happens inside the release run, strictly before any publish can
occur — and the reason is recorded in `release-published.yml` so nobody re-adds a dependency
on a job that is no longer there.

**Accepted cost:** a draft that is never published leaves the fork bumped to a version that
never shipped. The bump *sets* the version rather than incrementing it, so the next release's
bump overwrites it.

## Self-hosted pkg repository (ADR-17)

GitHub Pages repo (`pfblockerng.github.io/pkg`);
repo `priority: 100` dominates version selection, so our build wins over Netgate's. **Hard
rule (ADR-20): the catalog is keyed by *varver* (`ce-2.8` / `plus-26.03`), NOT by `${ABI}`**
— an ABI is not 1:1 with a version/edition's `php`/`py3` build inputs; the incidental
CE→FreeBSD15 / Plus→FreeBSD16 split is not a licence to key by ABI. **Never make that
simplification.** Mechanics: below + architecture-notes "Self-hosted pkg
distribution".

### Mechanics

Beyond the Netgate ports channel we publish a self-hosted FreeBSD `pkg` repository on GitHub
Pages (`pfblockerng.github.io/pkg`; NONE-signed, TLS-anchored; a derived index rebuilt from
**all** Releases each deploy). Cross-repo selection is keyed on repo **`priority:`** — it
dominates version — so our `priority: 100` (set by `add-repo.sh`) makes `pkg install`/`upgrade`
and the stock GUI Install pull our build over Netgate's. GUI discovery + the update badge stay
Netgate-bound; a GUI "Updates/Channel" panel is deferred (ADR-19; would touch `src/`).

Full varver/ABI rationale + live proof + upgrade-lag, the boot-time `rc.d` conf regenerator
(ADR-39), the publish pipeline (the separate `pfBlockerNG/pkg` repo + its OIDC deploy), the
generators + `add-repo.sh` bootstrap, and the `repo`-marker smoke flow:
[`docs/misc/architecture-notes.md`](../../docs/misc/architecture-notes.md) ("Self-hosted pkg
distribution").
