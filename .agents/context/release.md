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
script, so the rule never drifts. A versioned tag triggers: tests → GitHub Release → port
bump on our **`pfBlockerNG/FreeBSD-ports` fork** (self-hosted distribution, no upstream PR).
**Nightly builds get no GitHub Release.**

## Pipeline order — build + verify BEFORE anything is tagged (issue #1855)

`release.yml` is one dispatch, one run, in this order:

1. **`prepare-release`** (real only) — validate the tag↔channel scheme, refuse an already
   **published** release, assert **CI green on the release commit** (`release-ci-gate.sh`,
   walking past docs-only commits), commit the deterministic notes placeholder when no
   curated `docs/release-notes/TAG.md` exists (docs-only, on the channel branch), then **pin
   the release SHA**. *Nothing is tagged here.*
2. **Build + verify** — `resolve-stamp` / `build-pkgs-portable` (per-major `.pkg`s +
   `extra_pkgs` dep packages) build **from the pinned SHA** as *workflow* artifacts, then
   `ui-suite` / `smoke-suite` verify **those exact artifacts** (`pkg_artifact_prefix:
   pfBlockerNG-relpkg`) — never Release assets, so they need no tag and no Release.
3. **`tag-release`** — the FIRST irreversible step: creates + pushes the tag **on the pinned
   SHA** (not on "the branch tip now"), gated on the build and, when they ran, on **both**
   suite AND-gates.
4. **`release` → `attach-pkgs` → `publish-release` → `sync-ports-fork` → `repo-publish`** —
   draft Release, assets, healthcheck, publish flip, ports bump, pkg-repo dispatch.

So a failed run leaves **nothing** on GitHub — no tag, no draft (only the docs-only notes
commit, which the retry reuses). `tag-release` is the single seam for the suite gate;
publish-release inherits it transitively. Its resume path is narrowed to the
**crash-after-tag** window: a pre-existing tag on the pinned SHA is reused, a tag on any
other commit is refused loudly and never moved. `tests/test_release_tag_after_verify.py`
walks the whole `needs:` graph, so the pre-#1855 order cannot come back silently.

**Which channels verify live.** `prekind` (from `release-version.sh`) decides:
`alpha`/`beta` **skip** the live smoke/UI suites — the mandatory gate is the `verify-checks`
CI-green assertion above; `rc` and stable run them in full. One code path: for an alpha/beta
the verification phase is simply empty, not a parallel pipeline. The `force_suites` dispatch
input (default `false`) forces them on for an alpha/beta; it can only ever *add* verification.

**Which rows may veto.** A matrix row gates a release **iff its ci-metadata `status` is a
released pfSense version** (`active`, or its legacy alias `GA`). Every other value — `beta`,
anything added later, absent/unrecognized — is non-blocking: the leg still runs and still
reports, emits a loud demotion warning naming the row and its status, and cannot fail the
release. Predicate + warning live in `scripts/resolve-legs.sh`, switched on by the suites'
`release_gate` input (release-only; PR/nightly gating is unchanged).

## Release notes pipeline

Body precedence: a **committed `docs/release-notes/TAG.md` wins** (curated, or committed by
`prepare-release`'s own placeholder writer) — otherwise the workflow writes a **deterministic
placeholder** ending in the compare link (`prev_tag` classifies each tag's channel via
`release-version.sh` to find the previous same-channel release for that link). GitHub Models
drafting was removed (`ci: remove the GitHub Models changelog/notes drafts from the release
flow`, release run 30379645002) — it never produced a working result. A committed file's
title summary rides in an optional first-line `<!-- SUMMARY: … -->` marker (stripped from the
rendered body; the title is `YYYY-MM-DD - VER — summary`, ISO date prefixed so GitHub's
alphabetical release sort stays chronological). To author real notes, commit
`docs/release-notes/TAG.md` before dispatching — the **`/release-with-changelog`** skill does
this for you, applying the same prompt template `scripts/release-notes-prompt.txt` used to
describe the desired shape (group user-facing changes under **Features / Improvements /
Bug Fixes** with PR/issue links, CI/test/tooling/ADR noise filtered).
**Nightly builds get no GitHub Release.**

**Dry-run.** `release.yml`'s `workflow_dispatch` is a no-publish harness: pass the `tag` to
simulate with `dry_run=true` (default) to validate the scheme, build the `.pkg` artifacts, and
render the body (the real body shows in the run summary) — publishing nothing. Dispatchable
only from the default branch once merged.

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
