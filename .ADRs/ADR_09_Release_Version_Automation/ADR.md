# ADR-09: Scheduled version tracking & release automation

- **Status:** **Proposed** (2026-06-02; **amended 2026-06-05**). The amendment reconciles
  the ADR with three facts that landed after it was authored: (1) the **portable Linux
  `.pkg` builder** (`build-pkg-linux.yml` / `scripts/build-pkg-portable.py`) now exists and
  is the **default** build path (the FreeBSD `make package` VM build is retained as a
  **fidelity oracle / fallback**) — so the release-side build premise (Phase 1) is
  **already proven**, not a risk; (2) the supported-version matrix carries the
  **(freebsd_version, php_version)** pair per pfSense version, not just a FreeBSD *major*
  (the build env needs the PHP pin even though the artifact ABI dedupes by major); (3)
  **ADR-04 is Accepted**, so the CI-side Phases 5–6 are **ungated**. The matrix also
  supersedes the tactical `resolve-version` case-map added to `build-image.yml` for issue
  #22 (PR #105) — that single-version stopgap reads from this matrix once it lands.
- **Date:** 2026-06-02
- **Branch:** `adr/09` (off `devel`) / **Component(s):** new dev-only CI — a decoupled supported-version **matrix** (off-branch metadata), a **version-tracker** workflow, a **release `.pkg` build** (extends `.github/workflows/release.yml`; reuses the existing **portable Linux builder** by default + the **FreeBSD `make package`** builder as the fidelity oracle), and the **CI image-refresh / smoke fan-out** (now ungated — ADR-04 Accepted). Reuses the `scripts/` image pipeline (`image-publish.sh`, `image-upgrade.sh`, `install-from-repo.sh`). **No shipped (`src/`) code changes.**
- **Target runtime:** GitHub Actions — `ubuntu-latest` for the **default portable `.pkg` build** + matrix orchestration; a **FreeBSD VM** (`vmactions/freebsd-vm` or QEMU) for the **fidelity-oracle / fallback** build; **KVM** for the CI-image phases. Targets pfSense **CE** (CI + build) and **Plus** (build only).
- **Test suite:** no new `pytest` (this is a CI/workflow ADR); the default `python -m pytest` is untouched. Validation is workflow runs + the build round-trips (portable + FreeBSD oracle) + the sanity gate.

---

## 1. Context

### Today

- `.github/workflows/release.yml`: on a `vX.Y.Z[-devel]` tag → `verify-checks` → `release` (GitHub Release; pre-release if the tag is reachable only from `devel`) → `ports-pr` (opens a PR on `pfsense/FreeBSD-ports` bumping `GH_TAGNAME` + `PORTVERSION`). **It does not build or attach a `.pkg`** — the artifact is the source tag; Netgate's repo builds the actual package per pfSense version.
- `.github/workflows/test.yml`: unit matrix (`pytest` 3.11–3.13) + ruff + shellcheck + php-lint + PHPStan + markdownlint.
- `.github/workflows/smoke.yml` (ADR-04, **Accepted**): live-VM smoke against a single CE image — installs the branch `.pkg`, runs `pytest -m smoke`. It is **single-version by design** (a comment notes the version fan-out / matrix / scheduled refresh is deferred to *this* ADR).
- **Two `.pkg` builders already exist** (both proven by the ADR-04 smoke gate): `build-pkg-linux.yml` (→ `scripts/build-pkg-portable.py`) builds the port `.pkg` on a **plain Linux runner** and is the **default** (pfBlockerNG is a `NO_BUILD` port, so the portable builder reproduces `make package` from the Makefile + pkg-plist); `build-pkg.yml` runs the **real `make package` on an ABI-matched FreeBSD VM** and is retained as the **byte-for-byte fidelity oracle / fallback**. `build-image.yml` already wires `build-pkg.yml` for its publish round-trip.
- ADR-04 (**Accepted**) defines the VM smoke harness and the `scripts/` image pipeline (`image-publish.sh` = export a Proxmox seed → GHCR; `image-upgrade.sh` = bump a published image to a newer CE; `install-from-repo.sh` = clean install from `src/`).
- **Partial-version config exists:** `MIN_PFSENSE_VERSION` in `scripts/update-pfsense-stubs.py`; the per-version base facts in `docs/misc/pfSense_versions.md`; and the tactical `resolve-version` case-map in `build-image.yml` (issue #22 / PR #105) that maps `pfsense_ce_version → (freebsd_version, php_version)`. There is **no single decoupled matrix** that all of these read — this ADR builds it.

### Load-bearing facts (verified)

1. **`main` ⊆ `devel` ⊆ `next`, strictly linear** (one chain, no merge commits). Promotion is **rebase-based** with `--force-with-lease`. **Auto-committing or force-pushing the channel branches from a cron job is unacceptable** — it would clobber in-flight work and hand a bot too much trust.
2. **The `.pkg` is data-only but ABI-tagged.** The port `net/pfSense-pkg-pfBlockerNG-devel` ships no compiled files, but it `RUN_DEPENDS` on `net/libmaxminddb` (compiled `mmdblookup`) and does **not** set `NO_ARCH`, so the package is tagged `FreeBSD:<major>:<arch>`. `pkg` gates installs on the **OS major** (a `FreeBSD:15` package on `FreeBSD:16` is refused without `pkg add -f`). → **the published artifact dedupes to one `.pkg` per distinct FreeBSD major.** **But the *build* is parameterised by the full `(freebsd_version, php_version)` pair** — `make package` / the portable builder pin the PHP default (`USES=php` injects `php83`/`php83-intl`), and FreeBSD/PHP **co-vary per pfSense version** (CE 2.8.x ⇒ FreeBSD 15.0-RELEASE + PHP 8.3). So the **matrix carries the pair** (the same shape as `build-image.yml`'s `resolve-version` map and `docs/misc/pfSense_versions.md`); artifact *naming/dedup* keys on the FreeBSD major.
3. **CI already builds the `.pkg` two ways — the build premise is PROVEN.** The default is the **portable Linux builder** (`scripts/build-pkg-portable.py`, driven by `build-pkg-linux.yml`): it executes the port's own recipe + pkg-plist off-FreeBSD and was diffed byte-for-byte against a real `make package` artifact (exact but mtime + binary-repo dep versions). The **fidelity oracle / fallback** is the real `make package` on an ABI-matched FreeBSD VM (`build-pkg.yml`). The maintainer's manual `make package` (README "Building via the FreeBSD ports system") is the same recipe. → Phase 1 is no longer a *de-risking spike*; it is an **inventory + matrix-wiring** of these two existing builders.
4. **The CI side WAS downstream of ADR-04 — now unblocked.** ADR-04 is **Accepted** (harness code-complete; `smoke.yml` matrix green on a dispatched CI run; maintainer confirmed the manual checklist). Its GH-hosted KVM premise is **proven**, and `build-image.yml` already does the upgrade-in-place + publish + verify round-trip (much of Phase 5). → Phases 5–6 are **ungated** (the ADR-01-trap concern is resolved by ADR-04's acceptance, not deferred).
5. **No clean pfSense release/beta API.** `RELENG_*` branches/tags in `pfsense/FreeBSD-ports` and Netgate's pkg ABI list are the closest machine signals, and they lag — unreliable for **betas**. → detection is **curated**, not auto-merged.
6. **pfSense upgrades are appliance-grade.** Per maintainer guidance, in-place upgrade is designed to work out of the box, **including across FreeBSD-major jumps** — so the image-refresh flow is *try-upgrade → sanity-gate → publish*, with **no mandatory manual re-seed**. The seed image is already **minimal and plain** (a stock pfSense install + only the harness essentials), so the upgrade chain accumulates almost no cruft — removing the main reason ADR-04 §2 wanted a major-jump re-baseline. *(This refines that conservative "re-baseline on a MAJOR version jump" wording, which should be reconciled — see §3.)*
7. **pfSense Plus is license-encumbered.** We **track Plus versions and build `.pkg` artifacts** for them (building needs only the right FreeBSD-major env, no Plus license), but we **never run Plus in CI** (no licensed/redistributable image) — unless Netgate grants a free CI license.

---

## 2. Decision

Add a **curated-then-automated** version pipeline. A human nudges a **decoupled matrix** when a pfSense beta/release lands; everything downstream — release `.pkg` artifacts, GHCR smoke-image refresh, and the CI smoke fan-out — reacts automatically. **The matrix never lives on the channel branches, so the automation never force-pushes them.** The release-side build premise is **already proven** (two working builders — portable Linux by default, FreeBSD `make package` as the oracle — §1 fact 3), and **ADR-04 is Accepted**, so the CI-side phases are **no longer gated**.

| Area | Decision |
| --- | --- |
| **Supported-version matrix** | **Decoupled from `main`/`devel`/`next`.** The matrix is **data** (which versions) — `supported-versions.json` on a **`ci-metadata` orphan ref** (its own history, **not** in the `main → devel → next` chain), **read at runtime** by every workflow (`git show origin/ci-metadata:supported-versions.json` / checkout that ref, default token). **Not a repo variable:** variables have no usable git audit trail on a *user* repo (no diff/blame/rollback/PR review) and need a privileged token to write. The **logic** (the workflow YAML in `.github/`) stays on the channel branches and is promoted devel-first by rebase like any source — so **high-frequency churn** (add/drop a version) touches **only `ci-metadata`** (zero channel-branch writes), while **low-frequency churn** (how workflows react) follows the normal flow. A `schedule` workflow runs from the **default branch's** YAML but reads the shared off-branch data, so the version set is consistent regardless of which branch's workflow executes. **Schema per entry: `{ pfsense_version, channel: CE\|Plus, freebsd_version, freebsd_major, php_version, status: beta\|GA, ci: bool }`** — it carries the full `(freebsd_version, php_version)` **build pair** (§1 fact 2), not just the major. **It is the single source of truth that `build-image.yml`'s `resolve-version` map (issue #22), `docs/misc/pfSense_versions.md`, and the release/smoke matrices all read** — when this lands, the #22 case-statement is replaced by a matrix lookup (one place to add a version). **Discoverability/audit:** protect `ci-metadata` (PR-only) and keep a static pointer to it in `scripts/README.md` + `CLAUDE.md`. **Migration:** if CI-infra grows, move the JSON to a dedicated public `pfBlockerNG-ci-infra` repo (read via raw URL, no token) — a later, mechanical swap. |
| **Matrix lifecycle** | **Add** an entry when a beta lands (curated). **Drop** the oldest supported **CE** only when the **newest CE goes GA** (so the window is *previous + current CE major*, transiently `+1` during a beta). Plus entries are `ci: false`, build-only. |
| **Detect vs react** | **Detect = curated:** a human edits the matrix when a beta/release drops. *Optional* best-effort scheduled **probe** (scan `RELENG_*` / pkg ABI) that **opens a PR/issue nudge** — it **never** auto-edits the matrix. **React = fully automated:** a matrix change (or schedule) drives the release build **and** the CI refresh + fan-out. |
| **Release `.pkg` artifacts** | Extend `release.yml`: read the matrix → for each entry build a `.pkg` against its `(freebsd_version, php_version)` pair, **defaulting to the portable Linux builder** (`build-pkg-linux.yml`) and keeping the **FreeBSD `make package` VM builder** (`build-pkg.yml`) as the **fidelity-oracle / fallback** variant (selectable; "Linux by default, FreeBSD if we fuck up"). **Attach one `.pkg` per distinct FreeBSD major** to the GitHub Release (artifact dedup by ABI — §1 fact 2). CE **and** Plus built (Plus build-only). The existing `ports-pr` step is **unchanged**; a build failure surfaces but must not break `ports-pr`. |
| **CI image refresh** | Triggered by a new CE entry (or schedule): on a KVM runner, `image-upgrade.sh` pulls the current GHCR tag → `pfSense-upgrade` (**any** bump, incl. major) → **SANITY GATE** → `oras push` the new tag **only on pass**; **fail (no publish) on any sanity failure**. A manual seed (`image-publish.sh`) is a **fallback**, used only when the gate fails. *(`build-image.yml` already realises much of this — the upgrade-in-place publish + verify round-trip; Phase 5 generalises it to be matrix-driven.)* |
| **CI smoke fan-out** | The ADR-04 smoke workflow reads the matrix → runs the suite against **every `ci: true` CE image**, **never Plus**, as a **`strategy.matrix` job with `fail-fast: false`** so every leg runs to completion. **The pass criterion is the AND of all legs:** a single gating job `needs:` the whole matrix and fails red if **any** leg failed (a green is only green when *all* combinations passed). The version-tracker triggers it on a new CE image. |
| **Sanity gate (the publish guard)** | Boots; SSH answers; `/etc/version` advanced to the expected release; `pfctl -sr` loads; `install-from-repo.sh` installs pfBlockerNG and `pfblockerng.php update` exits 0; a `dig` of a baked control/blocked name returns the expected shape. **Any miss → do not publish.** |
| **Linearity** | The matrix is off-branch, so **version tracking never touches the channel branches**. The pfBlockerNG **package-version** bump (per channel, in the port `Makefile`/`info.xml`) stays the **existing manual tag flow** (devel-first, rebase-promote) — out of scope here. |

### Semantics that MUST be preserved (the contract — pin before relying)

- **The existing release flow is intact.** A normal tag push still produces the GitHub Release **and** the `FreeBSD-ports` PR; the `.pkg` build is **additive** and a build failure must **not** silently skip or break the `ports-pr` step (the ports PR is the real distribution path).
- **The version-tracker never writes to `main`/`devel`/`next`** (no commits, no force-push). Linearity is untouched.
- **A broken image is never published** — the sanity gate fails **closed**.
- **Plus is never executed in CI** (licensing).
- **The smoke fan-out gate is the AND of every leg.** With `fail-fast: false` all CE combinations run; the overall result is green **only if every leg passed** — one red leg fails the gate. No leg is silently dropped or allowed to pass partially.
- **The default unit suite (`test.yml`) is unchanged** — no new deps, no new required jobs on the unit path.

### Explicitly kept / out of scope

- **Auto-detecting betas as a merge/edit trigger** — out; curation only (an optional probe may *nudge*, never act).
- **Running pfSense Plus in CI** — out (licensing), unless a free license materialises.
- **The ADR-04 harness itself** — this ADR *consumes* it (ADR-04 Accepted); the CI-side phases parametrise it, not a re-implementation.
- **Re-deriving the two `.pkg` builders** — `build-pkg-linux.yml` (portable, default) and `build-pkg.yml` (FreeBSD oracle) already exist; this ADR *wires them to the matrix*, it does not rebuild them.
- **pfBlockerNG package-version bumping policy** — stays the current tag/release flow.
- **`NO_ARCH` on the port** — a separate (cross-arch) consideration, not required here.

---

## 3. Consequences

**Positive**

- **Same-day support** for a new CE version: one curated matrix edit → automated `.pkg` builds and (post-ADR-04) CI against the new version.
- **Published, installable `.pkg` artifacts** per FreeBSD major on every release — closes the gap that `release.yml` only bumps `GH_TAGNAME` today, and gives a higher-fidelity install/packaging gate than the rsync path.
- **No manual re-seed on a major** — fully automated upgrade-in-place, guarded by a fail-closed sanity gate.
- **Channel branches are never touched by a bot** — the decoupled matrix removes the linearity-vs-automation conflict entirely.

**Negative / risks**

- **Premise risk (release) — RESOLVED.** Building the port into an *installable* `.pkg` in CI is no longer hypothetical: the portable Linux builder (default) and the FreeBSD `make package` oracle both exist and pass the ADR-04 smoke gate (§1 fact 3). The residual risk is narrow — the portable builder could drift from real `make package` output — and is covered by keeping the FreeBSD VM build as a fallback oracle to diff against.
- **Premise risk (CI) — RESOLVED.** ADR-04 is **Accepted**; its GH-hosted KVM premise is proven and `build-image.yml` already runs the upgrade/publish/verify round-trip. Phases 5–6 are ungated.
- **Unattended major upgrade may not be as turnkey as assumed.** Mitigated by the sanity gate (fail-closed) and the documented manual-seed fallback. **ADR-04 §2 still says "re-baseline on a MAJOR version jump"** — that wording must be reconciled with this ADR's upgrade-in-place stance (tracked as a follow-up; not edited from here per the one-ADR-at-a-time rule).
- **Detection fragility:** no clean pfSense version API → curated nudge; a missed beta just means a late (manual) matrix edit, never a broken publish.
- **Third-party dependency:** the FreeBSD oracle/fallback build leans on a FreeBSD VM (`build-pkg.yml`'s QEMU path); the **default** portable Linux builder has no such dependency, so a `vmactions`/QEMU outage degrades to oracle-only, not a release-blocker.

---

## 4. Requirements (acceptance)

1. **Builders wired to the matrix (Phase 1):** both existing builders produce an **installable** `.pkg` for a matrix entry's `(freebsd_version, php_version)` pair — the **portable Linux builder by default**, the **FreeBSD `make package` VM build** as the selectable oracle/fallback; `pkg add` succeeds (deps resolve) on a matching pfSense.
2. **Release artifacts:** a tag push builds per matrix entry and **attaches a `.pkg` per distinct FreeBSD major** to the GitHub Release, and the `FreeBSD-ports` PR **still opens**.
3. **Decoupled matrix:** the supported-version set (carrying the `(freebsd_version, php_version)` pair) lives off the channel branches; workflows — including `build-image.yml`'s `resolve-version` — read it at runtime; editing it drives builds + CI **without any channel-branch commit**.
4. **Image refresh:** upgrade-in-place + sanity gate publishes a good image and **fails closed** on a deliberately-broken upgrade (no publish).
5. **Smoke fan-out:** runs across all `ci: true` CE images **in parallel** (`fail-fast: false`), **never Plus**, and the **gate is the AND of every leg** (any red leg ⇒ red gate).
6. **Linearity + unit suite untouched:** `main → devel → next` stays linear with no automation-driven force-push; `python -m pytest` (default) is unchanged.

---

## 5. Constraints (from `CLAUDE.md`)

- **No shipped (`src/`) changes.** Any new scripts are **POSIX `sh`**, quoted, absolute binary paths, ShellCheck-clean; workflows/YAML lint-clean; markdown markdownlint-clean.
- **Linear promotion:** work inline on `adr/09`, **one commit per phase, push directly** (PR only if the push is rejected); promote `devel → next` by **rebase + `--force-with-lease`**, never merge. The automation itself must honour this (never force-push channel branches).
- Commit style `<scope>: <imperative summary>` (`ci:`, `dev:`, `docs:`). PR bodies via `--body-file`.
- Secrets via GitHub Actions secrets (`SMOKE_SSH_PRIV_KEY`/`SMOKE_SSH_PUB_KEY`/`SMOKE_ADMIN_PASSWORD` from ADR-04; a `write:packages` token for GHCR; the `FreeBSD-ports` PR token already used by `release.yml`).
- Docs: the version-bump / CE-support checklist in `CLAUDE.md`/`README` is updated (Phase 7).

---

## 6. Action plan

Each phase is one commit, leaves `python -m pytest` (default) green, and pushes to `adr/09`. The **release-side build premise is already proven** (two existing builders — §1 fact 3) and **ADR-04 is Accepted**, so **no phase is gated**.

### Phase 1 — Inventory the two builders + define the matrix-driven build invocation

Prompt: `01_Build_Spike.txt`

- The build premise is **already proven** — `build-pkg-linux.yml` (portable, **default**) and `build-pkg.yml` (FreeBSD `make package`, **oracle/fallback**) both exist and pass the ADR-04 smoke gate. This phase **inventories** them: document each builder's inputs (notably the `(freebsd_version, php_version)` pair), how to select Linux-default vs FreeBSD-fallback, the artifact naming, and confirm `pkg add` resolves `libmaxminddb`. **No new spike workflow** — record the recipe + the two builders' contract in `RESULTS/01_Results.txt` for Phase 3.

### Phase 2 — Decoupled supported-version matrix + runtime reader

Prompt: `02_Version_Matrix.txt`

- Define the matrix schema + storage on a `ci-metadata` orphan ref — **off the channel branches**. Schema carries the **`(freebsd_version, php_version)` pair** per entry. A small composite action / `sh` reader emits the build matrix (entries → `(freebsd_version, php_version)`; artifacts dedup by distinct FreeBSD major) and the CI matrix (`ci: true` CE entries). Seed with today's **real** support set: **2.8.x → FreeBSD 15.0-RELEASE + PHP 8.3 (CE, GA, ci:true)**; current Plus → its FreeBSD major (Plus, GA, ci:false). *(2.7.x is below `MIN_PFSENSE_VERSION` 2.8.0 — not supported; do not seed it.)* **Repoint `build-image.yml`'s `resolve-version` map (issue #22) at this matrix** so there is one place to add a version. Document the **lifecycle** (add-on-beta, drop-oldest-CE-on-newest-GA).

### Phase 3 — Release-side: build (portable default / FreeBSD fallback) + attach per-FreeBSD-major `.pkg`

Prompt: `03_Release_Artifacts.txt`

- Extend `release.yml` (or a `needs`-linked build job): read the matrix → build a `.pkg` per entry against its `(freebsd_version, php_version)` pair, **defaulting to the portable Linux builder** and keeping the **FreeBSD `make package`** builder as a selectable oracle/fallback → `softprops/action-gh-release` attaches one `.pkg` per distinct FreeBSD major. CE + Plus built (Plus build-only). **`ports-pr` stays intact**; a build failure surfaces without breaking the ports PR.

### Phase 4 — Version-tracker workflow (scheduled; curated detect + react)

Prompt: `04_Version_Tracker.txt`

- `.github/workflows/version-tracker.yml` (`schedule` + `workflow_dispatch`): read the matrix; **react** = trigger the release-artifact build and (gated) the CI refresh/fan-out for new entries. Optional best-effort **probe** that opens a **PR/issue nudge** on a new `RELENG_*` — never edits the matrix, never touches channel branches.

### Phase 5 — CI smoke-image refresh: upgrade-in-place + sanity gate (ungated — ADR-04 Accepted)

Prompt: `05_Image_Refresh.txt`

- On a KVM runner: `image-upgrade.sh` pull current tag → `pfSense-upgrade` (any bump) → **sanity gate** (§2) → `oras push` the new tag **only on pass**; fail closed otherwise. Manual seed = fallback. Self-test: a deliberately-broken upgrade must **not** publish. *(Generalise `build-image.yml`, which already does this for a single version, to be matrix-driven.)*

### Phase 6 — CI smoke matrix fan-out across CE minors (ungated — ADR-04 Accepted)

Prompt: `06_Smoke_Fanout.txt`

- The ADR-04 smoke workflow reads the matrix → runs the suite against every `ci: true` CE image as a **`strategy.matrix` job with `fail-fast: false`** (all legs run in parallel); **never Plus**. A **gating job `needs:` all legs** — green only if every leg passed. Wire the version-tracker to trigger it on a new CE image.

### Phase 7 — Docs + DoD + reject criteria

Prompt: `07_Docs_DoD.txt`

- `scripts/README.md` + `README` + `CLAUDE.md` CE-support checklist: the matrix lifecycle, how to add/drop a version, the build-vs-CI split, Plus build-only. Finalise §7 manual checklist + reject criteria. Fold the spike workflow into the final shape.

---

## 7. Definition of done

- **Phases 1–4 + 7** green: both builders are matrix-wired (portable default + FreeBSD oracle); a tag attaches per-FreeBSD-major `.pkg`(s) **and** the ports PR still opens; the matrix is decoupled, carries the `(freebsd_version, php_version)` pair, and editing it drives builds (and the `resolve-version` map) **without** a channel-branch commit; `main → devel → next` linearity and the default `pytest` suite are untouched.
- **Phases 5–6** (ungated — ADR-04 Accepted) done: image refresh publishes a good image and **fails closed** on a broken upgrade; smoke fan-out runs across all `ci: true` CE images **in parallel with `fail-fast: false`**, never Plus, and the **gate is the AND of all legs**.
- Workflows/YAML lint-clean; any new `sh` ShellCheck-clean; markdown clean.
- Status → **Accepted** only after the maintainer confirms the manual checklist below.

### Reject criteria (decide cheaply, before wiring)

- **Release-side:** the in-CI build is already proven (portable + FreeBSD oracle, §1 fact 3), so the open risk is **portable-vs-`make package` drift**. If the portable `.pkg` ever diverges from the FreeBSD oracle in a way that affects install/behaviour → make the **FreeBSD VM build the release default** for the affected entry (the fallback exists precisely for this) rather than shipping a divergent portable artifact.
- **CI-side:** if **unattended upgrades (especially major) cannot pass the sanity gate reliably** → reject auto-refresh for that case and fall back to a manual seed for that major (the gate ensures a bad image is never published regardless).

### Manual smoke (owner: maintainer) — required before Accept

- [ ] A built `.pkg` installs (`pkg add`) on a real pfSense of **each supported FreeBSD major** — CE and Plus.
- [ ] Editing the matrix (add a version) triggers the `.pkg` build round-trip with **no** commit to `main`/`devel`/`next`.
- [ ] A normal `vX.Y.Z[-devel]` tag still produces the GitHub Release **and** the `FreeBSD-ports` PR, now with `.pkg` artifacts attached.
- [ ] The sanity gate **rejects** a deliberately-broken upgrade (no publish) and **accepts** a good one.
- [ ] The smoke fan-out runs across every `ci: true` CE image **in parallel** and **never** Plus; **one deliberately-failed leg turns the whole gate red** (no partial pass).
