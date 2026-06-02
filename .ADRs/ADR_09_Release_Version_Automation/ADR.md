# ADR-09: Scheduled version tracking & release automation

- **Status:** **Proposed** (2026-06-02)
- **Date:** 2026-06-02
- **Branch:** `adr/09` (off `devel`) / **Component(s):** new dev-only CI — a decoupled supported-version **matrix** (GitHub repo variables / off-branch metadata), a **version-tracker** workflow, a **release `.pkg` build** (extends `.github/workflows/release.yml`), and the **CI image-refresh / smoke fan-out** (gated). Reuses the `scripts/` image pipeline (`image-publish.sh`, `image-upgrade.sh`, `install-from-repo.sh`). **No shipped (`src/`) code changes.**
- **Target runtime:** GitHub Actions — `ubuntu-latest`; a **FreeBSD VM** (`vmactions/freebsd-vm` or QEMU) for `.pkg` builds; **KVM** for the gated CI-image phases. Targets pfSense **CE** (CI + build) and **Plus** (build only).
- **Test suite:** no new `pytest` (this is a CI/workflow ADR); the default `python -m pytest` is untouched. Validation is workflow runs + the Phase-1 build spike + the gated sanity gate.

---

## 1. Context

### Today

- `.github/workflows/release.yml`: on a `vX.Y.Z[-devel]` tag → `verify-checks` → `release` (GitHub Release; pre-release if the tag is reachable only from `devel`) → `ports-pr` (opens a PR on `pfsense/FreeBSD-ports` bumping `GH_TAGNAME` + `PORTVERSION`). **It does not build or attach a `.pkg`** — the artifact is the source tag; Netgate's repo builds the actual package per pfSense version.
- `.github/workflows/test.yml`: unit matrix (`pytest` 3.11–3.13) + ruff + shellcheck + php-lint + PHPStan + markdownlint. No smoke workflow exists (that is ADR-04, unbuilt).
- ADR-04 (**Proposed**) defines the VM smoke harness and the `scripts/` image pipeline (`image-publish.sh` = export a Proxmox seed → GHCR; `image-upgrade.sh` = bump a published image to a newer CE; `install-from-repo.sh` = clean install from `src/`).
- There is **no supported-version config** anywhere; the only version pin is `MIN_PFSENSE_VERSION` in `scripts/update-pfsense-stubs.py`.

### Load-bearing facts (verified)

1. **`main` ⊆ `devel` ⊆ `next`, strictly linear** (one chain, no merge commits). Promotion is **rebase-based** with `--force-with-lease`. **Auto-committing or force-pushing the channel branches from a cron job is unacceptable** — it would clobber in-flight work and hand a bot too much trust.
2. **The `.pkg` is data-only but ABI-tagged.** The port `net/pfSense-pkg-pfBlockerNG-devel` ships no compiled files, but it `RUN_DEPENDS` on `net/libmaxminddb` (compiled `mmdblookup`) and does **not** set `NO_ARCH`, so the package is tagged `FreeBSD:<major>:<arch>`. `pkg` gates installs on the **OS major** (a `FreeBSD:15` package on `FreeBSD:16` is refused without `pkg add -f`). → **one `.pkg` build per distinct FreeBSD major** suffices.
3. **The maintainer already builds the `.pkg` manually** via `make package` against the `../FreeBSD-ports` tree (README "Building via the FreeBSD ports system" → `work/pkg/*.pkg`). So the build premise is established for a local FreeBSD box; CI just needs to reproduce it in a FreeBSD VM.
4. **The CI side is downstream of ADR-04.** Refreshing the GHCR smoke image and fanning the smoke matrix require ADR-04's harness to exist **and** its **GH-hosted KVM kill-gate (Phase 1) to pass** — neither has happened. Building that automation now would repeat the **ADR-01 trap** (machinery on an unproven premise). → those phases are **gated**.
5. **No clean pfSense release/beta API.** `RELENG_*` branches/tags in `pfsense/FreeBSD-ports` and Netgate's pkg ABI list are the closest machine signals, and they lag — unreliable for **betas**. → detection is **curated**, not auto-merged.
6. **pfSense upgrades are appliance-grade.** Per maintainer guidance, in-place upgrade is designed to work out of the box, **including across FreeBSD-major jumps** — so the image-refresh flow is *try-upgrade → sanity-gate → publish*, with **no mandatory manual re-seed**. The seed image is already **minimal and plain** (a stock pfSense install + only the harness essentials), so the upgrade chain accumulates almost no cruft — removing the main reason ADR-04 §2 wanted a major-jump re-baseline. *(This refines that conservative "re-baseline on a MAJOR version jump" wording, which should be reconciled — see §3.)*
7. **pfSense Plus is license-encumbered.** We **track Plus versions and build `.pkg` artifacts** for them (building needs only the right FreeBSD-major env, no Plus license), but we **never run Plus in CI** (no licensed/redistributable image) — unless Netgate grants a free CI license.

---

## 2. Decision

Add a **curated-then-automated** version pipeline. A human nudges a **decoupled matrix** when a pfSense beta/release lands; everything downstream — release `.pkg` artifacts, GHCR smoke-image refresh, and the CI smoke fan-out — reacts automatically. **The matrix never lives on the channel branches, so the automation never force-pushes them.** The premise-at-risk (building an installable `.pkg` in CI) is **falsified first (Phase 1)**, and the CI-side phases are **gated on ADR-04 acceptance**.

| Area | Decision |
| --- | --- |
| **Supported-version matrix** | **Decoupled from `main`/`devel`/`next`.** The matrix is **data** (which versions) — `supported-versions.json` on a **`ci-metadata` orphan ref** (its own history, **not** in the `main → devel → next` chain), **read at runtime** by every workflow (`git show origin/ci-metadata:supported-versions.json` / checkout that ref, default token). **Not a repo variable:** variables have no usable git audit trail on a *user* repo (no diff/blame/rollback/PR review) and need a privileged token to write. The **logic** (the workflow YAML in `.github/`) stays on the channel branches and is promoted devel-first by rebase like any source — so **high-frequency churn** (add/drop a version) touches **only `ci-metadata`** (zero channel-branch writes), while **low-frequency churn** (how workflows react) follows the normal flow. A `schedule` workflow runs from the **default branch's** YAML but reads the shared off-branch data, so the version set is consistent regardless of which branch's workflow executes. Schema per entry: `{ pfsense_version, channel: CE\|Plus, freebsd_major, status: beta\|GA, ci: bool }`. **Discoverability/audit:** protect `ci-metadata` (PR-only) and keep a static pointer to it in `scripts/README.md` + `CLAUDE.md` so it isn't lost among branches. **Migration:** if CI-infra grows, move the JSON to a dedicated public `pfBlockerNG-ci-infra` repo (read via raw URL, no token) — a later, mechanical swap. |
| **Matrix lifecycle** | **Add** an entry when a beta lands (curated). **Drop** the oldest supported **CE** only when the **newest CE goes GA** (so the window is *previous + current CE major*, transiently `+1` during a beta). Plus entries are `ci: false`, build-only. |
| **Detect vs react** | **Detect = curated:** a human edits the matrix when a beta/release drops. *Optional* best-effort scheduled **probe** (scan `RELENG_*` / pkg ABI) that **opens a PR/issue nudge** — it **never** auto-edits the matrix. **React = fully automated:** a matrix change (or schedule) drives the release build and (gated) the CI refresh + fan-out. |
| **Release `.pkg` artifacts** | Extend `release.yml`: read the matrix → build **one `.pkg` per distinct FreeBSD major** in a **FreeBSD VM** (`make package` against `../FreeBSD-ports` with `GH_TAGNAME`/`WRKSRC` pointed at the tagged source) → **attach to the GitHub Release**. CE **and** Plus built (Plus build-only). The existing `ports-pr` step is **unchanged**. |
| **CI image refresh** *(GATED on ADR-04)* | Triggered by a new CE entry (or schedule): on a KVM runner, `image-upgrade.sh` pulls the current GHCR tag → `pfSense-upgrade` (**any** bump, incl. major) → **SANITY GATE** → `oras push` the new tag **only on pass**; **fail (no publish) on any sanity failure**. A manual seed (`image-publish.sh`) is a **fallback**, used only when the gate fails. |
| **CI smoke fan-out** *(GATED on ADR-04)* | The ADR-04 smoke workflow reads the matrix → runs the suite against **every `ci: true` CE image**; **never Plus**. The version-tracker triggers it on a new CE image. |
| **Sanity gate (the publish guard)** | Boots; SSH answers; `/etc/version` advanced to the expected release; `pfctl -sr` loads; `install-from-repo.sh` installs pfBlockerNG and `pfblockerng.php update` exits 0; a `dig` of a baked control/blocked name returns the expected shape. **Any miss → do not publish.** |
| **Linearity** | The matrix is off-branch, so **version tracking never touches the channel branches**. The pfBlockerNG **package-version** bump (per channel, in the port `Makefile`/`info.xml`) stays the **existing manual tag flow** (devel-first, rebase-promote) — out of scope here. |

### Semantics that MUST be preserved (the contract — pin before relying)

- **The existing release flow is intact.** A normal tag push still produces the GitHub Release **and** the `FreeBSD-ports` PR; the `.pkg` build is **additive** and a build failure must **not** silently skip or break the `ports-pr` step (the ports PR is the real distribution path).
- **The version-tracker never writes to `main`/`devel`/`next`** (no commits, no force-push). Linearity is untouched.
- **A broken image is never published** — the sanity gate fails **closed**.
- **Plus is never executed in CI** (licensing).
- **The default unit suite (`test.yml`) is unchanged** — no new deps, no new required jobs on the unit path.

### Explicitly kept / out of scope

- **Auto-detecting betas as a merge/edit trigger** — out; curation only (an optional probe may *nudge*, never act).
- **Running pfSense Plus in CI** — out (licensing), unless a free license materialises.
- **The ADR-04 harness itself** — this ADR *consumes* it; the CI-side phases are gated, not a re-implementation.
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

- **Premise risk (release, highest for the now-buildable half):** building the pfSense port into an *installable* `.pkg` inside a GHA FreeBSD VM may need pfSense-private build bits or Netgate-only deps, or exceed the time budget. **Mitigated by the Phase-1 spike + kill-threshold (§7)** before any wiring.
- **Premise risk (CI):** the whole CI-side is **downstream of ADR-04's unproven KVM premise**. **Mitigated by gating** Phases 5–6 on ADR-04 acceptance.
- **Unattended major upgrade may not be as turnkey as assumed.** Mitigated by the sanity gate (fail-closed) and the documented manual-seed fallback. **ADR-04 §2 still says "re-baseline on a MAJOR version jump"** — that wording must be reconciled with this ADR's upgrade-in-place stance (tracked as a follow-up; not edited from here per the one-ADR-at-a-time rule).
- **Detection fragility:** no clean pfSense version API → curated nudge; a missed beta just means a late (manual) matrix edit, never a broken publish.
- **Third-party dependency:** `vmactions/freebsd-vm` (or a hand-rolled QEMU FreeBSD VM) for the build.

---

## 4. Requirements (acceptance)

1. **Build spike (Phase 1):** a GHA FreeBSD VM builds an **installable** `.pkg` for the current FreeBSD major within the time budget (§7); `pkg add` succeeds (deps resolve) on a matching pfSense.
2. **Release artifacts:** a tag push **attaches a `.pkg` per distinct FreeBSD major** to the GitHub Release, and the `FreeBSD-ports` PR **still opens**.
3. **Decoupled matrix:** the supported-version set lives off the channel branches; workflows read it at runtime; editing it drives builds (and, gated, CI) **without any channel-branch commit**.
4. *(Gated)* **Image refresh:** upgrade-in-place + sanity gate publishes a good image and **fails closed** on a deliberately-broken upgrade (no publish).
5. *(Gated)* **Smoke fan-out:** runs across all `ci: true` CE images, **never Plus**.
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

Each phase is one commit, leaves `python -m pytest` (default) green, and pushes to `adr/09`. The **build premise is falsified first (Phase 1)**; the **CI-side phases (5–6) are GATED** — their prompts STOP unless ADR-04 is **Accepted**.

### Phase 1 — Spike & kill-gate: build an installable `.pkg` in a GHA FreeBSD VM

Prompt: `01_Build_Spike.txt`

- In a FreeBSD VM (`vmactions/freebsd-vm` or QEMU) matching the current CE's FreeBSD major: check out `../FreeBSD-ports`-equivalent + this repo, point the port at the working source, `make package`, and confirm `pkg add` of the result on a clean pkg root (deps resolve, incl. `libmaxminddb`).
- **Measure** build wall-time; record vs the kill-threshold (§7). Land a minimal `.github/workflows/build-spike.yml` + the numbers in `RESULTS/01_Results.txt`.
- **Gate:** can't build/install in budget → STOP; record the fallback (manual `make package` + manual upload) before Phase 3.

### Phase 2 — Decoupled supported-version matrix + runtime reader

Prompt: `02_Version_Matrix.txt`

- Define the matrix schema + storage (repo variable `SUPPORTED_VERSIONS` JSON, or a `ci-metadata` ref) — **off the channel branches**. A small composite action / `sh` reader that emits the build + CI matrices (distinct FreeBSD majors for builds; `ci: true` CE entries for smoke). Seed with today's set (2.7.x → FreeBSD 14, 2.8.x → FreeBSD 15; Plus build-only). Document the **lifecycle** (add-on-beta, drop-oldest-CE-on-newest-GA).

### Phase 3 — Release-side: build + attach per-FreeBSD-major `.pkg` artifacts

Prompt: `03_Release_Artifacts.txt`

- Extend `release.yml` (or a `needs`-linked build job): read the matrix → build one `.pkg` per distinct FreeBSD major (Phase-1 mechanism) → `softprops/action-gh-release` attaches them. CE + Plus built (Plus build-only). **`ports-pr` stays intact**; a build failure surfaces without breaking the ports PR.

### Phase 4 — Version-tracker workflow (scheduled; curated detect + react)

Prompt: `04_Version_Tracker.txt`

- `.github/workflows/version-tracker.yml` (`schedule` + `workflow_dispatch`): read the matrix; **react** = trigger the release-artifact build and (gated) the CI refresh/fan-out for new entries. Optional best-effort **probe** that opens a **PR/issue nudge** on a new `RELENG_*` — never edits the matrix, never touches channel branches.

### Phase 5 — *(GATED on ADR-04 Accepted)* CI smoke-image refresh: upgrade-in-place + sanity gate

Prompt: `05_Image_Refresh.txt`

- On a KVM runner: `image-upgrade.sh` pull current tag → `pfSense-upgrade` (any bump) → **sanity gate** (§2) → `oras push` the new tag **only on pass**; fail closed otherwise. Manual seed = fallback. Self-test: a deliberately-broken upgrade must **not** publish.

### Phase 6 — *(GATED on ADR-04 Accepted)* CI smoke matrix fan-out across CE minors

Prompt: `06_Smoke_Fanout.txt`

- The ADR-04 smoke workflow reads the matrix → runs the suite against every `ci: true` CE image; **never Plus**. Wire the version-tracker to trigger it on a new CE image.

### Phase 7 — Docs + DoD + reject criteria

Prompt: `07_Docs_DoD.txt`

- `scripts/README.md` + `README` + `CLAUDE.md` CE-support checklist: the matrix lifecycle, how to add/drop a version, the build-vs-CI split, Plus build-only. Finalise §7 manual checklist + reject criteria. Fold the spike workflow into the final shape.

---

## 7. Definition of done

- **Phases 1–4 + 7** green: Phase-1 spike is **GO**; a tag attaches per-FreeBSD-major `.pkg`(s) **and** the ports PR still opens; the matrix is decoupled and editing it drives builds **without** a channel-branch commit; `main → devel → next` linearity and the default `pytest` suite are untouched.
- **Phases 5–6** flip from **gated** to done **only after ADR-04 is Accepted**: image refresh publishes a good image and **fails closed** on a broken upgrade; smoke fan-out runs across all `ci: true` CE images, never Plus.
- Workflows/YAML lint-clean; any new `sh` ShellCheck-clean; markdown clean.
- Status → **Accepted** only after the maintainer confirms the manual checklist below.

### Reject criteria (decide cheaply, before wiring)

- **Release-side:** if a GHA FreeBSD VM **cannot** build the port into an installable `.pkg` within budget (needs pfSense-private build framework / Netgate-only deps, or too slow) → **reject the in-CI build**; fall back to manual `make package` + manual upload to the Release. Phase-1 settles this before Phase 3.
- **CI-side:** inherits ADR-04's reject (GH-hosted KVM unfit). Additionally, if **unattended upgrades (especially major) cannot pass the sanity gate reliably** → reject auto-refresh for that case and fall back to a manual seed for that major (the gate ensures a bad image is never published regardless).

### Manual smoke (owner: maintainer) — required before Accept

- [ ] A built `.pkg` installs (`pkg add`) on a real pfSense of **each supported FreeBSD major** — CE and Plus.
- [ ] Editing the matrix (add a version) triggers the `.pkg` build round-trip with **no** commit to `main`/`devel`/`next`.
- [ ] A normal `vX.Y.Z[-devel]` tag still produces the GitHub Release **and** the `FreeBSD-ports` PR, now with `.pkg` artifacts attached.
- [ ] *(Post-ADR-04)* the sanity gate **rejects** a deliberately-broken upgrade (no publish) and **accepts** a good one.
- [ ] *(Post-ADR-04)* the smoke fan-out runs across every `ci: true` CE image and **never** Plus.
