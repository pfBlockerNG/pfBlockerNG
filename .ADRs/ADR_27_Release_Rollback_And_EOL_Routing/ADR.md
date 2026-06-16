# ADR-27: Release Rollback Retention + EOL-pfSense Route-Only Distribution

- **Status:** **Proposed** (2026-06-16)
- **Date:** 2026-06-16
- **Branch:** `adr/27-release-rollback-and-eol-rou` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `scripts/build-repo-portable.py` (the matrix-driven catalog BRAIN — release-subtree retention)
  - `scripts/build-repo.sh` (`--print-conf` template — unchanged contract, referenced)
  - `tests/smoke/test_repo_install.py` + `tests/smoke/_matrix.py` (rollback smoke; ADR-04 `repo` marker)
  - `tests/test_build_repo_portable.py` (off-box catalog membership)
  - `src/usr/local/www/` (the pfSense GUI rollback panel) + `src/usr/local/pkg/pfblockerng/`
  - **Cross-repo:** `pfBlockerNG/pkg` `.github/workflows/publish.yml` (enumerate + fold the retained Releases)
  - **Design-only (deferred):** the `ci-metadata` version matrix schema + `scripts/read-version-matrix.sh` + `scripts/worker/` (the route-only flag)
- **Target runtime:** Python 3.11+ (portable builders, runner-side; stdlib + the existing zstd dep); PHP 8.3 (pfSense CE 2.8 GUI); POSIX `/bin/sh`; Cloudflare Worker (JS, ESM)
- **Test surface:** `tests/test_build_repo_portable.py` + `tests/test_smoke_matrix.py` (off-box, PR gate); `tests/smoke/test_repo_install.py` `-m repo` (live VM, dispatch); `tests/smoke/ui` `-m ui_render` (ADR-14, the GUI panel); `scripts/worker/test/` (`node --test`, part-2 design only)

Builds on **ADR-17** (self-hosted `pkg` repo / derived index), **ADR-18** (nightly channel + 14-deep
Actions-cache retention), and **ADR-20** (CE/Plus variant distribution — `routing.json` + the Cloudflare
Worker, UA → `<channel>/<varver>/<arch>/`).

---

## 1. Context (today)

### 1.1 The catalog already serves multiple versions per package — but only nightly uses it

`scripts/build-repo-portable.py:_write_catalog_dir()` writes **one `packagesite.yaml` NDJSON object per
`(name, version)`** in a bucket (`catalog_object(...)` per staged `.pkg`). So a single per-ABI catalog can
advertise *N* versions of the **same** package name; `pkg` then resolves `pkg install <name>` to the newest
and an explicit `pkg install <name>-<version>` (or `pkg add <url>`) to a pinned one.

The **nightly** channel exercises exactly this: `build_repo_matrix()` builds `nightly/<varver>/<arch>/`,
folds the fresh build in with the cache-restored prior nightlies, and prunes to the newest **14**
(`_retain_newest(paths, keep=nightly_keep)`, default 14). The catalog therefore carries 14 distinct
`pfSense-pkg-pfBlockerNG-nightly` versions — an older one stays installable for rollback.

The **release** subtree does **not** retain: `build_repo_matrix()` builds `release/<varver>/<arch>/` from
the **devel HEAD** build plus the **single latest stable tag** (`--stable-tag`/`--stable-src`), one version
of each name. There is no `release_keep`; older devel/stable releases are not folded in. (Cross-repo:
`pfBlockerNG/pkg` `publish.yml` resolves only "the newest non-prerelease Release tag" for stable and builds
devel from HEAD.)

### 1.2 Rollback today is effectively unavailable for releases

- A user on the release channel who upgrades and regresses has **no supported downgrade**: the catalog holds
  only the current devel + current stable; the prior `.pkg` exists **only** as a GitHub Release asset
  (manual `pkg add <https URL>` against an asset the catalog doesn't index, with no dependency resolution
  against our repo).
- There is **no GUI affordance** for version switching. The deferred **ADR-19** (Update/Channel panel) is the
  only sketch and is unimplemented.

### 1.3 Old / EOL pfSense versions cannot install at all

Distribution is keyed on the **build matrix** (`ci-metadata` `supported-versions.json`, read by
`scripts/read-version-matrix.sh`; entries carry `pfsense_version / freebsd_major / arch / php_version /
py_flavor / variant / status / ci`). The Worker (`scripts/worker/src/index.js`) routes a box's pkg UA via
`routing.json` (`{pattern, catalog, status}`, e.g. `pfSense/2.8 → ce-2.8`) to `release/<varver>/<arch>/`.

When the **minimum supported pfSense** moves forward (e.g. min CE 2.8 → 2.9), the dropped version leaves the
build matrix → no catalog is built for it → `routing.json` has no route for its UA → the Worker 404s it. A
box still on the EOL version can no longer install/upgrade pfBlockerNG **even though the last `.pkg` that
supported it exists** as a Release asset. (No such version exists *today* — min CE 2.8 is current — so this
is a forward-looking gap, not a live defect.)

### 1.4 Load-bearing facts (verified)

- `_write_catalog_dir` membership = one NDJSON object per `(name, version)` — multi-version is mechanical, not
  new (`scripts/build-repo-portable.py`).
- `_retain_newest(pkg_paths, keep)` already implements version-sorted prune (used for nightly); reusable verbatim.
- `build_repo_matrix(... nightly_keep=14, build_nightly=...)` is the single orchestrator; the release subtree
  is built inline with **no** retention parameter.
- The publish is a **derived, stateless index** (ADR-17): each run regenerates the catalog. Retention state for
  nightly is a same-repo **Actions cache** (`actions/cache`, `site/nightly`); releases need a retention source
  too (GitHub Releases are the natural durable store — they already hold every release `.pkg`).
- The repo smoke (`tests/smoke/test_repo_install.py`, `-m repo`) already **re-versions** the branch `.pkg` on
  the runner to forge a lower→higher pair for the `pkg upgrade` transition test — the same helper can forge a
  retained-older version for a **rollback** assertion.

---

## 2. Decision

Two composable parts. **Part 1 (rollback retention + GUI) is implemented by the phases below.** **Part 2
(EOL route-only distribution) is specified here but its implementation is deferred** until an EOL pfSense
version actually exists (§2.4) — it has no consumer today and must not be built speculatively.

### 2.1 Part 1 — Retain the last *N* devel + *M* stable releases (per-area decision)

| Area | Decision |
| ---- | -------- |
| Generator (`build-repo-portable.py`) | Generalize the nightly retention to the release subtree: add `--release-keep-devel N` / `--release-keep-stable M` (per-**channel** prune, since devel + stable share one `release/<varver>/<arch>/` catalog). Reuse `_retain_newest` keyed by package **name prefix** (`…-devel` vs stable). Default `N=M=0` ⇒ **unbounded** is wrong; default to the **current behaviour** (latest-only) so the change is inert until the publish opts in — i.e. the generator keeps *all* provided inputs and the **publish** decides how many to provide + a safety prune to `N`/`M`. Decision: the **generator prunes** to `N`/`M` (single source of the policy), publish provides candidates. |
| Retention depth | **Bounded both ways:** `N = 10` devel, `M = 10` stable (chosen defaults; overridable). An older-than-window release stays a GitHub Release asset but leaves the catalog. |
| Retention source | **GitHub Releases** (durable, already every release `.pkg`). `publish.yml` enumerates Releases, buckets by `prerelease` (devel pre-release) vs stable, takes the newest `N`/`M`, downloads their `.pkg`, and feeds them to the generator alongside the fresh devel-HEAD build. No new stateful store (unlike nightly's cache — Releases *are* the store). |
| Catalog shape | `release/<varver>/<arch>/` now carries up to `N`+`M` versions per ABI (multi-version NDJSON). `pkg install <pkg>` still takes newest; `pkg install <pkg>-<version>` / `pkg add` pins an older one. |
| Landing page | The ADR-20 "Older nightlies" per-edition disclosure pattern (`gen_landing.py`) generalizes to an **"Older releases"** disclosure under each edition — surfacing the retained devel/stable versions with their commit/date so a human can find a rollback target. |
| Rollback UX (CLI) | Documented: `pkg install pfSense-pkg-pfBlockerNG[-devel]-<version>` (pinned) or `pkg add <pages-url>/…/<name>-<version>.pkg`. The catalog now resolves deps for the pinned version. |
| Rollback UX (GUI) | A pfSense package page (`src/usr/local/www/`) listing the **installed** version + the **available** versions (read from the live repo catalog via `pkg rquery`/`pkg search`), with a guarded "switch to this version" action that runs the pinned `pkg install`. Coordinated with the deferred ADR-19 panel (this is the rollback slice of it). |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before changing)

1. **Catalog fidelity:** a multi-version `release/` catalog is still accepted by a real `pkg update`/`install`
   (meta.conf + packagesite.pkg + data.pkg well-formed; the ADR-17 generator-equivalence holds). Pinned off-box
   (`tests/test_build_repo_portable.py`) + live (`-m repo`).
2. **Newest-wins default:** `pkg install <name>` (no version) still installs the **newest** retained version —
   retention must never change the default install target.
3. **Cross-repo precedence (ADR-17):** our repo's `priority: 100` still wins vs Netgate for every retained
   version (the precedence smoke must stay green).
4. **Determinism / idempotency:** regenerating the catalog from the same inputs is byte-stable (mtime-pinned;
   ADR-17). Retention pruning is version-sorted + deterministic (`_retain_newest`).
5. **No release-build behaviour change:** a release `.pkg`'s bytes are unchanged; retention only changes *which*
   prebuilt `.pkg` the catalog indexes.

### 2.3 Explicitly kept / out of scope (Part 1)

- **Nightly retention** (14) is unchanged — this ADR only adds the *release* analogue.
- **Per-version dependency divergence** across retained releases is out of scope: we assume the RUN_DEPENDS set
  is stable across the retained window (true today). If a future release changes deps incompatibly, that older
  version's install is best-effort (documented).
- **A full GUI Update/Channel panel** (channel switching, update badge) stays **ADR-19**; ADR-27 adds only the
  **rollback/version-pick** slice.

### 2.4 Part 2 — EOL route-only distribution (DESIGN ONLY; implementation deferred)

Specified now so the matrix/Worker grow the right seams; **no phases below implement it** (no EOL consumer
exists — building it speculatively risks ADR-01's trap).

- **Matrix flag.** Extend `supported-versions.json` entries with a **role**: `build` (default — built + smoke,
  today's behaviour) vs `route-only` (NOT built, NOT smoked; its last-built catalog is **frozen/archived** and
  still served). `scripts/read-version-matrix.sh` gains `--print-route` (all entries with a live catalog) while
  `--print-build`/`--print-ci`/`--print-test` continue to yield only `build` entries — so adding a `route-only`
  entry never fans out a build or a smoke leg.
- **Worker.** `routing.json` already carries a `status` per route; a `route-only` entry emits a route to its
  **frozen** `release/<varver>/<arch>/` archive (a snapshot taken at the moment the version left `build`),
  unchanged thereafter. The Worker logic is untouched (it already routes by UA → catalog).
- **Archival storage.** When a version transitions `build → route-only`, its last catalog tree is copied to a
  durable archive path (e.g. `release/_archive/<varver>/<arch>/`) and the `routing.json` route repointed there,
  so the daily derived-index rebuild stops rebuilding it but keeps serving the frozen copy.
- **Trigger.** Implementation begins when the min supported pfSense first advances and a still-supported-by-an-
  older-`.pkg` version would otherwise lose its route. Until then this section is the design of record only.

---

## 3. Consequences

**Positive**

- A real, supported **rollback** path for releases (CLI + GUI), reusing the proven nightly multi-version
  mechanism — no new catalog machinery, no new stateful store (Releases are the source).
- The forward-looking **EOL** gap has a vetted design (matrix role + frozen archive) ready to implement the
  moment it has a consumer — without re-litigating the routing model.
- The landing page gains an "Older releases" view, parallel to "Older nightlies".

**Negative / risks**

- **Catalog/Pages growth:** `release/` grows by up to `N`+`M` versions per ABI. Bounded by the defaults
  (10+10); the Pages artifact + the publish runtime grow accordingly. Mitigated by the bound + version-sorted prune.
- **GUI surface (`src/`):** a new page ships to users and must clear the ADR-14 `ui_render` gate (no PHP
  warnings/notices) and the PFBL-01 sniff where applicable. Larger blast radius than a pure-tooling change.
- **Rollback foot-gun:** downgrading can hit a config-schema mismatch (a newer config read by older code). The
  GUI action must warn; out-of-scope to *migrate* config backwards (documented limitation).
- **Cross-repo coupling:** the retention *policy* lives in this repo's generator, but the *candidate provision*
  lives in `pfBlockerNG/pkg` `publish.yml` — the two must stay in step (the generator's prune is the backstop).

---

## 4. Requirements (acceptance)

- The `release/<varver>/<arch>/` catalog carries the newest **N** devel + **M** stable versions per ABI
  (deduped, version-sorted, pruned deterministically); `pkg install <name>` still yields the newest.
- A real pfSense box can `pkg install <name>-<oldversion>` (or `pkg add`) a **retained older** release and end up
  with that exact version active, deps resolved from our repo — proven by the live `-m repo` smoke.
- The off-box catalog-membership test pins that exactly the expected retained versions appear (and an older-than-
  window one does not).
- The GUI panel lists installed + available versions and performs a guarded version switch; it clears the ADR-14
  `ui_render` gate (200, no `Fatal/Parse/Warning/Notice/Uncaught`, marker present, no new `php_error.log` line).
- The landing page shows an "Older releases" disclosure per edition (unit-tested in `tests/test_gen_landing.py`).
- Part 2 is documented (§2.4) with the matrix-role + Worker-route design; **no** part-2 code lands.

## 5. Constraints (from CLAUDE.md)

- Portable builders: Python 3.11+, stdlib + the existing zstd encoder; deterministic, mtime-pinned output.
- GUI: PHP 8.3, tabs; pfSense help-text style; no `die()`/`exit()` in library code; PFBL-01 RequirePfbFilter
  where input handling applies.
- Shell: POSIX `/bin/sh`, quoted expansions, `LC_ALL=C` on machine-data sorts (ADR-26).
- `pkg` catalog fidelity (ADR-17): NONE-signed, `priority: 100`, byte-identical generators
  (`tests/test_add_repo_conf.py` + `tests/test_build_repo_portable.py` drift pins).
- No live Unbound in CI; the live VM smoke (ADR-04) is dispatch-only; the Web-UI `ui_render` tier is the PR gate
  for `src/www/` (ADR-14).
- Rebase-only PRs; one commit per phase; `python -m pytest` green at every phase.

## 6. Action plan

Part-1 only (Part 2 is design-only, §2.4). Early phases are behaviour-preserving prep (extract + pin the
retention seam) before the catalog shape changes.

### Phase 1 — Extract + pin a channel-keyed release-retention seam (prep)

Prompt: `01_Retention_Seam.txt` — behaviour-preserving.

- In `scripts/build-repo-portable.py`, generalize `_retain_newest` usage: factor a `retain_by_channel(paths,
  keep_devel, keep_stable)` helper that version-sorts + prunes per package-name channel (`-devel` vs stable),
  reusing `_retain_newest`. No call-site behaviour change yet (release subtree still latest-only).
- Off-box tests (`tests/test_build_repo_portable.py`): pin the helper — devel/stable bucketed independently,
  newest-`keep` kept per channel, ties + version order deterministic, `keep` larger than input is a no-op.
- Tests this phase adds: `test_retain_by_channel_*` (per-channel prune, order, no-op).

### Phase 2 — Release-subtree retention in `build_repo_matrix` (catalog shape change)

Prompt: `02_Release_Retention.txt`.

- Add `--release-keep-devel N` / `--release-keep-stable M` (defaults preserving today: latest-only ⇒ `1`/`1`).
  Fold provided release-candidate `.pkg` (devel + stable) into `release/<varver>/<arch>/`, prune via
  `retain_by_channel`, regenerate the multi-version catalog.
- Pin (contract §2.2): newest-wins default unchanged; multi-version membership exactly the kept set; determinism;
  cross-generator drift pins still hold.
- Tests: `test_release_subtree_retains_devel_and_stable`, `test_release_default_is_latest_only` (before-state),
  `test_release_catalog_lists_all_kept_versions`.

### Phase 3 — Publish wiring (cross-repo: `pfBlockerNG/pkg` `publish.yml`)

Prompt: `03_Publish_Retention.txt`.

- `publish.yml`: enumerate Releases, bucket by `prerelease`, take newest `N` devel + `M` stable, download their
  `.pkg`, pass them + `--release-keep-devel/-stable` to the generator. (This repo's phase = update
  `scripts/build-repo-portable.py` CLI/help + `docs`/`README` + any `scripts/build-repo*.sh` parity; the
  `publish.yml` edit is applied in the `pkg` repo and referenced.)
- Verification: a dry-run generator invocation with a synthetic multi-release input set produces the expected
  multi-version tree (off-box).

### Phase 4 — Rollback smoke (live VM, `-m repo`)

Prompt: `04_Rollback_Smoke.txt`.

- `tests/smoke/test_repo_install.py`: forge ≥2 retained release versions (reuse the existing re-version helper);
  install newest, assert it active; **roll back** via `pkg install <name>-<olderversion>`; assert the older
  version is now active, deps resolved from our repo; then re-upgrade to newest (before/after lifecycle).
- Pin: `pkg install <name>` (no version) still picks newest; the pinned install picks exactly the requested one.

### Phase 5 — GUI rollback panel + landing "Older releases"

Prompt: `05_Gui_And_Landing.txt`.

- `scripts/gen_landing.py`: add the per-edition "Older releases" disclosure (mirror `_older_nightlies_*`); unit
  tests in `tests/test_gen_landing.py`.
- `src/usr/local/www/`: a pfBlockerNG version-rollback page — list installed + available (from `pkg`), guarded
  switch action; pfSense GUI idioms; ADR-14 `ui_render` marker + no `php_error.log` line.
- Tests: `gen_landing` unit cases; `tests/smoke/ui -m ui_render` for the new page.

## 7. Definition of done

- Phases 1–5 merged; `python -m pytest` green throughout; off-box catalog-membership + `gen_landing` tests pin
  the retained set and the "Older releases" view.
- **Live `-m repo` smoke (CE + Plus fan-out):** install newest → roll back to a retained older version → re-upgrade,
  all from our repo with deps resolved; newest-wins default intact; cross-repo precedence intact.
- **ADR-14 `ui_render`:** the rollback page renders clean on the live VM.
- §2.4 (Part 2) present as design-of-record; **no** part-2 code merged.
- **Manual smoke checklist (owner: maintainer)** — the items CI cannot fully cover:
  - On a real box, GUI-switch to an older version and back; confirm the package functions (a DNSBL match) after each.
  - Confirm a rollback across a config-schema change warns and does not corrupt config (documented limitation).
  - Confirm Pages/catalog growth at `N=M=10` is within the publish runtime/artifact budget.
- **Reject criteria (ADR-01 discipline):** REJECT (or rescope) if any holds —
  - `pkg` cannot, on a real box, install a **pinned older** version from a multi-version catalog with dep
    resolution (i.e. rollback needs `pkg add` of a raw URL with no dep resolution) — then "rollback via catalog"
    is false and only the GitHub-Release-asset path remains (downgrade Part 1 to docs-only).
  - Multi-version `release/` catalogs are rejected/mis-resolved by a real `pkg update` (fidelity break).
  - The GUI switch cannot be made safe (no guard prevents a config-corrupting downgrade) — ship CLI-only, defer GUI.
