# ADR-27: Release Rollback Retention + EOL-pfSense Route-Only Distribution

- **Status:** **Accepted — Part 1** (released-rollback retention, merged) · **Implementing — Part 2** (EOL route-only; only the real version-flip deferred)
- **Date:** 2026-06-16
- **Branch:** `adr/27-release-rollback-and-eol-rou` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `scripts/build-repo-portable.py` (the matrix-driven catalog BRAIN — release-subtree retention)
  - `scripts/build-repo.sh` (`--print-conf` template — unchanged contract, referenced)
  - `tests/smoke/test_repo_install.py` + `tests/smoke/_matrix.py` (rollback smoke; ADR-04 `repo` marker)
  - `tests/test_build_repo_portable.py` (off-box catalog membership)
  - `scripts/gen_landing.py` (the Pages landing "Older releases" disclosure) + `README`/`docs` (CLI rollback procedure)
  - **Cross-repo:** `pfBlockerNG/pkg` `.github/workflows/publish.yml` (Part 1: enumerate + fold retained Releases; Part 2: feed each `route-only` version's frozen `.pkg`)
  - **Part 2 (implemented):** the `ci-metadata` `supported-versions.json` `role` flag + `scripts/read-version-matrix.sh` (`--print-route`) + `scripts/build-repo-portable.py` (route-only catalog from frozen `.pkg`) + `scripts/gen_landing.py` ("EOL pfSense versions" tables) + `scripts/worker/` (route-only routing, behaviour-pinned)
- **Target runtime:** Python 3.11+ (portable builders, runner-side; stdlib + the existing zstd dep); POSIX `/bin/sh`; Cloudflare Worker (JS, ESM)
- **Test surface:** `tests/test_build_repo_portable.py` + `tests/test_smoke_matrix.py` + `tests/test_gen_landing.py` (off-box, PR gate); `tests/smoke/test_repo_install.py` `-m repo` (live VM, dispatch — incl. the simulated-EOL route-only case); `scripts/worker/test/` (`node --test`, incl. route-only routing)

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

Two composable parts. **Part 1 (rollback retention) — phases 1–5, merged.** **Part 2 (EOL route-only
distribution) — phases 6–10, §2.4:** the mechanism + its full offline/synthetic + simulated-EOL test coverage
are **implemented**; the **only** deferred action is flipping a real pfSense version `build → route-only` the
day it actually EOLs (a one-line `supported-versions.json` edit). Building the *machinery* now is not the ADR-01
trap — the failure mode is silent + the trigger inevitable, and it is fully provable offline before any real
consumer exists.

### 2.1 Part 1 — Retain the last *N* devel + *M* stable releases (per-area decision)

| Area | Decision |
| ---- | -------- |
| Generator (`build-repo-portable.py`) | Generalize the nightly retention to the release subtree: add `--release-keep-devel N` / `--release-keep-stable M` (per-**channel** prune, since devel + stable share one `release/<varver>/<arch>/` catalog). Reuse `_retain_newest` keyed by package **name prefix** (`…-devel` vs stable). Default `N=M=0` ⇒ **unbounded** is wrong; default to the **current behaviour** (latest-only) so the change is inert until the publish opts in — i.e. the generator keeps *all* provided inputs and the **publish** decides how many to provide + a safety prune to `N`/`M`. Decision: the **generator prunes** to `N`/`M` (single source of the policy), publish provides candidates. |
| Retention depth | **Bounded both ways:** `N = 10` devel, `M = 10` stable (chosen defaults; overridable). An older-than-window release stays a GitHub Release asset but leaves the catalog. |
| Retention source | **GitHub Releases** (durable, already every release `.pkg`). `publish.yml` enumerates Releases, buckets by `prerelease` (devel pre-release) vs stable, takes the newest `N`/`M`, downloads their `.pkg`, and feeds them to the generator alongside the fresh devel-HEAD build. No new stateful store (unlike nightly's cache — Releases *are* the store). |
| Catalog shape | `release/<varver>/<arch>/` now carries up to `N`+`M` versions per ABI (multi-version NDJSON). `pkg install <pkg>` still takes newest; `pkg install <pkg>-<version>` / `pkg add` pins an older one. |
| Landing page | The ADR-20 "Older nightlies" per-edition disclosure pattern (`gen_landing.py`) generalizes to an **"Older releases"** disclosure under each edition — surfacing the retained devel/stable versions with their commit/date so a human can find a rollback target. |
| Rollback UX (CLI only) | Documented support/debug procedure: `pkg install -f pfSense-pkg-pfBlockerNG[-devel]-<version>` (pinned) or `pkg add <pages-url>/…/<name>-<version>.pkg`. `-f` is required — `pkg install` never downgrades over a newer installed build, so the pin is a no-op without it (proven on the live VM); the catalog still resolves deps for the pinned version (unlike `pkg add`). **No GUI** — rollback is a support/debugging action, not an expected user flow, so it does not warrant a shipped `src/www/` page (which would carry an `ui_render`/PHP blast radius for a rarely-trodden path). A future GUI version-pick, if ever wanted, stays with the deferred ADR-19 Update/Channel panel. |

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
- **Any GUI** is out of scope. The full Update/Channel panel (channel switching, update badge) stays **ADR-19**,
  and even the rollback/version-pick ships **no `src/www/` page** — rollback is a CLI + landing-disclosure support
  action, not an expected user flow. ADR-27 touches no `src/` production code at all.

### 2.4 Part 2 — EOL route-only distribution (IMPLEMENTED; only the version-flip is deferred)

**Why implemented now, not deferred.** The EOL gap (§1.3) has a *silent* failure mode (an EOL box loses all
pkg install/upgrade) and an *inevitable* trigger (the min supported pfSense advances). The mechanism is fully
provable offline today with a synthetic matrix entry + a simulated-EOL smoke — so "prove it works before you
need it" beats wiring it under pressure the day a version EOLs. ADR-01's "no speculative build" still holds
where it matters: **no real version is flipped to `route-only`** until one genuinely EOLs (a one-line matrix
edit). The machinery + its tests land now; the flip is the only deferred action.

**Refinement of the original sketch (load-bearing).** A `route-only` version's catalog is regenerated each run
**from its last frozen `.pkg` (already a GitHub Release asset — the same durable store Part 1 uses; no new
stateful store, no separate served `_archive/` path)** and served at the **normal** `release/<varver>/<arch>/`
location. The Worker therefore needs **no logic change** — it routes the EOL box's UA to the same
`release/<varver>` path as any live version; `role` does its work entirely in the matrix reader + generator +
publish.

- **Matrix `role` flag.** Add `role` to `supported-versions.json` entries: **`build`** (default; absent ⇒
  `build`, fully back-compat — built + CI + smoke, today's behaviour) vs **`route-only`** (NOT built, NOT
  smoked; catalog regenerated from frozen `.pkg`, still served + routed). `scripts/read-version-matrix.sh`
  gains **`--print-route`** (every entry with a live catalog = `build` ∪ `route-only`); `--print-build` /
  `--print-ci` / `--print-test` **exclude `route-only`**, so adding a `route-only` entry never fans out a build
  or a smoke leg. A *removed* (truly dropped) entry leaves the matrix entirely and **is** 404'd — `route-only`
  is the middle state that keeps an EOL box served.
- **Generator (`build_repo_matrix`).** For a `route-only` entry: skip the fresh devel-HEAD build **and the
  nightly subtree**, build the `release/<varver>/<arch>/` catalog from the **provided frozen `.pkg`** only (the
  Part-1 `--release-extra-pkgs` mechanic, keyed to that varver), and emit its routing entry so the Worker routes
  it. `build` entries are unchanged (Part 1).
- **Worker.** **Unchanged.** A `route-only` version routes to its normal `release/<varver>/<arch>/` catalog
  exactly like a `build` version; `status`/`role` stay informational at the edge. Pinned by a `router.test.js`
  case (CE + Plus) so the behaviour is guarded even though no Worker code changes.
- **Releases only — nightly excluded.** A `route-only` version has **no** nightly subtree (nightly is
  ephemeral, keep=14, never archived per-EOL). Route-only applies to the `release/` channel (stable + devel
  packages) only.
- **Landing page.** A new **"EOL pfSense versions"** section — one table per edition (**CE** and **Plus**),
  one row per EOL pfSense version → the last/highest `.pkg` version still served for it (with commit/date),
  mimicking the existing per-edition tables.
- **Publish wiring (`pfBlockerNG/pkg` `publish.yml`).** For each `route-only` entry (`--print-route` minus
  `--print-build`), enumerate that version's last release `.pkg` assets from GitHub Releases and feed them to
  the generator as that varver's frozen input. Same durable store as Part 1 — no new state.
- **Trigger (the only deferred action).** Flipping a real entry `build → route-only` happens the day the min
  supported pfSense first advances and a version still installable by an older `.pkg` would otherwise lose its
  route. Until then the matrix carries only `build` entries; the mechanism is exercised by synthetic unit tests
  plus the simulated-EOL `-m repo` smoke (CE + Plus).

---

## 3. Consequences

**Positive**

- A real, supported **rollback** path for releases (CLI), reusing the proven nightly multi-version
  mechanism — no new catalog machinery, no new stateful store (Releases are the source), and **no `src/`
  change** (pure tooling/tests/docs, so no `ui_render`/PHP blast radius).
- The forward-looking **EOL** gap has a vetted design (matrix role + frozen archive) ready to implement the
  moment it has a consumer — without re-litigating the routing model.
- The landing page gains an "Older releases" view, parallel to "Older nightlies".

**Negative / risks**

- **Catalog/Pages growth:** `release/` grows by up to `N`+`M` versions per ABI. Bounded by the defaults
  (10+10); the Pages artifact + the publish runtime grow accordingly. Mitigated by the bound + version-sorted prune.
- **Rollback foot-gun:** downgrading can hit a config-schema mismatch (a newer config read by older code). The
  rollback **documentation** warns; out-of-scope to *migrate* config backwards (documented limitation). Keeping
  rollback CLI-only (no one-click GUI) also makes the foot-gun a deliberate, support-driven action rather than a
  casually-reachable button.
- **Cross-repo coupling:** the retention *policy* lives in this repo's generator, but the *candidate provision*
  lives in `pfBlockerNG/pkg` `publish.yml` — the two must stay in step (the generator's prune is the backstop).

---

## 4. Requirements (acceptance)

- The `release/<varver>/<arch>/` catalog carries the newest **N** devel + **M** stable versions per ABI
  (deduped, version-sorted, pruned deterministically); `pkg install <name>` still yields the newest.
- A real pfSense box can `pkg install -f <name>-<oldversion>` (or `pkg add`) a **retained older** release and end
  up with that exact version active, deps resolved from our repo — proven by the live `-m repo` smoke. (`-f` is
  required to downgrade over a newer installed build; deps still resolve from the catalog.)
- The off-box catalog-membership test pins that exactly the expected retained versions appear (and an older-than-
  window one does not).
- The landing page shows an "Older releases" disclosure per edition (unit-tested in `tests/test_gen_landing.py`),
  and the CLI rollback procedure is documented (`README`/`docs`).
- **Part 2 (§2.4):** a `route-only` matrix entry is excluded from `--print-build`/`--print-ci`/`--print-test`
  yet present in `--print-route`; the generator serves its `release/<varver>/<arch>/` catalog from frozen `.pkg`
  with **no** nightly subtree; the Worker routes it to that normal path (CE + Plus, pinned); the landing page
  shows the per-edition "EOL pfSense versions" tables; and the simulated-EOL `-m repo` smoke proves a route-only
  CE **and** Plus version installs from its frozen catalog while not rebuilt. No real version is flipped to
  `route-only`.

## 5. Constraints (from CLAUDE.md)

- Portable builders: Python 3.11+, stdlib + the existing zstd encoder; deterministic, mtime-pinned output.
- Shell: POSIX `/bin/sh`, quoted expansions, `LC_ALL=C` on machine-data sorts (ADR-26).
- `pkg` catalog fidelity (ADR-17): NONE-signed, `priority: 100`, byte-identical generators
  (`tests/test_add_repo_conf.py` + `tests/test_build_repo_portable.py` drift pins).
- No `src/` production code changes (no GUI) — so no `ui_render`/PHP gate applies; the live VM smoke (ADR-04
  `-m repo`) is dispatch-only.
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
  install newest, assert it active; **roll back** via `pkg install -f <name>-<olderversion>` (`-f` forces the
  downgrade over the newer installed build); assert the older version is now active, deps resolved from our repo;
  then re-upgrade to newest (before/after lifecycle).
- Pin: `pkg install <name>` (no version) still picks newest; the pinned install picks exactly the requested one.

### Phase 5 — Landing "Older releases" + rollback documentation

Prompt: `05_Landing_And_Docs.txt`.

- `scripts/gen_landing.py`: add the per-edition "Older releases" disclosure (mirror `_older_nightlies_*`),
  surfacing the retained devel/stable versions with commit/date so a human can find a rollback target.
- `README`/`docs`: document the CLI rollback procedure (`pkg install -f <name>-<version>` / `pkg add <url>`),
  including the config-schema-mismatch caveat (no backward config migration).
- Tests: `gen_landing` unit cases in `tests/test_gen_landing.py` (the "Older releases" disclosure, before/after).

### Part 2 — EOL route-only distribution (§2.4)

Phases 6–10 implement the EOL mechanism end-to-end. Each is behaviour-preserving for `build` entries (the only
entries that exist in production today); `route-only` behaviour is exercised by synthetic fixtures + the
simulated-EOL smoke. **No real version is flipped** (that one-line matrix edit is the deferred trigger).

#### Phase 6 — Matrix `role` seam (reader + schema)

Prompt: `06_Role_Matrix_Seam.txt` — behaviour-preserving.

- `scripts/read-version-matrix.sh`: add `--print-route` (entries with a live catalog = `build` ∪ `route-only`);
  make `--print-build` / `--print-ci` / `--print-test` **exclude** `role == "route-only"` (absent/`build` ⇒
  today's behaviour, fully back-compat). Document `role` in `scripts/README.md`; the `supported-versions.json`
  schema gains an optional `role` field (default `build`) — note the `ci-metadata` schema/example update (applied
  on that orphan branch; referenced here, not in this repo's diff).
- Tests: extend the matrix-reader coverage (a `route-only` entry is absent from build/ci/test, present in route;
  an absent `role` behaves as `build`). If `tests/smoke/_matrix.py` consumes the matrix, pin that route-only is
  ignored by the smoke topology (`tests/test_smoke_matrix.py`).

#### Phase 7 — Generator: route-only catalog from frozen `.pkg` (no build, no nightly)

Prompt: `07_RouteOnly_Generator.txt`.

- `scripts/build-repo-portable.py` `build_repo_matrix`: for a `route-only` entry, skip the fresh devel-HEAD
  build **and** the nightly subtree, build `release/<varver>/<arch>/` from the provided frozen `.pkg` (reuse the
  Part-1 `--release-extra-pkgs`/`retain_by_channel` machinery, keyed to that varver), and emit its routing
  entry. `build` entries unchanged.
- Off-box tests (`tests/test_build_repo_portable.py`), **CE + Plus**: a synthetic matrix with a `route-only`
  entry → its release catalog is built from frozen `.pkg`, no `nightly/<varver>/` dir exists, a routing entry is
  present; `build` entries in the same matrix are unaffected (before/after).

#### Phase 8 — Worker: pin route-only routing (no logic change expected)

Prompt: `08_Worker_RouteOnly.txt`.

- `scripts/worker/`: confirm a `route-only` version's UA routes to its normal `release/<varver>/<arch>/` catalog
  with **no** `index.js` logic change (or the minimal change if one is genuinely required). Add `router.test.js`
  cases (`node --test`, offline) for a route-only CE **and** Plus route + the opposite-edition guard.

#### Phase 9 — Landing "EOL pfSense versions" section (CE + Plus tables)

Prompt: `09_Landing_EOL.txt`.

- `scripts/gen_landing.py`: add a per-edition **"EOL pfSense versions"** section — one table for **CE** and one
  for **Plus**, one row per EOL (route-only) pfSense version → the last/highest `.pkg` version still served (with
  commit/date), mimicking the existing `_edition_table_html` shape. Deterministic, mtime-pinned (ADR-17).
- Tests (`tests/test_gen_landing.py`): the section lists exactly the route-only versions per edition with their
  newest served `.pkg`; empty case (no route-only ⇒ no section); CE/Plus split (before/after).

#### Phase 10 — Simulated-EOL smoke (`-m repo`, CE + Plus) + publish wiring

Prompt: `10_EOL_Smoke_And_Publish.txt`.

- `tests/smoke/test_repo_install.py` (`-m repo`): a simulated `route-only` version (forged frozen `.pkg` + a
  catalog built without a fresh build / nightly) installs on a real box from its `release/<varver>/` catalog with
  deps resolved; assert no nightly subtree is served for it. CE **and** Plus legs.
- Publish wiring: specify (and apply in `pfBlockerNG/pkg` `publish.yml`) the `--print-route` minus
  `--print-build` enumeration that feeds each `route-only` version's last Release `.pkg` to the generator. This
  repo's diff = generator/reader CLI + docs + tests; the `publish.yml` edit is referenced + applied cross-repo.

## 7. Definition of done

- Phases 1–5 merged; `python -m pytest` green throughout; off-box catalog-membership + `gen_landing` tests pin
  the retained set and the "Older releases" view.
- **Live `-m repo` smoke (CE + Plus fan-out):** install newest → roll back to a retained older version → re-upgrade,
  all from our repo with deps resolved; newest-wins default intact; cross-repo precedence intact.
- **Part 2 (§2.4) phases 6–10 merged:** `role` seam (route-only excluded from build/ci/test, present in route);
  generator serves a route-only catalog from frozen `.pkg` with no nightly subtree; Worker routes it (CE + Plus,
  pinned); landing "EOL pfSense versions" tables (CE + Plus); and the **simulated-EOL `-m repo` smoke green on
  the CE and Plus legs** (a route-only version installs from its frozen catalog, not rebuilt). `python -m pytest`
  and `node --test` (worker) green throughout. **No real version flipped to `route-only`** — that one-line matrix
  edit is the deferred trigger, performed when the min supported pfSense first advances.
- **Manual smoke checklist (owner: maintainer)** — the items CI cannot fully cover:
  - On a real box, CLI roll back (`pkg install -f <name>-<oldver>`) to an older version and back; confirm the package functions (a DNSBL match) after each.
  - Confirm a rollback across a config-schema change warns and does not corrupt config (documented limitation).
  - Confirm Pages/catalog growth at `N=M=10` is within the publish runtime/artifact budget.
- **Reject criteria (ADR-01 discipline):** REJECT (or rescope) if any holds —
  - `pkg` cannot, on a real box, install a **pinned older** version from a multi-version catalog with dep
    resolution (i.e. rollback needs `pkg add` of a raw URL with no dep resolution) — then "rollback via catalog"
    is false and only the GitHub-Release-asset path remains (downgrade Part 1 to docs-only).
  - Multi-version `release/` catalogs are rejected/mis-resolved by a real `pkg update` (fidelity break).
