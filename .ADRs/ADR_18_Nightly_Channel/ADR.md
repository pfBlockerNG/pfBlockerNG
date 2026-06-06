# ADR-18: Publish a nightly `pkg` build channel

- **Status:** **Proposed** (2026-06-06)
- **Date:** 2026-06-06
- **Branch:** `adr/18-nightly-channel` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming") / **Component(s):** dev-only
  distribution/CI — builder override flags + a `conflicts` manifest key in
  `scripts/build-pkg-portable.py`; a `nightly` channel in `scripts/add-repo.sh`; a
  new **scheduled nightly build+stage** workflow (gated on `devel` having changed);
  an **extension of ADR-17's `repo-publish.yml`** to also derive + stage the nightly
  catalog subtree (one Pages deploy); new `repo`-marked cases in
  `tests/smoke/test_repo_install.py`; new unit cases in
  `tests/test_build_pkg_portable.py`. **No shipped (`src/`) code changes.**
- **Target runtime:** GitHub Actions `ubuntu-latest` — the **pure-Python** builder
  (`scripts/build-pkg-portable.py`) and catalog generator
  (`scripts/build-repo-portable.py`), both reused as-is (no libpkg). Client side:
  pfSense **CE 2.8+** (`FreeBSD:15:amd64`) `pkg` 1.21+. Smoke: the ADR-04 live
  pfSense CE VM.
- **Test suite:** unit cases extend `tests/test_build_pkg_portable.py` (default
  `python -m pytest`); live-VM cases extend `tests/smoke/test_repo_install.py`,
  carrying ADR-17's **`repo` marker** (a distribution flow, deselected from
  `-m smoke`). **Default `python -m pytest` stays unchanged** (the whole
  `tests/smoke` tree is `--ignore`d in default collection). No `pytest` oracle for
  the CI YAML itself → validation = `shellcheck`/`sh -n` + the **live-VM `repo`
  smoke** (§7), which is also the ADR-01-style **kill-gate**.

---

## 1. Context

### Today (verified on `devel` @ 1f62c8c)

1. **There is a release channel, but no nightly channel.** ADR-17 publishes a
   self-hosted `pkg` repository on GitHub Pages at
   `https://andrebrait.github.io/pfBlockerNG/${ABI}`, **derived over the durable
   GitHub *Release* `.pkg` assets** (`repo-publish.yml` enumerates every release —
   `repo-publish.yml:156` `gh api "repos/$REPO/releases" --paginate` — downloads
   their assets, buckets by ABI, runs `scripts/build-repo-portable.py`, and deploys
   the whole tree once). The catalog carries **only** `pfSense-pkg-pfBlockerNG` /
   `-devel`, and a new entry appears there **only when a `vX.Y.Z[-devel]` tag is
   cut**. A user tracking `devel` between releases has **no `pkg`-native way** to get
   the current devel tip — only `git`/manual `pkg add -f` of a CI artifact (forces,
   skips deps), the exact gap ADR-17 closed *for releases*.
2. **The nightly *smoke* already exists; the nightly *channel* does not.**
   `.github/workflows/repo-install.yml` runs the ADR-17 `repo` smoke nightly (cron),
   **gated on `devel` having changed since the last successful run** (the gate job
   anchors on `gh run list --workflow=repo-install.yml --status=success --limit 1`
   then counts `repos/$REPO/commits?since=…`). That validates the *install flow*
   nightly; it does **not** build or publish anything installable. This ADR adds the
   build+publish half, **reusing that exact gate** ("don't publish unless `devel`
   changed").
3. **The portable builder names the main package from `PORTNAME` verbatim.**
   `scripts/build-pkg-portable.py` sets the manifest `name` to `b.portname`
   (`:937`), and `b.portname = mk.get("PORTNAME")` (`:1166`); the pfSense
   `net/pfSense-pkg-pfBlockerNG-devel` port's `PORTNAME` **is** the full string
   `pfSense-pkg-pfBlockerNG-devel` (no `PKGNAMEPREFIX`/`PKGNAMESUFFIX` on the main
   package — those are applied only when resolving **dependency** names, `:639-651`).
   So a distinct package **name** is a **single-field** change, not a prefix/suffix
   dance. The package **version** is `compute_pkgversion(mk)` from
   `PORTVERSION[_PORTREVISION][,PORTEPOCH]` (`:1090`) — there is **no `--version`
   override** today. The CLI exposes `--channel devel|stable` / `--port-dir`
   (`:1288`); a nightly needs a name + version + provenance override path.
4. **`make_manifest` emits no `conflicts` key today** (`scripts/build-pkg-portable.py`
   `make_manifest`, `:935-958` — `name`/`version`/`comment`/`deps`/`annotations`,
   but no `conflicts`). It **does** already emit an `annotations` dict (`:956-957`,
   "annotations appear in BOTH manifests") — so commit provenance has a clean,
   already-supported home. A `conflicts` array must be **added** to make the nightly
   declare a named conflict with the release packages.
5. **`pkg` version comparison has no semver pre-release semantics; `-` is the
   name/version delimiter.** `pkg` derives `(name, version)` from a package string by
   splitting at the **last** `-`, and `PORTVERSION` forbids `-`. Version comparison
   tokenises on `.`/`_`/`,` and compares component-wise; a hash is not orderable.
   Consequences that pin the version scheme below: a literal `…-NIGHTLY-20260606-<sha>`
   mis-parses (version becomes `<sha>`); a hash inside the comparable version breaks
   monotonic `pkg upgrade`; a **bare date `20260606`** is a single numeric component
   that sorts **greater than every release's `3.x` first component forever**. The last
   point is *harmless here* only because the nightly is a **separate package name** —
   its version is **only ever compared nightly-to-nightly**, never against a release.
6. **GitHub Pages allows exactly one deployment per repository.**
   `actions/deploy-pages` publishes a single artifact as the **entire** site,
   replacing it each run (`repo-publish.yml` concurrency `group: pages-pfblockerng`,
   `cancel-in-progress: false`). **Two independent publish workflows deploying to the
   same repo would clobber each other.** This **forces** the nightly catalog to be
   produced by the **same** deploy as the release catalog (§2 Hosting), not a second
   workflow.
7. **The package is tiny.** A built `.pkg` is ≈ 2 MB (ADR-17 Context 5). 14 retained
   nightlies × (one `.pkg` per ABI, one ABI today) ≈ **28 MB** — negligible against
   Pages' 1 GB/100 MB-file/100 GB-month limits.

### Premise to falsify cheaply (the ADR-01 guard)

This ADR makes **no performance/memory claim** (so no benchmark kill-gate). The
premises are two **`pkg` mechanics**, each of which sinks or reshapes the design if
it fails, and **both are falsified on the ADR-04 VM in Phase 1 before any
build/publish CI is written**:

- **Date-version ordering — does `pkg upgrade` move
  `20260605 → 20260606 → 20260606.HHMMSS` monotonically?** The reasoning in Context 5
  says yes (numeric components, date dominant, `.HHMMSS` a more-specific suffix), but
  it is **unproven on a box**. **Reject/redesign** if `pkg` does not treat the dated
  versions as strictly increasing (e.g. it would mean a nightly cannot reliably
  supersede yesterday's).
- **Conflict-and-replace — does a `-NIGHTLY` package actually conflict with an
  installed `-devel`/stable build and replace it cleanly?** The two release packages
  already conflict purely via **identical installed file paths** (pkg refuses
  file-overlapping co-installs); a `-NIGHTLY` installing the same `src/` paths should
  inherit that, and an explicit `conflicts:` array should upgrade it to a *named*
  conflict + replace prompt. **Unproven on a box.** **Reject/redesign** if a box will
  not let the nightly replace a release build (or silently co-installs and corrupts
  the file registry).

Neither premise needs the publish pipeline to test — a hand-built `-NIGHTLY` `.pkg`
in a hermetic `file://` catalog on the VM settles both (Phase 1).

---

## 2. Decision

Add an **opt-in nightly build channel**: a **separately named** package
**`pfSense-pkg-pfBlockerNG-NIGHTLY`** built nightly from `devel` HEAD, versioned by
**build date** (`YYYYMMDD`, same-day rebuild → `YYYYMMDD.HHMMSS`), carrying the source
commit as a **manifest annotation**, declaring an explicit **conflict** with both
release packages, and served from a **separate catalog subtree** on the **same**
ADR-17 Pages site at `…/pfBlockerNG/nightly/${ABI}`. The nightly catalog is a
**derived, fully regenerated index over durable dated GitHub *pre-releases***
(`nightly-YYYYMMDD`, the last **14** retained) — exactly ADR-17's stateless model,
with pre-releases as the durable store in place of Releases. Users opt in with
`scripts/add-repo.sh nightly`, then `pkg install pfSense-pkg-pfBlockerNG-NIGHTLY` and
`pkg upgrade` tracks the newest date.

| Area | Decision |
| --- | --- |
| **Package identity** | A **separate package name** `pfSense-pkg-pfBlockerNG-NIGHTLY` (single-field override of `PORTNAME` — Context 3), **built from the `-devel` port** (identical recipe/plist/deps). A separate name means its version is compared **only nightly-to-nightly**, so a bare date orders correctly and it never shadows a release by version (Context 5). |
| **Version** | **`YYYYMMDD`** (UTC build date); a same-day rebuild appends **`.HHMMSS`** (UTC) → monotonic, stateless, no counter to track. The comparable version contains **no `-` and no hash** (Context 5). New `--pkgversion` builder override (CI passes the date). |
| **Commit provenance** | The source `devel` HEAD sha rides as a **manifest annotation** `commit=<sha>` (already-supported `annotations` dict, Context 4) + appended to the package **COMMENT**; surfaced by `pkg info -A pfSense-pkg-pfBlockerNG-NIGHTLY`. **Not** in the version, **not** in the `.pkg` filename (ADR-17 canonical `<name>-<version>.pkg` + dedup is preserved). New repeatable `--annotate K=V` builder override. |
| **Conflicts** | Emit an explicit **`conflicts: [pfSense-pkg-pfBlockerNG, pfSense-pkg-pfBlockerNG-devel]`** in the nightly manifest (new `conflicts` key, Context 4) — a *named* conflict + clean replace prompt **on top of** the file-overlap conflict the three packages already share. New repeatable `--conflicts <glob>` builder override (default empty → release builds unchanged). |
| **Hosting (forced by Context 6)** | **Unify into ADR-17's `repo-publish.yml`** — one Pages deploy emits **both** `…/${ABI}/` (release, over Releases) **and** `…/nightly/${ABI}/` (nightly, over the last-14 nightly pre-releases). A second deploy workflow is **impossible** (it would clobber the site). The nightly **schedule** triggers this unified deploy; a release tag also triggers it (the release catalog regenerated each time — stateless, harmless). |
| **Catalog = derived index over pre-releases** | The nightly `.pkg` per ABI is attached to a **dated GitHub pre-release `nightly-YYYYMMDD`** (the durable store, mirroring ADR-17's Releases). The unified publish enumerates the **last 14** nightly pre-releases, downloads their assets, buckets by ABI, runs `build-repo-portable.py` into `nightly/<ABI>/`. **Stateless + idempotent** (Pages holds no state of its own). |
| **Retention** | **Keep the last 14 nightly pre-releases** (≈ 14 build-days; within a day the `nightly-YYYYMMDD` tag is updated in place). The nightly build job **prunes** pre-releases older than the newest 14 after staging. ~28 MB/ABI retained (Context 7). |
| **Catalog gen** | **`scripts/build-repo-portable.py` reused unchanged** (pure-Python, no libpkg, ADR-17 Phase 3a). It already dedups per `(name,version,ABI)` and canonical-names — the nightly subtree gets the same treatment for free. |
| **Client bootstrap** | `scripts/add-repo.sh nightly` writes `/usr/local/etc/pkg/repos/pfblockerng-nightly.conf` (`url:` = `…/pfBlockerNG/nightly/${ABI}`, `signature_type: none`, `priority:` above the `pfSense` repo, `enabled: yes`), `pkg update`, verify. README one-liner + a "bleeding-edge / conflicts with release builds / switch back via the release channel" caveat. Static conf URL (URL-encoding gate). |
| **Gate (don't publish unless `devel` changed)** | **Reuse `repo-install.yml`'s last-successful-run gate** (Context 2): the nightly build+stage job runs only when `repos/$REPO/commits?since=<last successful nightly build>` is non-empty. No new build/pre-release/deploy when `devel` is unchanged. |
| **Trust model** | **`signature_type: none`** — identical to ADR-17 (TLS to the Pages host is the anchor; no signing key in CI). |
| **GUI** | **No `src/` change.** The nightly is a CLI/pkg-level channel; the stock GUI **Install** of pfBlockerNG-devel is unaffected (it resolves the `-devel` name, not `-NIGHTLY`). A GUI "channel" picker is **out of scope** (would touch `src/www`; the same deferral as ADR-17). |

### Semantics that MUST be preserved (the contract — pin with tests with the change)

- **The release channel is byte-for-byte unchanged.** A `--channel devel`/`--channel
  stable` build produces the **same** manifest as before (name, version, **no**
  `conflicts` key, deps) — pinned by a unit oracle in
  `tests/test_build_pkg_portable.py` (the new override flags **default off**). The
  release catalog at `…/${ABI}/` and the `pfSense-pkg-pfBlockerNG[-devel]` packages
  are untouched.
- **The existing release/tag flow is intact and unblocked.** A tag still produces the
  Release + ADR-09 per-major `.pkg` attach + the `FreeBSD-ports` PR; the unified
  `repo-publish` stays **additive** and its failure must not break
  `release`/`ports-pr`/`attach-pkgs` (ADR-17's `if: always()` leaf-job isolation is
  retained, not weakened, by adding the nightly subtree).
- **The nightly is a separate name** → a box that enabled only the release repo never
  receives a nightly; a box that enabled only the nightly repo never receives a
  release. `pkg upgrade` on either channel can never cross to the other (different
  names; the conflict only fires on an explicit cross-install).
- **Nightly install needs no `-f`.** `pkg install pfSense-pkg-pfBlockerNG-NIGHTLY`
  resolves dependencies and installs from the nightly catalog; pfBlockerNG
  **registers and runs** (POST-INSTALL hooks, menu, services).
- **Nightly `pkg upgrade` tracks the newest date** monotonically (Phase-1 premise),
  and a **cross-install conflict replaces** the prior build cleanly (Phase-1
  premise).
- **Default suite untouched.** `python -m pytest` stays unchanged (smoke tree
  `--ignore`d); the new unit cases live in the default suite and stay green.
- **No shipped `src/` change** — distribution/CI only.

### Explicitly kept / out of scope

- **A GUI "channel / Updates" picker** (GUI-driven switch between stable / devel /
  nightly) — **out** (touches `src/www`); a natural follow-on ADR, same deferral as
  ADR-17's update-badge gap.
- **Signing (PUBKEY/FINGERPRINTS)** — **out**; `none` (ADR-17 trust model).
- **A second GitHub repo / Pages site for nightlies** — **rejected** in favour of the
  unified same-site deploy (Context 6 makes a second same-repo deploy impossible; a
  *second repo* would add a cross-repo deploy token + a repo to maintain for
  isolation already provided by the separate subtree + package name).
- **Retaining nightlies beyond the last 14** — out (the release channel is the
  durable archive; old nightlies have no audience).
- **Changing ADR-09's matrix or builders, or ADR-17's catalog generator** — consumed,
  not modified (the nightly reuses the per-ABI matrix dedup and
  `build-repo-portable.py` unchanged).

---

## 3. Consequences

**Positive**

- **`pkg`-native bleeding edge.** Users tracking `devel` get
  `pkg install pfSense-pkg-pfBlockerNG-NIGHTLY` + `pkg upgrade` (deps resolved, no
  `-f`), instead of manual `pkg add -f` of a CI artifact.
- **Clean channel separation.** A separate package name + a separate catalog subtree
  means stable / devel / nightly never collide on version, and a user opts into
  exactly one stream. The explicit `conflicts` makes switching a single
  `pkg install`.
- **Stateless, ADR-17-consistent publishing.** The nightly catalog is derived over
  durable dated pre-releases the same way the release catalog is derived over
  Releases — one deploy, no Pages-side state, trivial rollback (re-deploy), last-14
  retained for free.
- **Tiny new surface, maximal reuse.** Reuses ADR-17's Pages deploy, the
  pure-Python catalog generator, the ADR-04 smoke harness, and `repo-install.yml`'s
  devel-changed gate. New code = a few builder flags + one manifest key + one
  `add-repo` channel + one scheduled job + the unified-publish extension.

**Negative / risks**

- **A bare-date version sorts above every release version forever.** Harmless **only**
  because the package name is separate (version compared nightly-to-nightly only) —
  but it is a sharp edge: if the name were ever reused for a release, the date would
  permanently shadow it. Mitigated by the **separate name** being load-bearing and
  asserted (the contract + smoke).
- **Authenticity = TLS only** (`none`), inherited from ADR-17.
- **Nightly builds are unreviewed `devel` tips** — a broken `devel` commit ships to
  nightly users the next night. Mitigated by the **devel-changed gate**; the
  **`repo` smoke validating the freshly-built nightly pkg before deploy** (fail-closed);
  the **switch-back-to-release** escape (`pkg install pfSense-pkg-pfBlockerNG-devel`);
  and the last-14 rollback window.
- **Unifying the nightly into `repo-publish`** means a nightly-subtree build error
  could fail the unified deploy. Mitigated by keeping the unified job an `if: always()`
  **leaf** (no release job `needs:` it — ADR-17's isolation), and by building the
  nightly pkg in the *gated schedule* job (its failure skips the deploy trigger, it
  does not corrupt the release catalog, which regenerates from Releases independently).
- **Same-day rebuild semantics.** `.HHMMSS` disambiguates within a day; the
  `nightly-YYYYMMDD` pre-release is updated in place (latest same-day build wins).

---

## 4. Requirements (acceptance)

1. **Nightly pkg built + named + versioned:** `build-pkg-portable.py` (with the new
   overrides) emits `pfSense-pkg-pfBlockerNG-NIGHTLY` at version `YYYYMMDD[.HHMMSS]`,
   with `conflicts: [pfSense-pkg-pfBlockerNG, pfSense-pkg-pfBlockerNG-devel]` and an
   `annotations.commit=<sha>`; a **release** build (`--channel devel`/`stable`) is
   **byte-identical** to before (no `conflicts`, version from `PORTVERSION`).
2. **Nightly install (no `-f`):** `pkg install pfSense-pkg-pfBlockerNG-NIGHTLY` from
   the nightly catalog resolves deps, installs, registers, and pfBlockerNG runs —
   pinned on the live VM.
3. **Conflict-and-replace (both directions):** installing the nightly over an
   installed `-devel` (and vice versa) is a **named conflict** that replaces cleanly;
   the file registry stays consistent — pinned on the live VM, before/after asserted.
4. **Date-version upgrade:** `pkg upgrade` moves an installed nightly from an earlier
   date to a later date (and `YYYYMMDD` → `YYYYMMDD.HHMMSS`) — pinned on the live VM,
   before ≠ after asserted across ≥ 3 versions.
5. **Unified publish:** one `repo-publish` deploy emits **both** `…/${ABI}/` and
   `…/nightly/${ABI}/`; a real pfSense `pkg update` accepts the nightly catalog; the
   nightly schedule (gated on `devel` changed) builds → stages a `nightly-YYYYMMDD`
   pre-release → prunes past 14 → triggers the deploy.
6. **Additive + safe:** a tag still publishes the Release + ports PR; a nightly
   build/publish failure does not break them or the release catalog; the nightly
   catalog carries only `-NIGHTLY`.
7. **Client bootstrap:** `add-repo.sh nightly` + a README one-liner add the conf,
   `pkg update` succeeds, and the nightly is installable — on a fresh box.
8. **Default suite unchanged; lint-clean:** `python -m pytest` unchanged + the new
   unit cases green; `shellcheck`/`sh -n` clean; markdownlint clean; the URL-encoding
   gate passes for new shell/docs.

---

## 5. Constraints (from `CLAUDE.md`)

- **Shell:** POSIX `sh` only (`#!/bin/sh`), quote all expansions, absolute binary
  paths; the bootstrap fetches a **static** conf URL (no query interpolation — the
  URL-encoding gate).
- **Python (builder/smoke):** 4-space, 3.11+, type hints on new functions, no bare
  `except`; **reuse** the `smoke_vm` fixture + `helpers.py` + `scripts/install-pkg.sh`
  and the `build_repo_via_portable` helper — do **not** add a second VM boot path; new
  live cases carry marker **`repo`** and stay out of default collection.
- **Test coverage rule:** every flow is a **transition** test — assert the **before**
  state (package absent / `-devel` installed / an earlier nightly date) and prove the
  install/upgrade/conflict **caused** the change, with **branch coverage** (conflict
  both directions; date-up *and* date-equal-suffix). The builder unit cases assert the
  release manifest **off** (no `conflicts`) *and* the nightly manifest **on** — proving
  the overrides are a real branch, not an always-on path. Leave the VM clean
  (`finally` / `CaseContext`).
- **Investigation rigor:** assert **effective state** — `pkg info` / `pkg query '%v'` /
  `pkg query '%R'` / `pkg info -A` (the commit annotation) / `pkg which` — never the
  exit code alone.
- **CI:** any workflow that commits/pushes activates the hooks first; least-privilege
  permissions (`contents: write` only where the nightly pre-release is created/pruned;
  `pages: write` + `id-token: write` only on the deploy job — unchanged from ADR-17).
- **Git:** **work in this ADR's `adr/18-nightly-channel` worktree** (reuse across
  phases; create off the latest `origin/devel` if absent), one commit per phase;
  `git fetch` + rebase onto the latest `origin/devel` before every push. Phases that
  touch `scripts/`, `tests/`, or CI land on `devel` via a **rebase-only PR**; **the ADR
  docs themselves push direct to `devel`** (the CLAUDE.md carve-out). PR bodies via
  `--body-file`. Commit style `<scope>: <imperative summary>`.
- **Docs:** README + CLAUDE.md updated when the nightly channel lands (final phase) —
  the install one-liner, the channel/conflict caveat, the unified-deploy + retention-14
  pre-release model.

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` green and the tree lint-clean. The
**cheap falsification is Phase 1** (do dated versions order + does the conflict
replace, on a real box), **before** any builder/publish code. The builder overrides
(Phase 2) are behaviour-preserving prep pinned by unit oracles; the client bootstrap
(Phase 3), the gated build+unified publish (Phase 4), and the full smoke (Phase 5)
make it usable + pinned; docs/DoD close it (Phase 6).

### Phase 1 — KILL-GATE: falsify date-version ordering + conflict-and-replace on the smoke VM

Prompt: `01_Kill_Gate_Pkg_Mechanics.txt`

- Cheaply prove the two `pkg` premises **before** building any tooling. Hand-build a
  minimal `pfSense-pkg-pfBlockerNG-NIGHTLY` `.pkg` at versions `20260605`, `20260606`,
  and `20260606.000001` — by taking the branch `.pkg` and rewriting just the manifest
  `name`/`version`/`conflicts` (e.g. a small in-test repack; no builder change yet),
  serve them in a hermetic `file://` `nightly/<ABI>/` catalog (reuse
  `build_repo_via_portable` / the Phase-1 ADR-17 serving path), and on the ADR-04 VM
  assert, as **transitions**: (a) install `-NIGHTLY` over an installed `-devel` is a
  **named conflict** that **replaces** it (`%R`/`%v`/`%n` before ≠ after; file
  registry consistent), and the reverse install replaces back; (b) `pkg upgrade`
  moves `20260605 → 20260606 → 20260606.000001` **monotonically** (each step
  before ≠ after). Land as new `repo`-marked cases in `tests/smoke/test_repo_install.py`
  (or a sibling `test_nightly_install.py`), minimal. **Record the verdict in
  `RESULTS/01_Results.txt`** — GO only if a real box orders the dated versions and
  replaces across the conflict; else REJECT/redesign (the version scheme or the
  conflict mechanism).

### Phase 2 — Builder overrides + manifest `conflicts` (the build tool), behaviour-preserving for release

Prompt: `02_Builder_Overrides.txt`

- Add to `scripts/build-pkg-portable.py`: a `--channel nightly` (builds from the
  `-devel` port but renames to `pfSense-pkg-pfBlockerNG-NIGHTLY`) **or** explicit
  `--pkgname`/`--pkgversion`/`--annotate K=V` (repeatable)/`--conflicts <glob>`
  (repeatable) overrides — pick the cleanest surface; CI passes the date version, the
  HEAD sha annotation, and the two conflict globs. Add a **`conflicts`** array to
  `make_manifest` (emitted only when non-empty, in **both** compact and full
  manifests). **Unit oracle (no VM)** in `tests/test_build_pkg_portable.py`:
  **(off)** `--channel devel`/`stable` manifest is unchanged — name from `PORTNAME`,
  version from `PORTVERSION`, **no `conflicts` key**; **(on)** the nightly manifest
  carries the `-NIGHTLY` name, the date version, `conflicts: [pfSense-pkg-pfBlockerNG,
  pfSense-pkg-pfBlockerNG-devel]`, and `annotations.commit=<sha>`. ruff/mypy clean.

### Phase 3 — `add-repo.sh nightly` channel + README one-liner

Prompt: `03_Client_Bootstrap.txt`

- Extend `scripts/add-repo.sh` with a `nightly` channel: write
  `/usr/local/etc/pkg/repos/pfblockerng-nightly.conf` (`url:` =
  `…/pfBlockerNG/nightly/${ABI}`, `signature_type: none`, `priority:` above the
  `pfSense` repo, `enabled: yes`), `pkg update`, verify the nightly package is visible
  from our repo; idempotent; the `--print-conf` output stays byte-identical to what the
  catalog side expects. README: the nightly install one-liner + the **bleeding-edge /
  conflicts-with-release / switch-back** caveat. Static conf URL only (URL-encoding
  gate); ShellCheck/`sh -n` clean.

### Phase 4 — Gated nightly build+stage workflow + unify the nightly subtree into `repo-publish`

Prompt: `04_Publish_Pipeline.txt`

- **New scheduled workflow** (cron; **gated on `devel` changed** by reusing
  `repo-install.yml`'s last-successful-run gate): per-ABI build the nightly `.pkg` from
  `devel` HEAD (`--channel nightly`, `--pkgversion $(date -u +%Y%m%d[.%H%M%S])`,
  `--annotate commit=$(git rev-parse --short HEAD)`) over the ADR-09 matrix; upsert a
  dated **`nightly-YYYYMMDD` pre-release** with the `.pkg` assets (the durable store);
  **prune** nightly pre-releases past the newest 14; trigger the unified deploy.
- **Extend `repo-publish.yml`**: alongside the release catalog (over Releases), also
  enumerate the **last 14 `nightly-*` pre-releases**, download their assets, and run
  `build-repo-portable.py` into a **`nightly/<ABI>/`** subtree staged into the **same**
  Pages artifact (one `upload-pages-artifact` + `deploy-pages`). Keep it an
  `if: always()` **leaf** — never gates/breaks `release`/`ports-pr`/`attach-pkgs`;
  `pages: write`+`id-token: write` stay scoped to the deploy job; `contents: write`
  only where the pre-release is created/pruned. Validate with a dispatch run that
  publishes a catalog a VM `pkg update` accepts.

### Phase 5 — Full live-VM smoke: install + conflict + date-upgrade from the nightly catalog

Prompt: `05_Smoke_Coverage.txt`

- Promote Phase 1 into permanent `repo`-marked coverage over a **builder-produced**
  nightly pkg (Phase 2), served from a hermetic `nightly/<ABI>/` catalog: **(a)**
  install `-NIGHTLY` from the nightly catalog (no `-f`, deps resolve, registers, runs,
  `%R` == our nightly repo, `pkg info -A` shows `commit`); **(b)** **conflict-and-replace
  both directions** (`-devel` ⇄ `-NIGHTLY`, before/after asserts); **(c)** **date
  `pkg upgrade`** across ≥ 3 versions (transition each step); **(d)** the shipped
  `add-repo.sh nightly` bootstrap end-to-end (gated dispatch-only real-URL leg reusing
  ADR-17's `SMOKE_REPO_LIVE_URL` pattern, pointing at `…/nightly`). Branch coverage; VM
  left clean.

### Phase 6 — Docs + DoD + Status

Prompt: `06_Docs_DoD.txt`

- README: the nightly install one-liner, how the channel works (separate name +
  conflict, derived-over-pre-releases, `${ABI}`, last-14 retention), the
  bleeding-edge/switch-back caveat. CLAUDE.md "Self-hosted pkg repository" section: the
  nightly channel, the unified deploy, the gate, the retention model. Finalise §7's
  checklist + reject criteria; set Status.

---

## 7. Definition of done

- `python -m pytest` unchanged + the new builder unit cases green; `shellcheck`/`sh -n`/
  markdownlint/URL-encoding gate clean.
- The builder emits a well-formed `pfSense-pkg-pfBlockerNG-NIGHTLY` (date version,
  `conflicts`, `commit` annotation) while a release build stays byte-identical (unit
  oracle).
- A CI dispatch of the unified `repo-publish` regenerates **both** catalogs and deploys
  them to Pages; a live VM `pkg update` against `…/nightly/${ABI}` succeeds. *(The
  hermetic `file://` nightly catalog is VM-accepted in Phases 1/5; the public Pages
  `nightly` deploy + the gated live-URL leg are **post-merge** — see below.)*
- `tests/smoke/test_repo_install.py` (marker **`repo`**) is green for: install the
  nightly (no `-f`, deps resolve, registers, runs, commit annotation present),
  conflict-and-replace both directions, and date `pkg upgrade` across ≥ 3 versions — on
  the ADR-04 VM.
- The existing tag flow still publishes the Release + ports PR; a nightly build/publish
  failure leaves them and the release catalog intact.
- Status flips **Proposed → Implemented (pending the post-merge live Pages `nightly`
  deploy + the gated live-URL verification)** once the hermetic affected-flow smoke
  (install / conflict / date-upgrade) is GREEN on the live VM; **→ Accepted** once the
  post-merge unified `repo-publish` dispatch deploys the public `…/nightly` catalog and
  the gated `test_install_from_live_nightly_url` installs `-NIGHTLY` from the served URL
  — **no human manual-smoke gate** (the live-VM smoke is the oracle).

### POST-MERGE step (flips Implemented → Accepted)

Same GitHub constraint as ADR-17: a brand-new scheduled/`workflow_dispatch` workflow is
only dispatchable once it is on the default branch (`devel`). The nightly workflow +
the unified `repo-publish` extension land with this ADR; then:

1. `gh workflow run <nightly-build>.yml --ref devel` (or dispatch `repo-publish.yml`
   after one nightly build+stage) — builds the nightly pkg, stages the
   `nightly-YYYYMMDD` pre-release, and deploys the unified catalog to Pages (capture
   the run id + the `page_url`; confirm `…/${ABI}/` **and** `…/nightly/${ABI}/` are
   both served, the latter a clean canonical `pfSense-pkg-pfBlockerNG-NIGHTLY-<date>.pkg`).
2. Dispatch the `repo` smoke with `SMOKE_REPO_LIVE_URL=…/pfBlockerNG/nightly` set so
   `test_install_from_live_nightly_url` runs instead of skipping (it polls the served
   nightly catalog, writes the production nightly conf, then `pkg install
   pfSense-pkg-pfBlockerNG-NIGHTLY` with no `-f` asserting `%R == pfblockerng-nightly`).
   Green there confirms the live URL → Status **Accepted**.

### Reject / degrade criteria (decide on evidence)

- **`pkg` does not order the dated versions monotonically** (an earlier date is not
  superseded, or `.HHMMSS` doesn't beat the bare date) → **REJECT/REDESIGN** the
  version scheme (e.g. fall back to `<lastrelease>.<YYYYMMDD>` so a single numeric tail
  orders within the separate name). Settled by **Phase 1** before any tooling.
- **A box won't let the nightly replace a release build across the conflict** (silent
  co-install, or a refused/forced replace that corrupts the registry) → **REJECT**: the
  separate-conflicting-package model fails; reconsider (e.g. a same-name `-devel`
  nightly in a separate repo with priority — the model the user explicitly weighed and
  set aside). Settled by **Phase 1**.
- **Unifying the nightly subtree destabilises the release deploy** (the nightly build
  can fail the unified `repo-publish`) → **DEGRADE**: move the nightly build entirely
  into the gated schedule job (build + stage the pre-release there) and have
  `repo-publish` only ever *read* pre-release assets, so a nightly **build** failure
  never reaches the deploy. Settled by **Phase 4**.
- **Pages bandwidth/size ever bind** (won't at this scale — Context 7) → **MIGRATE** to
  a dedicated static host/CDN (ADR-17's escape hatch); the conf `url:` changes, nothing
  else.

### Affected-flow smoke (gates Accept — on the ADR-04 live VM)

Via `tests/smoke/test_repo_install.py` (marker `repo`), dispatched
`gh workflow run smoke.yml -f pytest_marker=repo`. Each must be GREEN on the live
pfSense CE VM:

- [ ] **Install the nightly, no `-f`.** Package absent → `pkg install
  pfSense-pkg-pfBlockerNG-NIGHTLY` installs **from the nightly repo**
  (`pkg query '%R'` == `pfblockerng-nightly`), deps resolve, every registered file
  lands, `pkg info -A` shows `commit=<sha>`, pfBlockerNG runs.
- [ ] **Conflict-and-replace (both directions).** `-devel` installed → installing
  `-NIGHTLY` is a **named conflict** that replaces it (`%n` `-devel` → `-NIGHTLY`); the
  reverse install replaces back — both directions, before ≠ after, registry
  consistent.
- [ ] **Date `pkg upgrade`.** Nightly catalog carrying only `20260605` ⇒ installed
  `%v == 20260605`; rebuilt with `20260606` ⇒ `pkg upgrade` moves it to `20260606`;
  rebuilt with `20260606.000001` ⇒ `pkg upgrade` moves it again — three real
  before ≠ after transitions, monotonic.
- [ ] **Builder release-build unchanged (unit).** `--channel devel`/`stable` manifest
  has **no `conflicts` key** and `version` from `PORTVERSION`; the nightly manifest has
  both — proving the overrides are a branch, not an always-on path.
- [ ] **Additive safety.** The unified `repo-publish` stays a leaf gated `if: always()`;
  a nightly build/stage/deploy failure cannot gate or break
  `release`/`ports-pr`/`attach-pkgs` or the release catalog (job-isolation review).
- [ ] **Live `…/nightly` URL (post-merge, gated).** `test_install_from_live_nightly_url`
  installs `-NIGHTLY` from the served `andrebrait.github.io/pfBlockerNG/nightly` catalog
  (gated on `SMOKE_REPO_LIVE_URL`).
