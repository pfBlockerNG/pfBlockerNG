# ADR-17: Self-hosted pfSense `pkg` repository on GitHub Pages

- **Status:** **Implemented** (2026-06-05) — *pending the post-merge live Pages deploy +
  the gated live-URL verification.* The hermetic affected-flow smoke (install / cross-repo
  precedence / `pkg upgrade`) is **GREEN on the live VM** (§7); only the public
  `andrebrait.github.io` Pages deploy + the live-URL leg remain, which are **post-merge** (a brand-new
  `workflow_dispatch` workflow is only dispatchable once it lands on the default branch
  `devel`). Flips to **Accepted** once that deploy dispatch confirms the live
  `https://andrebrait.github.io/pfBlockerNG/${ABI}` URL.
- **Date:** 2026-06-05
- **Branch:** `adr/17` (off **`devel`**) / **Component(s):** new dev-only CI — a
  **repo-publish** job/workflow that consumes ADR-09's release `.pkg` artifacts +
  `read-version-matrix` action and deploys a `pkg` catalog to **GitHub Pages**; new
  `scripts/build-repo-portable.py` (primary pure-Python catalog generator) +
  `scripts/build-repo.sh` (FreeBSD-VM fallback / `--print-conf` template) +
  `scripts/add-repo.sh` (client bootstrap); new live-VM
  `tests/smoke/test_repo_install.py` (marker `repo`). **Reused, not modified:** ADR-09's
  `read-version-matrix` action, the portable builder (`build-pkg-linux.yml` /
  `scripts/build-pkg-portable.py`), the `release.yml` `.pkg` artifacts, the ADR-04
  smoke harness (`tests/smoke/conftest.py` `smoke_vm` + `helpers.py` +
  `scripts/install-pkg.sh`). **No shipped (`src/`) code changes** (the repo-only
  scope — §2; the GUI panel that would touch `src/www` is explicitly out of scope).
- **Target runtime:** GitHub Actions — `ubuntu-latest` with a **pure-Python catalog
  generator** (`scripts/build-repo-portable.py`; **no libpkg** — Phase 3a falsified
  the "portable builder proves libpkg-on-Linux" assumption: `build-pkg-portable.py`
  hand-rolls the `.pkg` archive in pure Python and never invokes libpkg, so the
  catalog is hand-rolled the same way), with the **FreeBSD VM** (`build-pkg.yml`
  path, `scripts/build-repo.sh` + real `pkg repo`) retained as the fidelity
  fallback. Client side: pfSense **CE 2.8+** (`FreeBSD:15:amd64`) `pkg` 1.21+.
  Smoke: the ADR-04 live pfSense CE VM.
- **Test suite:** a new live-VM `tests/smoke/test_repo_install.py` carrying its **own
  marker `repo`** (a distribution flow, deselected from `-m smoke`). **Default
  `python -m pytest` stays unchanged** (the whole `tests/smoke` tree is `--ignore`d in
  default collection). No `pytest` oracle for the CI YAML / shell itself → validation =
  `shellcheck`/`sh -n` + the **live-VM `repo` smoke** (§7), which is also the
  ADR-01-style **kill-gate**.

---

## 1. Context

### Today (verified on `devel` @ 91b62bf)

1. **There is no installable repository — only Release assets.** After ADR-09,
   `release.yml` on a `vX.Y.Z[-devel]` tag runs `read-matrix` → `build-pkgs-portable`
   → `attach-pkgs`: it builds **one `.pkg` per distinct FreeBSD major** (deduped from
   the matrix) and **attaches** them to the GitHub Release, and `ports-pr` opens the
   PR on `pfsense/FreeBSD-ports` (the Netgate channel). The **only** way a user gets
   our build directly is: download the Release asset and `pkg add -f` — which
   **forces** the install, **skipping dependency resolution and any signature**. That
   is the gap this ADR closes.
2. **ADR-09 already supplies the build half — ADR-17 consumes it.** Merged ADR-09
   provides: the decoupled supported-version matrix on the `ci-metadata` orphan ref
   (schema per entry: `{pfsense_version, channel, freebsd_version, freebsd_major,
   php_version, py_flavor, status, ci}` — it carries the **`py_flavor`** already);
   the `.github/actions/read-version-matrix` composite action; and the portable
   Linux `.pkg` builder. **This ADR does not re-derive any of that** — it builds the
   *repository* over the artifacts ADR-09 already produces.
3. **pfSense GUI install is NOT repo-locked — only discovery is** (read from upstream
   `pfsense/pfSense` `master`, verified):
   - **Discovery** — `get_pkg_info()` (`src/etc/inc/pkg-utils.inc`) lists via
     `pkg search -r {$g['product_name']} {$g['pkg_prefix']}*` →
     `pkg search -r pfSense pfSense-pkg-*` (`globals.inc`: `product_name => 'pfSense'`,
     `pkg_prefix => 'pfSense-pkg-'`). **Available Packages is restricted to the repo
     named `pfSense` (Netgate's)** — a third-party repo **cannot add list entries**.
   - **Install** — `pkg_install()` runs `pkg install -y <name>` with **no `-r`**. So
     `pkg` resolves the name across **all enabled repos**, and selection is keyed
     **first on repo `priority:`** — a **higher-priority repo wins even at a lower
     version**. *(Phase-1 live-VM finding — falsifies the earlier "highest version
     wins, priority breaks ties": on the VM a competing repo at `priority: 200` /
     version `_1` BEAT ours at `priority: 99` / version `_9`. Version is the
     **secondary** key, only between equal-priority repos.)* → once a package is
     *listed* (Netgate's repo carries `pfSense-pkg-pfBlockerNG-devel` via our ports
     PR), our repo wins the GUI **Install** button purely because `add-repo.sh` sets
     its `priority:` **above** the Netgate `pfSense` repo — **regardless of version**.
     No GUI patching, no co-opting the `pfSense` repo name.
   - **Installed Packages** (`pkg_mgr_installed.php`) reads the **local pkg db** → a
     pfBlockerNG installed from our repo **shows there and runs normally**, identical
     to a Netgate-repo install. Only Available-list **discovery** and the GUI
     **"update available" badge** stay Netgate-bound (the badge compares the installed
     version against the `-r pfSense` remote).
   - pfSense's **GUI branch selector** reads only `/usr/local/etc/pfSense/pkg/repos`
     (`$g['pkg_repos_path']`); our conf lives in the standard
     `/usr/local/etc/pkg/repos/` read by `pkg(8)` — so it is a **CLI/pkg-level** repo,
     invisible to (and not disturbing) the base-system branch selector. `pfSense-repo-setup`
     regenerates only the `pfSense` conf, not ours.
4. **FreeBSD `pkg` repository mechanics.** `pkg repo <dir> [signing]` turns a directory
   of `.pkg` files into a catalog (`meta.conf`, `packagesite.pkg`, `data.pkg`). A client
   repo conf (`/usr/local/etc/pkg/repos/<name>.conf`) declares `url:`, `mirror_type:`,
   `signature_type:` (`NONE` | `PUBKEY` | `FINGERPRINTS`), `priority:`, `enabled:`. The
   `url:` supports the **`${ABI}` variable** (e.g. `https://<user>.github.io/pfBlockerNG/${ABI}`),
   so one conf **auto-follows the box's ABI across a pfSense OS upgrade**. pfSense imposes
   **nothing** on third-party repos — `signature_type: none` (trust = HTTPS to the host)
   is honored; there is **no global "require signed" knob**.
5. **The package is tiny — hosting is not a size problem.** pfBlockerNG is a data-only
   port (PHP/Python/shell) and **does not bundle its RUN_DEPENDS** (they resolve from
   Netgate's repo). The built `.pkg` is **≈ 2 MB** (`src/` is 6.4 MB → ~2 MB
   compressed). The whole repo = a few ~2 MB `.pkg` (one per ABI/flavor — **one today**)
   plus tiny catalog files. **GitHub Pages limits** (published site ≤ 1 GB, soft
   bandwidth 100 GB/month, 100 MB/file) are **comfortably non-binding** (~50k
   installs/month before the soft bandwidth cap whispers). **Pages is chosen for the
   directory layout** a `pkg` repo needs (a base URL + `${ABI}` subpaths + `All/`),
   which flat Release assets cannot express — **not** for size.

### Premise to falsify cheaply (the ADR-01 guard)

Two independent premises; either failing reshapes or sinks the ADR. **Both are
falsified before the publishing pipeline is built** (Phase 1 spikes the harder one).

- **Client-side (the real premise) — does a live pfSense box install/upgrade from a
  third-party GitHub-hosted, NONE-signed repo?** The reasoning above says yes (the
  install action isn't repo-locked; `${ABI}` follows the OS), but it is **unproven on
  a box**. **Phase 1 spikes it on the ADR-04 VM**: hand-build a minimal repo from one
  portable `.pkg`, serve it, add a repo conf, `pkg install pfSense-pkg-pfBlockerNG-devel`
  **with no `-f`**, and assert it installs from *our* repo (deps resolve, registers,
  runs) **and** that cross-repo precedence picks our build over a lower-versioned
  decoy. **Reject/redesign** if pfSense refuses a third-party repo for install, the
  conf does not persist, or precedence can't be made to favor our build.
- **Build-side — can a pfSense-acceptable catalog be generated on a Linux runner?**
  The portable builder already runs libpkg on Linux to *create* packages; `pkg repo`
  (catalog gen) is another libpkg op. **Phase 2 confirms** the Linux-generated catalog
  is accepted by a real pfSense `pkg update`. If not, **fall back** to generating the
  catalog on the FreeBSD VM (`build-pkg.yml` already provides one) — a localized
  change, not a sink.
- **Cross-pfSense-version upgrade — does *our* build survive an OS upgrade?** pfSense's
  own `pfSense-upgrade` reinstalls `pfSense-pkg-*` for the new version and likely runs
  `-r pfSense`. Whether our build leads after an OS-major jump depends on version
  precedence and whether that reinstall is repo-locked. The **single-image** precedence
  case (our higher version wins on `pkg upgrade`) is proven in Phase 1/5; the **true
  OS-major upgrade** is **dispatch-only** (needs the image-refresh chain) and, if it
  can't be made to favor our build, **degrades to a documented CLI `pkg upgrade` step**.

---

## 2. Decision

Publish a **self-hosted FreeBSD `pkg` repository on GitHub Pages**, generated in CI
over the `.pkg` artifacts ADR-09 already attaches to each GitHub Release, served as a
per-`${ABI}` directory tree with **`signature_type: none`** (TLS-anchored). Users add
a one-time repo conf (`scripts/add-repo.sh` / a README one-liner) and then **`pkg
install` / `pkg upgrade`** — and, because the GUI **Install** action is not
repo-locked, the **stock webConfigurator Install of pfBlockerNG-devel transparently
pulls our build** via cross-repo resolution. The repository is a **derived, fully
regenerated index over the durable Release assets** — no stateful accumulation.

| Area | Decision |
| --- | --- |
| **Trust model** | **`signature_type: none`** — `pkg` fetches over HTTPS; trust anchor = TLS to the GitHub-Pages host (`andrebrait.github.io`, GitHub's `*.github.io` cert; matches the project's image-no-signature precedent). **No signing key in CI** (a CI-resident key would itself be a root-code attack surface). pfSense honors per-repo `none` (Context 4). |
| **Hosting** | **GitHub Pages**, deployed via `actions/upload-pages-artifact` + `actions/deploy-pages` (the site is *replaced* each deploy → **no `gh-pages` history bloat**; the 1 GB source-repo concern never arises). |
| **Repo = derived index over Releases** | The **GitHub Releases** `.pkg` assets (ADR-09 `attach-pkgs`) are the **durable store**. The publish job **enumerates all releases, downloads their `.pkg` assets, buckets by ABI, runs `pkg repo` per ABI dir, and deploys the whole tree** — **stateless + idempotent**, so every published build (all versions, all ABIs) is retained without accumulating state. |
| **Layout + `${ABI}`** | One catalog per ABI under `…/<ABI>/` (e.g. `…/FreeBSD:15:amd64/`); the client conf `url:` uses **`${ABI}`** so it auto-follows an OS upgrade. **Flavor collision guard:** today every supported combo collapses to one tree (CE 2.8 + Plus 25.03 are both FreeBSD15 / php83 / py311). **If** two matrix entries ever share ABI **and** package-version but differ in php/py, the same name+version+ABI **cannot coexist** in one catalog → split into `…/<ABI>-<php><py>/` subtrees and have `add-repo.sh` detect+pin the box's flavor. `build-repo.sh` **fails loud** on an unhandled collision (never silently drops a build). |
| **Catalog gen** | **libpkg on `ubuntu-latest`** (reuse the portable builder's libpkg); **FreeBSD VM fallback** if a real pfSense `pkg update` rejects the Linux-generated catalog (Phase 2 decides on evidence). |
| **Client bootstrap** | `scripts/add-repo.sh` writes `/usr/local/etc/pkg/repos/pfblockerng-devel.conf` (`url:` with `${ABI}`, `signature_type: none`, `priority:` above the `pfSense` repo, `enabled: yes`), runs `pkg update`, verifies. README one-liner. **CLI-only setup**; thereafter GUI Install works via cross-repo resolution. |
| **GUI** | **No `src/` change.** Stock GUI **Install** of pfBlockerNG-devel pulls our build (Context 3, install not repo-locked). The GUI **update badge** stays Netgate-bound (a documented limitation); a pfBlockerNG GUI "Updates/Channel" panel for GUI-driven upgrade-to-our-latest is **out of scope** (deferred — would touch `src/www`). |
| **Catalog contents** | **Only** `pfSense-pkg-pfBlockerNG` / `-devel`. Our repo therefore **only ever competes for our own package** — `pkg upgrade` can never pull anything else from us. |
| **Repo precedence (priority)** | **Repo `priority:` is the primary key — it dominates version** (Phase-1 live-VM finding: a higher-priority repo wins even at a *lower* version). `add-repo.sh` sets our `priority:` **above** the Netgate `pfSense` repo, so cross-repo resolution selects **ours regardless of version**. Versioning discipline is therefore **secondary** (it only orders equal-priority repos) — `priority:` is the lever; the smoke pins precedence in both directions. |

### Semantics that MUST be preserved (the contract — pin with tests with the change)

- **The existing release flow is intact and unblocked.** A tag still produces the
  GitHub Release (source tarball) + ADR-09's per-major `.pkg` attach **and** the
  `FreeBSD-ports` PR. The repo-publish job is **additive** and **its failure must not
  break** `release`/`ports-pr`/`attach-pkgs` (separate job; `if: always()` gating;
  least-privilege except the Pages deploy).
- **Our catalog contains only pfBlockerNG** → a box that enabled our repo never
  receives any other package from us.
- **Repo install needs no `-f`.** `pkg install pfSense-pkg-pfBlockerNG-devel` resolves
  dependencies and installs from our repo; cross-repo precedence selects our build;
  pfBlockerNG **registers and runs** (POST-INSTALL hooks, menu, services).
- **Cross-version follow:** the `${ABI}` conf points at the box's current ABI tree;
  `pkg upgrade` pulls our matching build **when one is published** (precedence holds).
- **Default suite untouched.** `python -m pytest` stays unchanged (smoke tree `--ignore`d).
- **No shipped `src/` change** — distribution/CI only.

### Explicitly kept / out of scope

- **A pfBlockerNG GUI "Updates/Channel" panel** (GUI-driven upgrade to *our* latest,
  closing the Netgate-bound badge gap) — **out** (touches `src/www`); a natural
  follow-on ADR/phase if wanted.
- **Signing (PUBKEY/FINGERPRINTS)** — **out**; `none` chosen (Context 4 / Trust).
- **Adding entries to the stock Available Packages list** — **impossible** without
  patching pfSense (`-r pfSense`); not attempted. Discovery rides on Netgate listing
  the package (it does); CLI `pkg install` needs no listing at all.
- **Base-system repo / pfSense branch-selector integration** — untouched.
- **Changing ADR-09's matrix or builders** — consumed, not modified.
- **Bundling RUN_DEPENDS** into the repo — out; they resolve from Netgate's repo
  (the `.pkg` stays ~2 MB).

---

## 3. Consequences

**Positive**

- **One-command install + real upgrades.** `pkg install` / `pkg upgrade` (deps
  resolved, no `-f`), and the **stock GUI Install pulls our build** with zero GUI
  hacking — the headline goal.
- **Cross-pfSense-version aware.** `${ABI}` + ADR-09's per-release matrix means a box
  on a newer pfSense gets the matching build (where published), without re-bootstrapping.
- **Idempotent, stateless publishing.** The repo is regenerated over the durable
  Release assets each deploy → no history bloat, trivial rollback (re-deploy), all
  versions/ABIs retained for free.
- **Tiny new surface, maximal reuse.** Consumes ADR-09's matrix/builder/artifacts and
  the ADR-04 smoke harness; the only new code is two scripts + one CI job + one smoke.
- **No key to leak.** `none` removes the CI-private-key supply-chain risk entirely.

**Negative / risks**

- **Authenticity = TLS only.** `none` means a compromise of the Pages host's TLS
  (`andrebrait.github.io`) or the Pages content could serve altered root-running packages. Accepted
  per precedent; revisitable to **offline-signed PUBKEY** later (key never in CI) — the
  conf gains a `signature_type`, the layout is unchanged.
- **GUI discovery + update badge stay Netgate-bound** (Context 3). Our newer builds
  install via GUI Install / CLI `pkg upgrade` but the GUI won't *badge* them — a
  documented limitation; the deferred GUI panel would close it.
- **Cross-repo precedence races.** `priority:` is the primary key (Phase-1 finding), so
  our above-Netgate `priority:` makes ours win — but that also means we **shadow** a
  same-name Netgate build by `priority:` even when theirs is newer (our catalog carries
  only pfBlockerNG, so the blast radius is our own package). Mitigated by the
  above-Netgate `priority:` + versioning discipline (the secondary key) + the smoke
  precedence assertions in both directions.
- **OS-major upgrade survival is the residual unknown** (Premise 3) — single-image
  precedence is proven; true major-jump survival is dispatch-only and may degrade to a
  documented CLI `pkg upgrade`.
- **Linux catalog-gen fidelity.** Mitigated by the FreeBSD-VM fallback and the smoke
  proving a real pfSense `pkg update` accepts the catalog.

---

## 4. Requirements (acceptance)

1. **Catalog generated + published:** a CI job regenerates a `pkg` catalog over **all**
   Release `.pkg` assets, bucketed per ABI under `…/<ABI>/`, and deploys it to GitHub
   Pages; a real pfSense `pkg update` against the URL succeeds.
2. **Repo install (no `-f`):** `pkg install pfSense-pkg-pfBlockerNG-devel` from our repo
   resolves deps, installs, registers, and pfBlockerNG runs — pinned on the live VM,
   asserting cross-repo precedence picks our build (vs a lower decoy).
3. **GUI install path:** the stock webConfigurator Install of pfBlockerNG-devel pulls
   our build via cross-repo resolution (asserted via the effective installed version /
   repo origin, not the HTTP response).
4. **Cross-version follow:** the `${ABI}` conf + a `pkg upgrade` pulls our matching
   build on a version bump (single-image precedence proven; OS-major upgrade dispatch-only
   or documented-CLI if it can't favor our build).
5. **Additive + safe:** a tag still publishes the Release + ports PR; a repo-publish
   failure does not break them; our catalog carries only pfBlockerNG.
6. **Client bootstrap:** `add-repo.sh` + a README one-liner add the conf, `pkg update`
   succeeds, and the package is installable — on a fresh box.
7. **Default suite unchanged; lint-clean:** `python -m pytest` unchanged; `shellcheck`/
   `sh -n` clean; markdownlint clean; the URL-encoding gate passes for new shell/docs.

---

## 5. Constraints (from `CLAUDE.md`)

- **Shell:** POSIX `sh` only (`#!/bin/sh`), quote all expansions, absolute binary paths;
  pass values that may be empty/spaced via their own option (the URL-encoding gate) — the
  bootstrap fetches a **static** conf URL (no query interpolation).
- **Python (smoke):** 4-space, 3.11+, type hints, no bare `except`; **reuse** the
  `smoke_vm` fixture + `helpers.py` + `scripts/install-pkg.sh` — do **not** add a second
  VM boot path; the test carries marker `smoke` and stays out of default collection.
- **Test coverage rule:** every flow is a **transition** test — assert the **before**
  state (package absent / a lower decoy version installed) and prove the install/upgrade
  **caused** the change, with **branch coverage** (our-version-higher ⇒ ours wins; lower
  ⇒ Netgate-like wins). Leave the VM clean (`finally` / `CaseContext`).
- **Investigation rigor:** assert **effective state** — `pkg info`/`pkg query %v`/`pkg
  which`, the installed version, the repo origin (`pkg query '%R'`) — never the exit code
  alone; follow the chroot/path rules where relevant.
- **CI:** any workflow that commits/pushes activates the hooks first; least-privilege
  permissions (`pages: write` + `id-token: write` **only** on the deploy job).
- **Git:** **work in this ADR's `adr/17` worktree** (reuse across phases; create off the
  latest `origin/devel` if absent), one commit per phase; `git fetch` + rebase onto the
  latest `origin/devel` before every push. Phases that touch `scripts/`, `tests/`, or CI
  land on `devel` via a **rebase-only PR**; **the ADR docs themselves push direct to
  `devel`** (the CLAUDE.md carve-out). PR bodies via `--body-file`. Commit style
  `<scope>: <imperative summary>`.
- **Docs:** README + CLAUDE.md updated when the install/upgrade UX + the repo pipeline
  land (final phase).

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` unchanged/green and the tree
lint-clean. The **cheap falsification is Phase 1** (does a real box install from a
third-party repo at all), **before** any publishing pipeline is built. The build tool
(Phase 2) and the publish pipeline (Phase 3) follow; the client bootstrap (Phase 4) and
full smoke coverage (Phase 5) make it usable + pinned; docs/DoD close it (Phase 6).

### Phase 1 — KILL-GATE: falsify "a pfSense box installs from a third-party repo" on the smoke VM

Prompt: `01_Spike_Repo_Install.txt`

- Cheaply prove the core premise **before** building CI. Build one portable `.pkg`
  (existing builder), hand-assemble a minimal single-ABI catalog (`pkg repo`), serve it
  to the ADR-04 VM (the existing mock HTTP server / a `file://` or on-box dir), add a
  repo conf (`signature_type: none`), and `pkg install pfSense-pkg-pfBlockerNG-devel`
  **with no `-f`**. **Assert (transition):** package absent → installed **from our
  repo** (`pkg query '%R'`), deps resolved, POST-INSTALL ran, pfBlockerNG functions; and
  **cross-repo precedence** picks our build over a lower-versioned decoy (and the decoy
  wins when ours is lower — both branches). Land as `tests/smoke/test_repo_install.py`
  (marker `repo`, deselected from `-m smoke`), minimal. **Record the verdict in
  `RESULTS/01_Results.txt`** — GO only
  if a real box honors the third-party repo for install + precedence; else REJECT/redesign.

### Phase 2 — Catalog generator + `${ABI}` layout + repo-conf template (the build tool)

Prompt: `02_Build_Repo_Tool.txt`

- `scripts/build-repo.sh` (POSIX sh): given a dir of `.pkg`, bucket by ABI, run
  `pkg repo` per `…/<ABI>/`, emit the tree + the **flavor-collision guard** (fail loud on
  an unhandled same-name+version+ABI/different-flavor clash). Emit the client repo-conf
  template (`${ABI}` url, `signature_type: none`, `priority`, `enabled`). **Confirm
  libpkg-on-Linux catalog gen is accepted by a real pfSense `pkg update`** (reuse the
  Phase-1 VM); if not, wire the **FreeBSD-VM fallback** and record the decision. ShellCheck/
  `sh -n` clean; a tiny fixture-based local run in the handoff.

### Phase 3 — Publish pipeline: regenerate over Releases → deploy to Pages

Prompt: `03_Publish_Pipeline.txt`

- Add a **repo-publish** job/workflow (consumes `read-version-matrix` + the release
  `.pkg` artifacts): enumerate **all** releases → download their `.pkg` assets → bucket
  by ABI → `scripts/build-repo.sh` → `actions/upload-pages-artifact` + `deploy-pages`.
  **Additive + isolated:** `if: always()`, never gates/breaks `release`/`ports-pr`/
  `attach-pkgs`; `pages: write` + `id-token: write` scoped to the deploy job only.
  Enable the Pages environment. Validate with a dispatch run that publishes a catalog a
  VM `pkg update` accepts.

### Phase 4 — Client bootstrap (`add-repo.sh`) + README one-liner

Prompt: `04_Client_Bootstrap.txt`

- `scripts/add-repo.sh` (POSIX sh): write `/usr/local/etc/pkg/repos/pfblockerng-devel.conf`
  (`${ABI}` url, `none`, `priority`, `enabled`), `pkg update`, verify the package is
  visible from our repo; idempotent; channel arg (devel|stable). README: the one-line
  install + the discovery/update-badge caveat (Context 3). Static conf URL only (URL-encoding gate).

### Phase 5 — Full live-VM smoke: install + precedence + upgrade (falsify-first, then expand)

Prompt: `05_Smoke_Coverage.txt`

- Promote Phase 1 into the full `test_repo_install.py`: **(a)** GUI-path / CLI install from
  our repo (cross-repo precedence both branches, before/after asserts); **(b)** `pkg
  upgrade` from a lower installed version → our newer build (transition); **(c)**
  **dispatch-only** real-`andrebrait.github.io`-URL install (hermetic mock is the gated default).
  If the OS-major upgrade-survival case can't favor our build, **document the CLI
  `pkg upgrade` degrade** and record numbers. Branch coverage + VM left clean.

### Phase 6 — Docs + DoD + Status

Prompt: `06_Docs_DoD.txt`

- README: the install one-liner, how the repo works (derived-over-Releases, `${ABI}`),
  the **GUI discovery/update-badge caveat**, the **deferred GUI panel**. CLAUDE.md: the
  repo-publish pipeline + the smoke. Finalise §7's checklist + reject criteria; set Status.

---

## 7. Definition of done

- `python -m pytest` unchanged; `shellcheck`/`sh -n`/markdownlint/URL-encoding gate clean.
- A CI dispatch regenerates the catalog over all Release `.pkg` and deploys it to Pages;
  a live VM `pkg update` against the URL succeeds. *(The hermetic `file://` + portable +
  `build-repo.sh` catalogs are VM-accepted now; the public Pages deploy + the live-URL
  leg are **post-merge** — see below.)*
- `tests/smoke/test_repo_install.py` (marker **`repo`**) is green: install-from-our-repo
  (no `-f`, deps resolve, registers, runs), cross-repo precedence (both branches), and
  `pkg upgrade` to our newer build — on the ADR-04 VM.
- The existing tag flow still publishes the Release + ports PR; the repo-publish job's
  failure leaves them intact.
- Status flips **Proposed → Implemented (pending the post-merge live Pages deploy + the
  gated live-URL verification)** — the hermetic affected-flow smoke (install / precedence /
  `pkg upgrade`) is GREEN on the live VM; **→ Accepted** once the post-merge `repo-publish`
  dispatch deploys the public `andrebrait.github.io` catalog and the gated
  `test_install_from_live_pages_url` installs from the served URL — **no human
  manual-smoke gate** (the live-VM smoke is the oracle).

### POST-MERGE step (flips Implemented → Accepted)

The live Pages deploy + the gated `test_install_from_live_pages_url` leg are **post-merge**,
a GitHub constraint: a brand-new `workflow_dispatch` workflow is only dispatchable once it
exists on the default branch (`devel`). `repo-publish.yml` lands with this ADR; then:

1. `gh workflow run repo-publish.yml --ref devel -f build_branch_pkg=true` — deploys the
   catalog to Pages (capture the run id + the `page_url`).
2. Dispatch the `repo` smoke with `SMOKE_REPO_LIVE_URL=https://andrebrait.github.io/pfBlockerNG` set, so
   `test_install_from_live_pages_url` runs instead of skipping (it polls the served catalog,
   pins the Pages anycast IPs, writes our production conf, then `pkg install` with no `-f`
   asserting `%R == pfblockerng-devel`). Green there confirms the live URL → Status **Accepted**.

### Reject / degrade criteria (decide on evidence)

- **pfSense refuses a third-party repo for install** (the conf is ignored/overwritten, or
  cross-repo precedence can't favor our build) → **REJECT**: the GUI/CLI install premise
  fails; fall back to documenting `pkg add -f` of the Release asset (status quo). Settled
  by **Phase 1** before any pipeline is built.
- **Linux catalog gen is not pfSense-acceptable** → **DEGRADE**: generate the catalog on
  the FreeBSD VM (`build-pkg.yml`); localized, not a sink. Settled by **Phase 2**.
- **OS-major upgrade can't be made to favor our build** → **DEGRADE** *(outcome:
  **DEGRADED-TO-CLI**, recorded in `RESULTS/05_Results.txt`)*: a true OS-major jump
  (e.g. `FreeBSD:15` → `FreeBSD:16`, which changes `${ABI}` and thus the served `<ABI>/`
  subtree) is not reachable on a single CE smoke image — an in-place `pfSense-upgrade`
  across a major is `image-refresh.yml`'s job (ADR-09), not this per-run flow. The
  single-image upgrade (`_1` → `_9` within one ABI) is proven; the OS-major case degrades
  to the documented operator action: after a pfSense OS upgrade the box's `${ABI}` follows
  it automatically (the conf `url:` is the literal `${ABI}`, §2), so a plain CLI
  `pkg update -f && pkg upgrade` pulls our build for the **new** ABI once that ABI's catalog
  is published. No test attempts it (it would fail-skip on one image) — a deliberate,
  documented non-goal for the flow.
- **Pages bandwidth/size ever bind** (won't at this scale — Context 5) → **MIGRATE** to a
  dedicated static host/CDN (same escape hatch ADR-09 wrote for `ci-metadata`); the conf
  `url:` changes, nothing else.

### Affected-flow smoke (gates Accept — on the ADR-04 live VM)

All five are GREEN on the live pfSense CE VM via `tests/smoke/test_repo_install.py` (marker
`repo`), dispatched `gh workflow run smoke.yml -f pytest_marker=repo` (the standalone
`repo-install.yml` is dispatchable once on `devel`). Run ids cite the load-bearing dispatch.

- [x] **Install from our repo, no `-f`.** Package absent → `pkg install
  pfSense-pkg-pfBlockerNG-devel` installs **from our repo** (`pkg query '%R'` ==
  `pfblockerng-devel`), deps resolve, every registered file lands (> 50), no `-f`.
  *(`test_install_from_our_repo_lands_all_files` — run **27031334263**, P1.)*
- [x] **Cross-repo precedence (both branches).** Proven priority-driven against a controlled
  `netgate-decoy` repo serving the same package: ours at the higher `priority:` ⇒ ours
  installs (`%R == pfblockerng-devel`); the decoy at the higher `priority:` ⇒ the decoy
  installs (`%R == netgate-decoy`) — both directions, so precedence is real, not incidental.
  *(`test_precedence_ours_higher_priority_wins` + `test_precedence_decoy_higher_priority_wins`
  — run **27031334263**, P1.)*
- [x] **`pkg update` accepts the catalog.** The hermetic `file://` Pages-style catalog —
  from **both** generators — is consumed without error: `build-repo.sh` (real `pkg repo`)
  and `build-repo-portable.py` (pure-Python). *(`test_build_repo_script_catalog_is_accepted`
  — run **27033922928**, P2; `test_portable_catalog_is_accepted` — run **27035602221**, P3a.
  The real `andrebrait.github.io` URL leg, `test_install_from_live_pages_url`, is gated on
  `SMOKE_REPO_LIVE_URL` and is the post-merge step above.)*
- [x] **Upgrade to our newer build.** Our repo carrying only `_1` ⇒ installed `%v == _1`
  from `pfblockerng-devel`; same repo rebuilt with `_9` ⇒ `pkg upgrade` moves it to
  `%v == _9`, still from `pfblockerng-devel` — a real before ≠ after transition, both
  versions asserted. The shipped `add-repo.sh` bootstrap is also exercised end-to-end.
  *(`test_pkg_upgrade_moves_to_our_newer_build` + `test_shipped_add_repo_sh_bootstrap_installs`
  — run **27040686824**, P5.)*
- [x] **Additive safety.** `repo-publish` is a **leaf** in `release.yml`'s `needs:` graph
  (nothing depends on it) and is gated `if: always()`, copied from `attach-pkgs` — so a
  repo-publish failure (build / generator / Pages deploy) cannot gate or break
  `release`/`ports-pr`/`attach-pkgs`. *(Job-isolation review, P3 — `RESULTS/03_Results.txt`.)*
