# ADR-39: Meta-package distribution + Cloudflare Worker retirement

- **Status:** **Proposed** (2026-06-21)
- **Date:** 2026-06-21
- **Branch:** `adr/39-meta-package-distribution` (off **`devel`**; `{slug}` = sanitised
  ADR-title slug per CLAUDE.md "Branch naming") / **Component(s):** dev-only
  distribution/CI — `scripts/add-repo.sh` (repoint to direct Pages + install the
  meta-package), a new shared on-box detection helper, the new `pfblockerng-repo`
  **meta-package** port on `pfBlockerNG/FreeBSD-ports@pfblockerng/use-github`
  (`pkg-post-install.in` / `pkg-post-deinstall.in`), `pfBlockerNG/pkg`'s `publish.yml`
  (build + inject the meta-package per catalog), `scripts/build-repo-portable.py`
  (delete `routing.json` generation); `scripts/worker/`, `.github/workflows/deploy-worker.yml`,
  and the `worker-tests` CI job (**deleted**).
  **Supersedes:** ADR-20's dynamic-routing layer (the Cloudflare Worker + `routing.json` +
  User-Agent routing — §2 "primary mechanism", Phases 3's routing manifest and 5). ADR-20's
  variant-keyed catalog tree (`release/<varver>/<arch>`, `nightly/<varver>/<arch>`) is
  **retained unchanged**. **No shipped (`src/`) code changes** to the running package's DNSBL/IP
  logic — distribution-only, like ADR-17/18/20; the meta-package is a new shipped `.pkg` but
  carries only shell scripts + a conf template.
- **Target runtime:** GitHub Actions `ubuntu-latest` — the same pure-Python pipeline as
  ADR-17/18/20 (`build-pkg-portable.py`, `build-repo-portable.py`). Client side: pfSense
  CE 2.8+ / Plus, POSIX `sh` only (the meta-package's `pkg-post-install` runs under libpkg with
  the base system only — no PHP, no add-on deps).
- **Test suite:** `tests/test_add_repo_conf.py`, `tests/test_build_repo_portable.py`,
  `tests/test_detect_variant.sh` (new, shellspec), `tests/smoke/test_repo_install.py`
  (the `repo` marker). Deleted: `scripts/worker/test/router.test.js`.

## 1. Context

### 1.1 Today

ADR-17 stood up a self-hosted FreeBSD `pkg` repository on GitHub Pages
(`pfblockerng.github.io/pkg`). ADR-20 made it **variant-aware** — the catalog is bucketed
`release/<varver>/<arch>/` and `nightly/<varver>/<arch>/`, where `<varver>` is
`ce-2.8` / `plus-26.03` (`catalog_name_from_version()`, `build-repo-portable.py:389`) and
`<arch>` is the bare arch (`amd64`/`aarch64`). To pick the right subtree per box, ADR-20
added a **Cloudflare Worker** that read the pkg client's `User-Agent`, matched it against a
generated `routing.json`, and 302-redirected to the box's catalog. `add-repo.sh` wrote one
conf pointing at the Worker URL (`https://pkg.pfblockerng.workers.dev/<channel>/${ABI}`),
"written once" — the Worker did all per-box routing.

### 1.2 The problem (ADR-20 amendment 2026-06-21, issue #442)

The UA-routing premise was verified with a **fabricated** product User-Agent
(`curl -A "Netgate pfSense Plus/26.03"`). A **real** pkg client sends
`User-Agent: pkg/2.5.1` — a generic string carrying **no edition and no version**
(confirmed by `pkg -d update`; Netgate avoids this by putting the version in the URL *path*,
not the UA). So every real request matches no `routing.json` pattern → the Worker returns
`404 Unsupported pfSense version` → pkg reports `Failed writing received data to disk`. This
is exactly ADR-20's **Phase-1 kill-gate REJECT** condition ("UA absent or replaced"); the
gate's GO was recorded against the stub, so its own fallback never fired. The self-hosted
Worker install path is non-functional. (The Netgate ports channel is unaffected.)

A second, smaller symptom surfaced in the same investigation: the nightly base version was
frozen (the `-nightly` port `PORTVERSION` was never bumped in lockstep with `-devel`). That
is fixed separately (PR #445) and is **not** part of this ADR; it is noted only because it was
found in the same #442 thread.

### 1.3 Load-bearing facts

- **The portable builder already emits post-install/deinstall scripts.** `build-pkg-portable.py`
  maps port `SUB_FILES` (`pkg-post-install` → manifest `post-install`, `pkg-post-deinstall` →
  `post-deinstall`, plus pre-/combined variants — `_SCRIPT_KEYS`, `:939`), substitutes the
  `.in` `SUB_LIST` tokens (`build_scripts()`, `:949`), and writes `m["scripts"]` into the
  manifest (`make_manifest()`, `:1031`). **No builder change is needed** for the meta-package
  to ship a `pkg-post-install` — the premise that gated this ADR HOLDS.
- **On-box edition/version detection is known and live-verified.** ADR-20 Phase 1 confirmed
  `globals.plus.inc` **exists on Plus, is absent on CE** (live probe 2026-06-09); `/etc/version`
  carries the version string. The box's arch/FreeBSD major is available from `pkg config abi`
  (`FreeBSD:<major>:<arch>`). These three are sufficient to compute `<varver>/<arch>` on-box in
  POSIX `sh` — the same mapping `catalog_name_from_version()` does in Python.
- **The catalog tree leaf is a bare `<arch>`, not `${ABI}`.** Because there is no Worker to
  rewrite `${ABI}` → `<varver>/<arch>`, the direct conf must carry the **fully resolved**
  path `…/<channel>/<varver>/<arch>` with no `${ABI}` variable. The ADR-17 "`${ABI}`
  auto-follows an OS upgrade" property is replaced by the meta-package re-running detection
  (§2, §3 "self-heal").
- **`routing.json` has exactly one consumer — the Worker.** Nothing else (landing page,
  generators, client) reads it; it deletes cleanly with the Worker.
- **Conf byte-identity is enforced.** `add-repo.sh --print-conf`, `build-repo.sh --print-conf`,
  and `build-repo-portable.py --print-conf` must emit **byte-identical** confs
  (`tests/test_add_repo_conf.py`); changing the URL means changing all three together.
- **`pkg install pfblockerng-repo` chicken-and-egg.** A box can only install the meta-package
  after a repo conf already exists. So `add-repo.sh` stays the **first-touch bootstrap**: it
  writes the initial resolved conf *and* installs the meta-package, which thereafter maintains
  the conf. (Install-UX decision confirmed with the maintainer 2026-06-21.)

## 2. Decision

Retire the UA-routed Worker entirely and replace it with **on-box local detection**, fronted
by a small **`pfblockerng-repo` meta-package** whose `pkg-post-install` re-runs detection and
(re)writes the direct GitHub Pages conf — self-healing across upgrades — and whose
`pkg-post-deinstall` removes it.

| Area | Decision |
| --- | --- |
| **Detection** | One shared POSIX-`sh` helper resolves **edition** (`globals.plus.inc` present ⇒ Plus, else CE), **version** (`/etc/version`), and **arch** (`pkg config abi`) into `<varver>/<arch>` (`ce-2.8/amd64`, `plus-26.03/aarch64`). Mirrors `catalog_name_from_version()` exactly; pinned by tests against the same cases. |
| **Conf shape** | Direct, fully resolved: `url: "https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>"` — **no `${ABI}`**. Everything else unchanged from ADR-17/20: `priority: 100`, `mirror_type: none`, `signature_type: none`, `enabled: yes`; repo name `pfblockerng` (release) / `pfblockerng-nightly` (nightly). |
| **Meta-package** | New `pfblockerng-repo` port on `pfblockerng/use-github`: `pkg-post-install.in` (detect → write conf → `pkg update`) and `pkg-post-deinstall.in` (remove conf). Ships the detection helper + conf template. Arch-/version-independent content; built per catalog so each carries a matching-ABI copy. |
| **First-touch** | `add-repo.sh` stays the headline bootstrap: writes the initial resolved conf via the helper, then `pkg install pfblockerng-repo`. Future `pkg upgrade` / OS-upgrade package reinstall re-fires the post-install → re-detects → rewrites the conf (self-heal). |
| **Worker** | `scripts/worker/`, `deploy-worker.yml`, the `worker-tests` CI job, the `deploy-worker` release job, `routing.json` generation (`build-repo-portable.py` + `publish.yml`), and the `SMOKE_WORKER_LIVE` Case-4 leg are **deleted**. |
| **Catalog tree** | **Unchanged** (`release/<varver>/<arch>`, `nightly/<varver>/<arch>`). Only the *routing layer* in front of it changes (Worker → on-box detection). |
| **Trust** | Unchanged from ADR-17: first-touch `add-repo.sh` is fetched over HTTPS to GitHub; the meta-package installs from our NONE-signed, TLS-anchored repo exactly like the pfBlockerNG package itself. No new trust surface. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Conf byte-identity** across all three generators (`--print-conf`) after the URL change —
   `tests/test_add_repo_conf.py`.
2. **Conf field set** unchanged except the `url:` value: `priority: 100`, `signature_type: none`,
   `mirror_type: none`, `enabled: yes`, per-channel repo name.
3. **varver/arch correctness**: on-box detection yields the **same** `<varver>/<arch>` that
   `catalog_name_from_version()` + the matrix arch produce for that box — pinned by shared
   table-driven cases (`2.8.1+CE→ce-2.8`, `26.03.1+Plus→plus-26.03`, …).
4. **Idempotence**: re-running the bootstrap / re-firing the post-install yields the identical
   conf; channels don't clobber (`pfblockerng.conf` vs `pfblockerng-nightly.conf`).
5. **EOL/route-only**: a box whose `<varver>` is a retained-but-EOL catalog (ADR-27) still gets
   a working conf pointing at its frozen subtree — no special routing needed.
6. **Catalog acceptance**: `pkg update` against the resolved direct URL loads the catalog and
   `pkg install/upgrade pfBlockerNG` resolves our build (priority 100 dominates) — the existing
   `repo`-marker smoke still passes.

### Explicitly kept / out of scope

- The variant-keyed catalog tree, `catalog_name_from_version()`, per-ABI bucketing — **kept**.
- The PR #445 nightly-version lockstep fix — **separate**, already in flight.
- A GUI "Updates/Channel" panel (ADR-19) — still deferred (would touch `src/`).
- `config.xml` / package runtime behaviour — untouched.

## 3. Consequences

**Positive**

- The self-hosted install path **works on real boxes** (the #442 blocker is removed) — no
  dependency on a UA the client doesn't send.
- **No edge infrastructure**: no Cloudflare Worker to deploy, secrets to hold, or `routing.json`
  to keep live. Fewer moving parts, one less always-on service, smaller CI surface
  (`worker-tests`, `deploy-worker` gone).
- **Self-healing**: the conf follows the box across version/edition upgrades via the
  meta-package's post-install, replacing the `${ABI}` auto-follow that the direct path loses.
- Detection is **deterministic and offline** — a local file/`pkg` read, not a network round-trip
  through Fastly + Cloudflare.

**Negative / risks**

- **Self-heal depends on the post-install re-firing.** It fires on meta-package
  install/upgrade and on pfSense's package reinstall during an OS upgrade — but a box that
  changes edition/version **without** reinstalling the meta-package keeps a stale conf until its
  next meta-package upgrade. Mitigated because the stale `<varver>` subtree is **retained**
  (ADR-27 EOL routing), so the box still resolves *a* working catalog, just not the newest;
  each release bumps the meta-package, so the next `pkg upgrade` corrects it.
- **New shipped `.pkg`** (`pfblockerng-repo`) to build and inject per catalog — small, but new
  port + plist + publish wiring to maintain.
- **Detection correctness is now on-box logic** we own (previously the Worker's job). A wrong
  `<varver>` writes a 404-ing conf. Guarded by the shared table tests + the upgrade/EOL smoke.

## 4. Requirements (acceptance)

- `add-repo.sh` (no Worker) writes a direct resolved conf and installs `pfblockerng-repo`; a
  real `pkg update` loads the catalog and `pkg install pfBlockerNG` pulls our build.
- The meta-package's `pkg-post-install` rewrites the conf to the box's correct `<varver>/<arch>`
  on (re)install; `pkg-post-deinstall` removes it.
- All three conf generators emit byte-identical confs; `tests/test_add_repo_conf.py` green
  against the new URL.
- The Worker, `routing.json`, and their tests/CI are gone; `test_build_repo_portable.py` and the
  smoke suite green without them.
- The `repo`-marker smoke proves: fresh install via the meta-package, cross-repo precedence,
  `pkg upgrade`, and an EOL/route-only box all resolve the correct catalog.

## 5. Constraints (from CLAUDE.md)

- `pkg-post-install` / detection helper: **POSIX `sh` only**, base-system utilities; runs under
  libpkg with no PHP and no add-on deps. Quote all expansions; `LC_ALL=C` on any machine-data
  sort/compare.
- All distribution code stays **dev-only** (release archives are `src/` only) — but the
  meta-package's scripts ship inside the `pfblockerng-repo` `.pkg`.
- Conf generators must remain byte-identical (drift is a silent break).
- ADR-text + phase prompts land **directly on `devel`** (no PR). Every code/CI/test phase uses
  the **full worktree + rebase-only PR** flow.

## 6. Action plan

The early phases are the behaviour-preserving prep: extract + pin the detection logic and the
conf shape *before* repointing the URL or deleting the Worker.

### Phase 1 — Shared on-box variant-detection helper (+ tests)

- **Prompt:** `01_Detection_Helper.txt`
- Add a POSIX-`sh` helper that resolves edition (`globals.plus.inc`), version (`/etc/version`),
  arch (`pkg config abi`) → `<varver>/<arch>`, mirroring `catalog_name_from_version()`.
- Behaviour-preserving (new code, no caller yet). Pin with `tests/test_detect_variant.sh`
  (shellspec) using the **same** case table as `test_catalog_name_from_version()` — CE, Plus,
  patch-stripping, arch leaf — plus a fixture for the CE (absent `globals.plus.inc`) vs Plus
  branch. **Tests:** new shellspec; assert both edition branches and the version→varver map.

### Phase 2 — `pfblockerng-repo` meta-package port

- **Prompt:** `02_Meta_Package_Port.txt`
- Create the port on `pfblockerng/use-github` (Makefile + pkg-plist + `pkg-post-install.in` +
  `pkg-post-deinstall.in`), shipping the Phase-1 helper + conf template. post-install: detect →
  write `/usr/local/etc/pkg/repos/pfblockerng.conf` (resolved direct URL) → `pkg update`;
  post-deinstall: remove it. **Tests:** off-box, build the `.pkg` with `build-pkg-portable.py`
  and assert the manifest `scripts.post-install`/`post-deinstall` carry the substituted bodies;
  assert the written conf matches the byte-identical template for sample boxes.

### Phase 3 — Publish: build + inject the meta-package per catalog

- **Prompt:** `03_Publish_Inject.txt`
- Wire `pfBlockerNG/pkg`'s `publish.yml` to build `pfblockerng-repo` for each `<varver>/<arch>`
  (cheap; matching ABI) and fold it into every catalog so `pkg install pfblockerng-repo`
  resolves on every box. **Tests:** `test_build_repo_portable.py` — the meta-package appears in
  each generated `packagesite`/`data.pkg`.

### Phase 4 — Repoint `add-repo.sh` + install the meta-package (boundary change)

- **Prompt:** `04_AddRepo_Repoint.txt`
- `DEFAULT_BASE_URL` → `https://pfblockerng.github.io/pkg`; build the **resolved** `url:` via the
  Phase-1 helper (no `${ABI}`); after writing the initial conf, `pkg install pfblockerng-repo`.
  Update all three `--print-conf` generators byte-identically. **Tests:** rewrite
  `tests/test_add_repo_conf.py` for the resolved URL + byte-identity; idempotence; channel
  non-clobber.

### Phase 5 — Retire the Worker + `routing.json`

- **Prompt:** `05_Retire_Worker.txt`
- Delete `scripts/worker/`, `deploy-worker.yml`, the `worker-tests` job (`test.yml`), the
  `deploy-worker` job (`release.yml`), `routing.json` generation in `build-repo-portable.py` +
  `publish.yml`, and the `SMOKE_WORKER_LIVE`/Case-4 leg. Remove the now-dead routing tests
  (`router.test.js`, the `_ua_pattern`/`_dedup_routes`/`generate_routing_json` tests). **Tests:**
  suite green with the routing tests removed; no dangling references (grep gate).

### Phase 6 — Smoke + docs + DoD

- **Prompt:** `06_Smoke_Docs_DoD.txt`
- `repo`-marker smoke: fresh install through the meta-package → resolved conf → catalog accepted
  → `pkg install pfBlockerNG` pulls our build; **upgrade self-heal** (reinstall meta-package →
  re-detect → conf rewritten — assert before/after); **EOL/route-only** box resolves its retained
  subtree. Update `CLAUDE.md` ("Self-hosted pkg repository" / "Cloudflare routing Worker" →
  superseded), `README.md`, and ADR-20's status (add a "superseded by ADR-39" amendment).

## 7. Definition of done

- All §4 requirements met; the `repo`-marker smoke (fresh install, cross-repo precedence,
  `pkg upgrade`, **upgrade self-heal**, EOL routing) is green on the live-VM fan-out (CE + Plus).
- Worker/`routing.json`/their CI + tests removed; the suite is green without them; no dangling
  references remain.
- All three conf generators byte-identical against the new resolved URL.
- Docs updated; ADR-20 carries a "superseded by ADR-39 (routing layer)" amendment.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- A real OS upgrade that changes `<varver>` (e.g. CE 2.8 → a later major, or CE → Plus) on a box
  with `pfblockerng-repo` installed, then `pkg upgrade` — confirm the conf self-heals to the new
  `<varver>/<arch>` (CI reinstalls the package to simulate; a true cross-major OS upgrade is
  out-of-CI).
- The live `pfblockerng.github.io/pkg` URL resolves the variant catalog from a real box (the
  gated `SMOKE_REPO_LIVE_URL` leg, post-merge).

**REJECT criteria (what would kill or re-scope this ADR):**

- On-box detection cannot reliably distinguish CE from Plus, or cannot resolve `/etc/version` →
  `<varver>`, on a supported box (would force a different detection source — but ADR-20 Phase 1
  already verified `globals.plus.inc`, so this is low risk).
- `pkg` refuses an arch-/version-independent meta-package such that it cannot be made to resolve
  on every box even when built per-catalog (would force a per-box build or a different
  bootstrap). Surfaced cheaply in Phase 2/3 before the Worker is deleted in Phase 5.
