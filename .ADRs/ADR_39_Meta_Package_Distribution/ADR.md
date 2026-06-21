# ADR-39: On-box pkg-repo conf regeneration (boot hook) + Cloudflare Worker retirement

- **Status:** **Proposed** (2026-06-21)
- **Date:** 2026-06-21
- **Branch:** `adr/39-meta-package-distribution` (off **`devel`**). The branch/dir keep the
  original "meta-package" slug for continuity; the design **pivoted away from a meta-package**
  to a self-guarding boot hook installed by `add-repo.sh` (see §1.4). / **Component(s):**
  dev-only distribution/CI — `scripts/add-repo.sh` (repoint to direct Pages + install the
  generator hook), a new self-guarding `rc.d` **conf-generator** script with detection **folded
  in** (shipped *by* `add-repo.sh`, not a package — no separate `/lib` helper),
  `scripts/build-repo-portable.py` (delete `routing.json` generation); `scripts/worker/`,
  `.github/workflows/deploy-worker.yml`, and the `worker-tests` CI job (**deleted**).
  **Supersedes:** ADR-20's dynamic-routing layer (the Cloudflare Worker + `routing.json` +
  User-Agent routing). ADR-20's variant-keyed catalog tree (`release/<varver>/<arch>`,
  `nightly/<varver>/<arch>`) is **retained unchanged**. **No shipped (`src/`) code changes** —
  distribution-only, like ADR-17/18/20; nothing new is added to a release archive.
- **Target runtime:** GitHub Actions `ubuntu-latest` — the same pure-Python pipeline as
  ADR-17/18/20 (`build-pkg-portable.py`, `build-repo-portable.py`). Client side: pfSense CE 2.8+ /
  Plus, **POSIX `sh` only** — `add-repo.sh` and the `rc.d` hook (with folded detection) run with the
  base system only (no PHP, no add-on deps).
- **Test suite:** `tests/test_add_repo_conf.py` (four-way conf byte-identity, incl. the hook),
  `tests/test_build_repo_portable.py`, `tests/shell/generate_hook_spec.sh` (shellspec — the
  regenerator), `tests/smoke/test_repo_install.py` (the `repo` marker). **Deleted:**
  `scripts/worker/test/router.test.js`, `tests/shell/detect_variant_spec.sh` (detection folded
  into the hook), `tests/test_pfblockerng_repo_pkg.py` (the abandoned meta-package build test).

## 1. Context

### 1.1 Today

ADR-17 stood up a self-hosted FreeBSD `pkg` repository on GitHub Pages
(`pfblockerng.github.io/pkg`). ADR-20 made it **variant-aware** — the catalog is bucketed
`release/<varver>/<arch>/` and `nightly/<varver>/<arch>/`, where `<varver>` is `ce-2.8` /
`plus-26.03` (`catalog_name_from_version()`, `build-repo-portable.py`) and `<arch>` is the bare
arch (`amd64`/`aarch64`). To pick the right subtree per box, ADR-20 added a **Cloudflare Worker**
that read the pkg client's `User-Agent`, matched it against a generated `routing.json`, and
302-redirected to the box's catalog. `add-repo.sh` wrote one conf pointing at the Worker.

### 1.2 The problem — UA routing is unreliable (the UA is context-dependent)

The UA-routing premise rested on a real but **partial** observation. pfSense's PHP layer
(`pkg-utils.inc` `pkg_env()`) builds a product User-Agent —
`product_label/product_version[:uniqueid]` (→ `pfSense/2.8.1-RELEASE:<uid>`,
`Netgate pfSense Plus/26.03.1-RELEASE:<uid>`) — and injects it **into the process environment of
`proc_open()`** for PHP-wrapped pkg calls (`pkg_call`/`pkg_exec`, behind `pkg_install`/`pkg_update`
— the **GUI Package Manager**). ADR-20 Phase 1 probed *that* value and recorded
`USER_AGENT_VISIBLE = GO`. It is real — for that path; the error was generalising it to **all**
pkg fetches.

The product UA is **never written to `pkg.conf`** (verified on CE 2.8.1 + Plus 26.03.1), so it
applies **only** to PHP/GUI-initiated operations. A **raw CLI `pkg update`** sends the bare libpkg
default — captured live on Plus 26.03.1 as `pkg/1.21.3` (every request, 18/18 identical) — and so
does `pkg-static`, the binary the `pfSense-upgrade` path runs (a shell script making direct pkg
calls — bare UA **even when launched from the GUI's System-Update page**). So the Worker's
`ua.includes("pfSense/2.8")` resolves a **GUI-initiated** install but returns
`404 Unsupported pfSense version` for:

- raw CLI `pkg install`/`upgrade` (advanced users, scripts),
- our own `repo`-marker smoke and any scripted install,
- the **`pkg-static` upgrade path** — exactly where a resolvable conf matters most.

A repo that resolves only from the GUI Package Manager is unreliable, and the bare-UA paths
include the upgrade path that matters most. (Netgate sidesteps the whole problem by baking the
version into the URL *path* and rewriting it server-side via the proprietary `pfSense-repoc`;
see §1.3.) On-box detection (§2) resolves the catalog for **every** path. The Netgate ports
channel is unaffected.

### 1.3 Load-bearing facts (verified, not assumed)

- **`${ABI}` is NOT 1:1 with a pfSense version.** A pfSense `${ABI}` (`FreeBSD:<major>:<arch>`)
  carries only the FreeBSD major + arch; two pfSense versions/editions can share one major (one
  `${ABI}`) yet ship different PHP/Python and therefore different pfBlockerNG builds. So `${ABI}`
  **cannot** select a catalog — varver keying is mandatory. The current matrix being incidentally
  1:1 is **not** a guarantee. Full rationale: `docs/misc/architecture-notes.md` → "Self-hosted pkg
  distribution — ABI is NOT 1:1". (This is why ADR-17's `${ABI}`-auto-follow trick is unavailable
  to us and ADR-20's varver tree must stay.)
- **No third-party pre-solve hook exists.** Verified against the on-box `pfSense-repo-setup` (CE
  2.8.1 + Plus 26.03.1) and the `pfSense-upgrade` driver: `repo-setup` enumerates only
  `${PLUS_CERT_BASE}/pfSense-repo-*.name` (the Netgate staging dir `/usr/local/etc/pfSense/pkg/repos/`)
  to **symlink one** chosen conf onto `pfSense.conf` — it never reads `/usr/local/etc/pkg/repos/*`
  generically and never rewrites conf *content* (that is the proprietary `repoc`'s job). A
  `+PRE_INSTALL` runs *inside* the locked libpkg transaction (nested `pkg` is impossible), and the
  upgrade driver runs only hardcoded pfSense scripts before the solve. **Conclusion:** a
  third-party version-pinned conf cannot be corrected *before* the upgrade's package-solve; the
  correction is necessarily **after** the transaction.
- **Every varver-changing upgrade reboots.** pfSense cannot swap the running ABI / PHP / Python
  interpreters live, so any upgrade that changes our build inputs rides the staged boot-upgrade
  (kernel `next_stage` annotation → reboot). Conversely, a plain `pkg upgrade` that does *not*
  bump the pfSense version cannot change `<varver>`, so it leaves the conf valid. **Therefore a
  boot-time healer is guaranteed a turn after every upgrade that could invalidate the conf.**
- **User-created `/usr/local/etc/rc.d/*.sh` survive reboots and upgrades** (`/usr/local` rides the
  boot-environment clone; maintainer-confirmed from long operational use). So a non-package hook
  placed there persists across the very upgrade it heals.
- **On-box edition/version detection is known and KISS.** Edition = **"`/etc/product_label`
  contains `Plus`"** (→ `plus`, else `ce`; an absent file degrades safely to `ce`); `/etc/version`
  carries the version; `pkg config abi` gives `FreeBSD:<major>:<arch>`. These three resolve
  `<varver>/<arch>` in a few lines of POSIX `sh`, mirroring `catalog_name_from_version()`. They are
  **folded into the `rc.d` hook** — one self-contained file, no separate `/lib` helper.
- **Conf byte-identity is enforced across FOUR producers.** `add-repo.sh --print-conf`,
  `build-repo.sh --print-conf`, `build-repo-portable.py --print-conf`, **and the `rc.d` hook**
  must emit **byte-identical** confs (`tests/test_add_repo_conf.py`); changing the URL or the
  marker means changing all four together.
- **`routing.json` has exactly one consumer — the Worker.** It deletes cleanly with the Worker.

### 1.4 Why a self-guarding boot hook, not a meta-package

The earlier draft fronted the conf-correction with a `pfblockerng-repo` **meta-package** whose
`pkg-post-install` re-ran detection. That is more machinery than the problem needs, and the
maintainer's framing is simpler and strictly more robust:

- **Conf correction must be its own persistent survivor.** On a version cross the stale-varver conf
  still points at a *retained* (old) catalog, so the next pkg op may pull the **old-build**
  pfBlockerNG (wrong PHP dep) or, for devel/nightly (no Netgate fallback), drop it. pfBlockerNG
  therefore **cannot fix its own repo conf** when it is the thing broken/removed — the corrector has
  to be independent of it.
- **A non-package `rc.d` hook is that survivor, with no lifecycle cost.** It has no deps to break,
  survives the BE clone (§1.3), and runs on the guaranteed post-upgrade boot. Cleanup is a
  non-problem: the hook is **self-guarding** — it regenerates only a conf that already exists — so an
  orphaned hook left behind after the user removes the repo is inert. No package, no `pkg-plist`, no
  install/deinstall wiring, nothing to uninstall.
- **A regenerator, not a healer.** The hook does **not** touch packages — no `pkg update`, no
  reconcile, no network. It only **rewrites the conf** so the box's *next* pkg operation (manual or
  scheduled) resolves the correct catalog. Re-deriving the whole conf from detection is strictly
  simpler than diffing/patching one in place, and — ordered before any networked pkg fetch (§2) —
  removes the "correct the conf before pkg runs" timing problem entirely.

## 2. Decision

Retire the (non-functional) UA-routed Worker entirely and replace it with **on-box local
detection** plus a self-guarding `rc.d` **conf-regenerator hook** — detection folded into the one
hook file, installed by `add-repo.sh` as the one-touch bootstrap.

| Area | Decision |
| --- | --- |
| **Detection** | **Folded into the hook** (KISS, no `/lib` helper): **edition** = "`/etc/product_label` contains `Plus`" (⇒ `plus`, else `ce`; absent file ⇒ `ce`), **version** = major.minor of `/etc/version`, **arch** = leaf of `pkg config abi`. Resolves `<varver>/<arch>` mirroring `catalog_name_from_version()`; pinned by `tests/shell/generate_hook_spec.sh`. |
| **Conf shape** | Direct, fully resolved: `url: "https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>"` — **no `${ABI}`** (no Worker to expand it). A **marker first line** (`# Generated at boot by pfblockerng_repo_generate (ADR-39) …`) identifies a hook-generated conf. Everything else unchanged from ADR-17/20: `priority: 100`, `mirror_type: none`, `signature_type: none`, `enabled: yes`; repo name `pfblockerng` (release) / `pfblockerng-nightly` (nightly). |
| **First-touch** | `add-repo.sh` (no Worker) is a lean bootstrap: install the hook, stage the conf, **run the hook** (`onestart`) to resolve the conf now, verify the marker line, then `pkg update` + verify a package is visible. add-repo.sh does **no detection itself** — the hook is the single source of the resolved conf. |
| **Generator hook** | A POSIX-`sh` `rc.d` script, **fail-proof (always `exit 0`)**, ordered `REQUIRE: FILESYSTEMS` / `BEFORE: NETWORKING` so it runs before any networked `pkg` fetch. It is a pure **regenerator**: for each of our conf files that **exists**, detect `<varver>/<arch>` and **unconditionally overwrite** the conf with the canonical body (channel keyed by filename). **No `pkg` call, no network, no snapshot, no parse-and-compare, no reconcile.** Channel-correct (`/nightly/` for the nightly conf). If detection fails it leaves the conf **unchanged** (warns) rather than writing a malformed URL. |
| **Worker** | `scripts/worker/`, `deploy-worker.yml`, the `worker-tests` CI job, the `deploy-worker` release job, `routing.json` generation (`build-repo-portable.py` + `publish.yml`), and the `SMOKE_WORKER_LIVE` Case-4 leg are **deleted**. |
| **Meta-package** | **Not built.** The abandoned Phase-2 artifacts (`tests/test_pfblockerng_repo_pkg.py` and the `build-pkg-portable.py` meta-package additions) are reverted. |
| **Matrix-collision guard** | A fail-closed CI/unit check rejects a version matrix that puts two pfSense versions on the **same `(freebsd_major, arch)` with different `(php, py)`** — the case where varver keying would be ambiguous — so the structural assumption is enforced mechanically, not trusted. |
| **Catalog tree** | **Unchanged** (`release/<varver>/<arch>`, `nightly/<varver>/<arch>`). Only the *routing layer* changes (Worker → on-box detection + hook). |
| **Trust** | Unchanged from ADR-17: `add-repo.sh` is fetched over HTTPS from GitHub; the conf points at our NONE-signed, TLS-anchored Pages repo exactly like the pfBlockerNG package itself. No new trust surface; no new shipped artifact. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Conf byte-identity** across all four producers (the three `--print-conf` generators **and** the
   hook) after the URL/marker change — `tests/test_add_repo_conf.py`.
2. **Conf field set** unchanged except the `url:` value + the marker line: `priority: 100`,
   `signature_type: none`, `mirror_type: none`, `enabled: yes`, per-channel repo name.
3. **varver/arch correctness**: the hook's folded detection yields the **same** `<varver>/<arch>`
   that `catalog_name_from_version()` + the matrix arch produce for that box — pinned by shared
   table-driven cases (`2.8.1+CE→ce-2.8`, `26.03.1+Plus→plus-26.03`, …) and cross-checked against an
   independent oracle on the live VM.
4. **Hook safety + idempotence**: the hook **never** exits non-zero (cannot wedge boot); orphaned
   (conf absent) it is a no-op; re-running yields the **identical** conf (pure regenerate); channels
   don't clobber (`pfblockerng.conf` vs `pfblockerng-nightly.conf`).
5. **EOL/route-only**: a box whose `<varver>` is a retained-but-EOL catalog (ADR-27) still gets a
   working conf pointing at its frozen subtree — no special routing needed.
6. **Catalog acceptance**: `pkg update` against the resolved direct URL loads the catalog and
   `pkg install/upgrade pfBlockerNG` resolves our build (priority 100 dominates) — the existing
   `repo`-marker smoke still passes.

### Explicitly kept / out of scope

- The variant-keyed catalog tree, `catalog_name_from_version()`, per-ABI bucketing — **kept**.
- The detection logic — **kept**, but **folded into the hook** (the standalone
  `scripts/lib/detect_variant.sh` + its shellspec are deleted; the hook is self-contained).
- A GUI "Updates/Channel" panel (ADR-19) — still deferred (would touch `src/`).
- `config.xml` / package runtime behaviour — untouched.
- Pre-solve correction of the conf inside the upgrade transaction — **proven impossible** for a
  third party (§1.3); the accepted model is **regenerate the conf at the next boot, before any
  networked pkg op**, so the box's next solve sees the correct URL.

## 3. Consequences

**Positive**

- The self-hosted install path **works on real boxes** (the UA blocker is removed) — no dependency
  on a UA the client doesn't send.
- **No edge infrastructure and no new shipped package**: no Cloudflare Worker to deploy/secret, no
  `routing.json` to keep live, no meta-package port/plist/publish wiring. Fewer moving parts, one
  less always-on service, smaller CI surface.
- **Self-correcting with no lifecycle cost**: the conf follows the box across version/edition
  upgrades via a self-guarding hook that needs no uninstall and is benign if orphaned.
- **No boot-time pkg/network at all.** The hook is local-file-only and ordered `BEFORE: NETWORKING`,
  so the conf is correct **before** the box's first networked pkg fetch of the boot — eliminating
  the one-pkg-run lag that originally motivated a separate healer, with **no** `pkg update`,
  reconcile, snapshot, or DNS/ordering dependency to get right.
- **Maximally simple.** A pure regenerator — re-derive the conf from detection and overwrite — has
  no diff/patch logic, no restore-on-failure path, and no pkg state machine to reason about.
- Detection is **deterministic and offline** — a local file/`pkg config` read, not a network
  round-trip.

**Negative / risks**

- **Detection correctness is on-box logic we own.** A wrong `<varver>` writes a 404-ing conf.
  Guarded by the hook shellspec + the smoke (whose end-to-end resolve cross-checks the hook's
  detection against an independent oracle), and the matrix-collision guard fails the build if the
  keying could ever be ambiguous. A detection *failure* (vs. a wrong answer) is fail-safe: the hook
  leaves the existing conf unchanged rather than writing garbage.
- **Hook robustness is safety-critical** — a hook that could exit non-zero or hang could affect
  boot. Mitigated by the hard rule "always `exit 0`", the local-file-only design (no network to
  block on), and a shellspec that asserts the orphan guard, the regenerate path, idempotence, and
  the detection-failure-leaves-conf-unchanged path.
- **A package mis-resolved before the next boot is not auto-fixed.** The hook corrects the *conf*,
  not packages; if a pkg op runs against a stale conf *before* the corrective boot, it could pull
  an old/absent build. In practice every `<varver>`-changing upgrade reboots (§1.3) and the hook
  runs before that boot's networked pkg, so the realistic window is closed; pfBlockerNG data lives
  in `/var/db/pfblockerng` (not pkg-managed) so a transient remove loses nothing.

## 4. Requirements (acceptance)

- `add-repo.sh` (no Worker) installs the generator hook and runs it to write a direct resolved conf;
  a real `pkg update` loads the catalog and `pkg install pfBlockerNG` pulls our build.
- The hook: is a no-op when the conf is absent; regenerates a present conf to the box's correct
  `<varver>/<arch>` (overwriting a stale one); re-running yields the **identical** conf; leaves the
  conf unchanged on a detection failure; makes **no** `pkg`/network call; **never exits non-zero**.
- All four conf producers (three `--print-conf` generators + the hook) emit byte-identical confs;
  `tests/test_add_repo_conf.py` green against the new URL + marker.
- The Worker, `routing.json`, the meta-package artifacts, and their tests/CI are gone;
  `test_build_repo_portable.py` and the smoke suite green without them; no dangling references.
- The matrix-collision guard fails a deliberately-colliding fixture and passes the real matrix.
- The `repo`-marker smoke proves: fresh install, cross-repo precedence, `pkg upgrade`, **conf
  regeneration after a stale-varver conf** (and end-to-end resolve from the corrected conf), and an
  EOL/route-only box all resolve the correct catalog.

## 5. Constraints (from CLAUDE.md)

- `add-repo.sh` / the `rc.d` hook (with folded detection): **POSIX `sh` only**, base-system
  utilities; no PHP, no add-on deps. Quote all expansions; `LC_ALL=C` on any machine-data
  sort/compare.
- All distribution code stays **dev-only** (release archives are `src/` only). The `rc.d` hook is
  installed on the box by `add-repo.sh`, not shipped inside any `.pkg`.
- Conf generators must remain byte-identical (drift is a silent break).
- ADR-text + phase prompts land **directly on the branch** (docs carve-out, no PR). Every
  code/CI/test phase uses the **full worktree + rebase-only PR** flow.

## 6. Action plan

Phase 1 prototyped a standalone detection helper; the final design **folds detection into the
hook** (no `/lib` file). The phases repoint the boundary, add the regenerator hook, then delete the
dead Worker/meta-package surface last.

### Phase 1 — On-box variant detection — **superseded (folded into the hook)**

- **Prompt:** `01_Detection_Helper.txt`
- Originally landed as a standalone `scripts/lib/detect_variant.sh` (+ `detect_variant_spec.sh`).
  The final design **folds that logic into the `rc.d` hook** (one self-contained file) and **deletes
  the standalone helper + its spec**; detection is exercised by the hook shellspec instead.

### Phase 2 — Lean `add-repo.sh` + the `rc.d` conf-regenerator hook (boundary change)

- **Prompt:** `02_AddRepo_And_Hook.txt`
- Repoint `add-repo.sh`: `DEFAULT_BASE_URL` → `https://pfblockerng.github.io/pkg`; make it a lean
  bootstrap (install the hook, stage the conf, run the hook to resolve it, verify the marker, then
  `pkg update` + verify). Add the self-guarding `rc.d` regenerator with **folded detection** (no
  `${ABI}`, no Worker). Update all three `--print-conf` generators to emit the marker line, kept
  byte-identical with the hook. **Tests:** rewrite `tests/test_add_repo_conf.py` for the resolved
  URL + four-way byte-identity, idempotence, channel non-clobber; new `generate_hook_spec.sh` (orphan
  guard exits 0; regenerate release/nightly; unconditional stale-varver rewrite; never any
  `pkg update`/`install`/`upgrade`; detection-failure leaves the conf unchanged; **`exit 0` on every
  path**).

### Phase 3 — Retire the Worker + `routing.json`; revert the meta-package prep; matrix guard

- **Prompt:** `03_Retire_Worker_And_Metapkg.txt`
- Delete `scripts/worker/`, `deploy-worker.yml`, the `worker-tests` job (`test.yml`), the
  `deploy-worker` job (`release.yml`), `routing.json` generation in `build-repo-portable.py` +
  `publish.yml`, and the `SMOKE_WORKER_LIVE`/Case-4 leg. Revert the abandoned meta-package prep
  (`tests/test_pfblockerng_repo_pkg.py`, the `build-pkg-portable.py` meta-package additions) —
  **keep** the detection helper. Add the **matrix-collision guard** (fail-closed unit test over the
  version matrix: no two entries share `(freebsd_major, arch)` with different `(php, py)`).
  **Tests:** suite green with routing + meta-package tests removed; collision guard passes the real
  matrix and fails a colliding fixture; grep gate for dangling `worker`/`routing.json`/`pfblockerng-repo`
  references.

### Phase 4 — Smoke + docs + DoD

- **Prompt:** `04_Smoke_Docs_DoD.txt`
- `repo`-marker smoke: fresh install → resolved conf → catalog accepted → `pkg install pfBlockerNG`
  pulls our build; **conf regeneration** (seed a deliberately-stale `<varver>` conf, fire the hook,
  assert before/after the conf flips to the box's real `<varver>/<arch>` and the corrected conf
  resolves + installs our build end-to-end, with the hook's detection cross-checked against an
  independent oracle); **EOL/route-only** box resolves its retained subtree. Update `CLAUDE.md`
  ("Self-hosted pkg repository" / "Cloudflare routing Worker" → superseded by ADR-39; reconcile with
  the ABI-not-1:1 hard rule), `README.md`, ADR-20's status (add a "superseded by ADR-39 (routing
  layer)" amendment), and `docs/misc/architecture-notes.md` (the distribution note already records
  the invariant — add the regenerator-hook mechanism).

## 7. Definition of done

- All §4 requirements met; the `repo`-marker smoke (fresh install, cross-repo precedence,
  `pkg upgrade`, **conf regeneration + end-to-end resolve**, EOL routing) is green on the live-VM
  fan-out (CE + Plus).
- Worker/`routing.json`/meta-package prep/their CI + tests removed; the suite is green without them;
  no dangling references remain.
- All four conf producers byte-identical against the new resolved URL + marker.
- The matrix-collision guard is wired into CI and green on the real matrix.
- Docs updated; ADR-20 carries a "superseded by ADR-39 (routing layer)" amendment.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- A **real OS upgrade that changes `<varver>`** (a true cross-major upgrade, or CE → Plus) on a box
  with the hook installed, then reboot — confirm the conf regenerates to the new `<varver>/<arch>`
  and the box's next `pkg` op resolves the new catalog. CI simulates the regeneration by firing the
  hook against a stale conf; a true cross-major OS upgrade and the rc.d-survives-the-BE-clone
  property are out-of-CI (the latter is maintainer-confirmed).
- **Edition detection on a real Plus box (smoke-validated):** confirm `/etc/product_label` contains
  `Plus` on Plus and not on CE, so the hook resolves `plus-*` vs `ce-*` correctly. The live CE
  fan-out leg already exercises the `ce-*` path end-to-end (the regenerated conf must resolve a real
  package); the Plus leg exercises `plus-*`.
- The live `pfblockerng.github.io/pkg` URL resolves the variant catalog from a real box (the gated
  `SMOKE_REPO_LIVE_URL` leg, post-merge).

**REJECT criteria (what would kill or re-scope this ADR):**

- On-box detection cannot reliably distinguish CE from Plus, or cannot resolve `/etc/version` →
  `<varver>`, on a supported box (the `/etc/product_label` "Plus" check degrades safely to CE on an
  absent file, so low risk; the live fan-out proves it both ways).
- The non-package `rc.d` hook is found NOT to survive a real cross-major BE-clone upgrade (would
  force falling back to the dep-free meta-package as the hook's vehicle — the only reason to revive
  it). Surfaced by the maintainer smoke before relying on it in the field.

### Post-merge follow-ups (separate repos / ops — not blocking acceptance)

These items are required for the full ecosystem to reflect the no-Worker design, but they are
cross-repo or operational and cannot land in a single PR against this repo. They should be
completed shortly after this branch merges to `devel`.

**(a) `pfBlockerNG/pkg` repo — reconcile `publish.yml` and `gen_landing.py`.**
`publish.yml` in `pfBlockerNG/pkg` was written for the Worker era: it may reference
`routing.json` generation, routing-specific comments, or build steps that no longer apply.
`gen_landing.py` (which generates the Pages landing page) may point the install-card's
bootstrap URL at `pkg.pfblockerng.workers.dev` (the now-retired Worker). These must be
updated to reflect the direct-URL architecture:

- Remove any `routing.json` generation steps or comments from `publish.yml`.
- Update the landing page's install card to use `add-repo.sh` with the default
  `https://pfblockerng.github.io/pkg` base (no Worker URL).
- `publish.yml` consumes this repo's `scripts/build-pkg-portable.py` and
  `scripts/build-repo-portable.py` — both have already had the Worker/`routing.json`
  generation removed in this ADR's Phase 3; `publish.yml` just needs the references
  cleaned up to match.

This is a **separate PR against `pfBlockerNG/pkg`** that should be opened after this
branch lands on `devel` (the scripts it consumes are stable at that point).

**(b) Retire the live Cloudflare Worker deployment.**
Once this branch merges and `pfBlockerNG/pkg`'s `publish.yml` no longer deploys the Worker:

- Delete the `pfblockerng-router` (or equivalent) Cloudflare Worker in the Cloudflare
  dashboard (or via `wrangler delete`).
- Remove the `*.workers.dev` route / custom domain binding if configured.
- Revoke / archive the `CF_API_TOKEN` / `CF_ACCOUNT_ID` GitHub Actions secrets that
  authorized `wrangler deploy` (those secrets are now inert; removing them reduces the
  secret surface).

This is an **operational step** (no code PR needed) that should happen after confirming
the direct-URL path is live and serving on `pfblockerng.github.io/pkg`.
