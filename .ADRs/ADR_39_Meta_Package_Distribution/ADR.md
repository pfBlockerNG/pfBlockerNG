# ADR-39: On-box pkg-repo self-heal (boot hook) + Cloudflare Worker retirement

- **Status:** **Proposed** (2026-06-21)
- **Date:** 2026-06-21
- **Branch:** `adr/39-meta-package-distribution` (off **`devel`**). The branch/dir keep the
  original "meta-package" slug for continuity; the design **pivoted away from a meta-package**
  to a self-guarding boot hook installed by `add-repo.sh` (see §1.4). / **Component(s):**
  dev-only distribution/CI — `scripts/add-repo.sh` (repoint to direct Pages + install the
  self-heal hook), the shared on-box detection helper (`scripts/lib/detect_variant.sh`, **kept**
  from Phase 1), a new self-guarding `rc.d` self-heal script (shipped *by* `add-repo.sh`, not a
  package), `scripts/build-repo-portable.py` (delete `routing.json` generation); `scripts/worker/`,
  `.github/workflows/deploy-worker.yml`, and the `worker-tests` CI job (**deleted**).
  **Supersedes:** ADR-20's dynamic-routing layer (the Cloudflare Worker + `routing.json` +
  User-Agent routing). ADR-20's variant-keyed catalog tree (`release/<varver>/<arch>`,
  `nightly/<varver>/<arch>`) is **retained unchanged**. **No shipped (`src/`) code changes** —
  distribution-only, like ADR-17/18/20; nothing new is added to a release archive.
- **Target runtime:** GitHub Actions `ubuntu-latest` — the same pure-Python pipeline as
  ADR-17/18/20 (`build-pkg-portable.py`, `build-repo-portable.py`). Client side: pfSense CE 2.8+ /
  Plus, **POSIX `sh` only** — `add-repo.sh`, the detection helper, and the `rc.d` hook run with the
  base system only (no PHP, no add-on deps).
- **Test suite:** `tests/test_add_repo_conf.py`, `tests/test_build_repo_portable.py`,
  `tests/shell/detect_variant_spec.sh` (shellspec, Phase 1), a new `rc.d`-hook shellspec,
  `tests/smoke/test_repo_install.py` (the `repo` marker). **Deleted:** `scripts/worker/test/router.test.js`,
  `tests/test_pfblockerng_repo_pkg.py` (the abandoned meta-package build test).

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
- the **`pkg-static` upgrade path** — exactly where the self-heal/reconcile has to work.

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
- **On-box edition/version detection is known and live-verified.** `globals.plus.inc` **exists on
  Plus, absent on CE**; `/etc/version` carries the version; `pkg config abi` gives
  `FreeBSD:<major>:<arch>`. These three resolve `<varver>/<arch>` in POSIX `sh` — already
  implemented and tested as `scripts/lib/detect_variant.sh` (Phase 1), mirroring
  `catalog_name_from_version()`.
- **Conf byte-identity is enforced.** `add-repo.sh --print-conf`, `build-repo.sh --print-conf`,
  and `build-repo-portable.py --print-conf` must emit **byte-identical** confs
  (`tests/test_add_repo_conf.py`); changing the URL means changing all three together.
- **`routing.json` has exactly one consumer — the Worker.** It deletes cleanly with the Worker.

### 1.4 Why a self-guarding boot hook, not a meta-package

The earlier draft fronted the self-heal with a `pfblockerng-repo` **meta-package** whose
`pkg-post-install` re-ran detection. That is more machinery than the problem needs, and the
maintainer's framing is simpler and strictly more robust:

- **Self-heal must be its own persistent survivor.** On a version cross the stale-varver conf still
  points at a *retained* (old) catalog, so pkg may pull the **old-build** pfBlockerNG (wrong PHP
  dep) or, for devel/nightly (no Netgate fallback), drop it. pfBlockerNG therefore **cannot heal
  itself** when it is the thing broken/removed — the healer has to be independent of it.
- **A non-package `rc.d` hook is that survivor, with no lifecycle cost.** It has no deps to break,
  survives the BE clone (§1.3), and runs on the guaranteed post-upgrade boot. Cleanup is a
  non-problem: the hook is **self-guarding** — its first act is to exit `0` if our repo conf is
  absent — so an orphaned hook left behind after the user removes the repo is inert. No package, no
  `pkg-plist`, no install/deinstall wiring, nothing to uninstall.

## 2. Decision

Retire the (non-functional) UA-routed Worker entirely and replace it with **on-box local
detection** plus a **self-guarding `rc.d` self-heal hook**, both driven by the shared POSIX-`sh`
detection helper and installed by `add-repo.sh` as the one-touch bootstrap.

| Area | Decision |
| --- | --- |
| **Detection** | The shared helper `scripts/lib/detect_variant.sh` (Phase 1, kept) resolves **edition** (`globals.plus.inc` ⇒ Plus, else CE), **version** (`/etc/version`), **arch** (`pkg config abi`) into `<varver>/<arch>`. Mirrors `catalog_name_from_version()` exactly; pinned by `tests/shell/detect_variant_spec.sh`. |
| **Conf shape** | Direct, fully resolved: `url: "https://pfblockerng.github.io/pkg/<channel>/<varver>/<arch>"` — **no `${ABI}`** (no Worker to expand it). Everything else unchanged from ADR-17/20: `priority: 100`, `mirror_type: none`, `signature_type: none`, `enabled: yes`; repo name `pfblockerng` (release) / `pfblockerng-nightly` (nightly). |
| **First-touch** | `add-repo.sh` (no Worker): computes `<varver>/<arch>` via the helper, writes the resolved conf, **and installs the self-heal hook** into `/usr/local/etc/rc.d/`. |
| **Self-heal hook** | A POSIX-`sh` `rc.d` script, **fail-proof (always `exit 0`)**, ordered after networking and before the pfBlockerNG/unbound services. On each boot: (1) **guard** — `[ -f <our conf> ] \|\| exit 0`; (2) compare the box's current `<varver>` to the one embedded in the conf URL; (3) **match → exit 0** (the every-boot fast no-op, zero `pkg` work); (4) **mismatch → rewrite only the varver/arch segment, `pkg update`, and reconcile the installed pfBlockerNG package** (`pkg install -y` / `pkg upgrade` of whatever pfBlockerNG package the box has) so devel/nightly boxes that lost the package get it back. Mismatch happens only on the rare post-version-upgrade boot. |
| **Worker** | `scripts/worker/`, `deploy-worker.yml`, the `worker-tests` CI job, the `deploy-worker` release job, `routing.json` generation (`build-repo-portable.py` + `publish.yml`), and the `SMOKE_WORKER_LIVE` Case-4 leg are **deleted**. |
| **Meta-package** | **Not built.** The abandoned Phase-2 artifacts (`tests/test_pfblockerng_repo_pkg.py` and the `build-pkg-portable.py` meta-package additions) are reverted; the detection helper + its tests are kept. |
| **Matrix-collision guard** | A fail-closed CI/unit check rejects a version matrix that puts two pfSense versions on the **same `(freebsd_major, arch)` with different `(php, py)`** — the case where varver keying would be ambiguous — so the structural assumption is enforced mechanically, not trusted. |
| **Catalog tree** | **Unchanged** (`release/<varver>/<arch>`, `nightly/<varver>/<arch>`). Only the *routing layer* changes (Worker → on-box detection + hook). |
| **Trust** | Unchanged from ADR-17: `add-repo.sh` is fetched over HTTPS from GitHub; the conf points at our NONE-signed, TLS-anchored Pages repo exactly like the pfBlockerNG package itself. No new trust surface; no new shipped artifact. |

### Semantics that MUST be preserved (the contract — pin with tests before swapping)

1. **Conf byte-identity** across all three generators (`--print-conf`) after the URL change —
   `tests/test_add_repo_conf.py`.
2. **Conf field set** unchanged except the `url:` value: `priority: 100`, `signature_type: none`,
   `mirror_type: none`, `enabled: yes`, per-channel repo name.
3. **varver/arch correctness**: on-box detection yields the **same** `<varver>/<arch>` that
   `catalog_name_from_version()` + the matrix arch produce for that box — pinned by shared
   table-driven cases (`2.8.1+CE→ce-2.8`, `26.03.1+Plus→plus-26.03`, …).
4. **Hook safety + idempotence**: the hook **never** exits non-zero (cannot wedge boot); on a
   matching box it is a no-op; orphaned (conf absent) it is a no-op; re-running yields the identical
   conf; channels don't clobber (`pfblockerng.conf` vs `pfblockerng-nightly.conf`).
5. **EOL/route-only**: a box whose `<varver>` is a retained-but-EOL catalog (ADR-27) still gets a
   working conf pointing at its frozen subtree — no special routing needed.
6. **Catalog acceptance**: `pkg update` against the resolved direct URL loads the catalog and
   `pkg install/upgrade pfBlockerNG` resolves our build (priority 100 dominates) — the existing
   `repo`-marker smoke still passes.

### Explicitly kept / out of scope

- The variant-keyed catalog tree, `catalog_name_from_version()`, per-ABI bucketing — **kept**.
- The Phase-1 detection helper + its shellspec — **kept** (now wired into `add-repo.sh` + the hook).
- A GUI "Updates/Channel" panel (ADR-19) — still deferred (would touch `src/`).
- `config.xml` / package runtime behaviour — untouched.
- Pre-solve correction of the conf — **proven impossible** for a third party (§1.3); the accepted
  model is post-upgrade-boot heal.

## 3. Consequences

**Positive**

- The self-hosted install path **works on real boxes** (the UA blocker is removed) — no dependency
  on a UA the client doesn't send.
- **No edge infrastructure and no new shipped package**: no Cloudflare Worker to deploy/secret, no
  `routing.json` to keep live, no meta-package port/plist/publish wiring. Fewer moving parts, one
  less always-on service, smaller CI surface.
- **Self-healing with no lifecycle cost**: the conf follows the box across version/edition upgrades
  via a self-guarding hook that needs no uninstall and is benign if orphaned.
- Detection is **deterministic and offline** — a local file/`pkg` read, not a network round-trip.

**Negative / risks**

- **The lag is structural, not eliminated.** Because no third-party pre-solve hook exists (§1.3),
  the heal happens on the post-upgrade **boot**, not inside the upgrade transaction — there is a
  brief within-one-boot window where the stale-varver build may be installed/removed before the
  hook runs. Bounded and invisible if the hook is ordered before the pfBlockerNG/unbound services;
  pfBlockerNG data lives in `/var/db/pfblockerng` (not pkg-managed) so a transient remove loses
  nothing. Pinned by the upgrade smoke.
- **Detection correctness is on-box logic we own.** A wrong `<varver>` writes a 404-ing conf.
  Guarded by the shared table tests + the upgrade/EOL smoke; the matrix-collision guard fails the
  build if the keying could ever be ambiguous.
- **Hook robustness is safety-critical** — a hook that could exit non-zero or hang could affect
  boot. Mitigated by the hard rule "always `exit 0`", network-gated ordering, and a shellspec that
  asserts the guard, the no-op path, and non-zero-exit-proofing.

## 4. Requirements (acceptance)

- `add-repo.sh` (no Worker) writes a direct resolved conf **and** installs the self-heal hook; a
  real `pkg update` loads the catalog and `pkg install pfBlockerNG` pulls our build.
- The hook: is a no-op on a matching box and when the conf is absent; on a simulated varver change
  rewrites the conf to the box's correct `<varver>/<arch>`, `pkg update`s, and reconciles the
  pfBlockerNG package; **never exits non-zero**.
- All three conf generators emit byte-identical confs; `tests/test_add_repo_conf.py` green against
  the new URL.
- The Worker, `routing.json`, the meta-package artifacts, and their tests/CI are gone;
  `test_build_repo_portable.py` and the smoke suite green without them; no dangling references.
- The matrix-collision guard fails a deliberately-colliding fixture and passes the real matrix.
- The `repo`-marker smoke proves: fresh install, cross-repo precedence, `pkg upgrade`, **upgrade
  self-heal**, and an EOL/route-only box all resolve the correct catalog.

## 5. Constraints (from CLAUDE.md)

- `add-repo.sh` / detection helper / `rc.d` hook: **POSIX `sh` only**, base-system utilities; no
  PHP, no add-on deps. Quote all expansions; `LC_ALL=C` on any machine-data sort/compare.
- All distribution code stays **dev-only** (release archives are `src/` only). The `rc.d` hook is
  installed on the box by `add-repo.sh`, not shipped inside any `.pkg`.
- Conf generators must remain byte-identical (drift is a silent break).
- ADR-text + phase prompts land **directly on the branch** (docs carve-out, no PR). Every
  code/CI/test phase uses the **full worktree + rebase-only PR** flow.

## 6. Action plan

Phase 1 already landed (the detection helper). The remaining phases repoint the boundary, add the
hook, then delete the dead Worker/meta-package surface last.

### Phase 1 — Shared on-box variant-detection helper (+ tests) — **DONE**

- **Prompt:** `01_Detection_Helper.txt`
- `scripts/lib/detect_variant.sh` resolves edition/version/arch → `<varver>/<arch>`, mirroring
  `catalog_name_from_version()`; pinned by `tests/shell/detect_variant_spec.sh`. Behaviour-preserving
  (new code, callers added in Phase 2). **Retained as-is.**

### Phase 2 — `add-repo.sh` resolved conf + the self-heal `rc.d` hook (boundary change)

- **Prompt:** `02_AddRepo_And_Hook.txt`
- Repoint `add-repo.sh`: `DEFAULT_BASE_URL` → `https://pfblockerng.github.io/pkg`; build the
  **resolved** `url:` via the Phase-1 helper (no `${ABI}`, no Worker). Add the self-guarding `rc.d`
  self-heal script and install it from `add-repo.sh`. Update all three `--print-conf` generators
  byte-identically. **Tests:** rewrite `tests/test_add_repo_conf.py` for the resolved URL +
  byte-identity, idempotence, channel non-clobber; new shellspec for the hook (guard exits 0;
  no-op on match; rewrite-on-mismatch using a fixture varver; **asserts `exit 0` on every path**,
  including a forced-error path).

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
  pulls our build; **upgrade self-heal** (write a deliberately-stale `<varver>` conf, fire the hook,
  assert before/after the conf flips and the correct build is reconciled and serving);
  **EOL/route-only** box resolves its retained subtree. Update `CLAUDE.md` ("Self-hosted pkg
  repository" / "Cloudflare routing Worker" → superseded by ADR-39; reconcile with the ABI-not-1:1
  hard rule), `README.md`, ADR-20's status (add a "superseded by ADR-39 (routing layer)"
  amendment), and `docs/misc/architecture-notes.md` (the distribution note already records the
  invariant — add the self-heal-hook mechanism).

## 7. Definition of done

- All §4 requirements met; the `repo`-marker smoke (fresh install, cross-repo precedence,
  `pkg upgrade`, **upgrade self-heal**, EOL routing) is green on the live-VM fan-out (CE + Plus).
- Worker/`routing.json`/meta-package prep/their CI + tests removed; the suite is green without them;
  no dangling references remain.
- All three conf generators byte-identical against the new resolved URL.
- The matrix-collision guard is wired into CI and green on the real matrix.
- Docs updated; ADR-20 carries a "superseded by ADR-39 (routing layer)" amendment.

**Manual smoke checklist (owner: maintainer — what CI cannot fully cover):**

- A **real OS upgrade that changes `<varver>`** (a true cross-major upgrade, or CE → Plus) on a box
  with the hook installed, then reboot — confirm the conf self-heals to the new `<varver>/<arch>`
  and pfBlockerNG is reconciled. CI simulates the heal by firing the hook against a stale conf; a
  true cross-major OS upgrade and the rc.d-survives-the-BE-clone property are out-of-CI (the latter
  is maintainer-confirmed).
- **Boot ordering / DNS (smoke-validated):** the hook's heal does a `pkg` fetch, so it must run at a
  boot stage where DNS works (the resolver is up, or `resolv.conf` carries a reachable upstream) —
  not strictly before the local resolver if the box resolves via 127.0.0.1. Confirm on the live
  fan-out that the heal's `pkg update`/reconcile actually succeed at that stage; the rc-order
  keywords may need tuning to the real boot order.
- **Reconcile activation (smoke-validated):** confirm the hook's raw `pkg upgrade`/`install` of
  pfBlockerNG yields an **active** pfBlockerNG after the boot. A raw CLI pkg op does **not** fire
  pfSense's GUI PHP install hooks (the same PHP-vs-CLI split as §1.2), so activation must come from
  pfBlockerNG's normal boot-time integration — assert DNSBL actually serves post-heal, not just
  that the package is installed.
- The live `pfblockerng.github.io/pkg` URL resolves the variant catalog from a real box (the gated
  `SMOKE_REPO_LIVE_URL` leg, post-merge).

**REJECT criteria (what would kill or re-scope this ADR):**

- On-box detection cannot reliably distinguish CE from Plus, or cannot resolve `/etc/version` →
  `<varver>`, on a supported box (Phase 1 already verified `globals.plus.inc`, so low risk).
- The non-package `rc.d` hook is found NOT to survive a real cross-major BE-clone upgrade (would
  force falling back to the dep-free meta-package as the hook's vehicle — the only reason to revive
  it). Surfaced by the maintainer smoke before relying on it in the field.
