# ADR-47: Local/CI execution parity — CI as parallel dispatch of shared, isolated scripts

- **Status:** **Accepted** (status recorded 2026-07-04; §8 live acceptance discharged 2026-06-27; proposed 2026-06-26; design resolved + adversarially verified 2026-06-27). **P1 landed** via PR #591; **P2–P5 landed** via PR #595 (rebase-merged 2026-06-27): `run-id.sh`/`select-box.sh`, `build-leg.sh`/`parity-guard.sh`, `run-smoke.sh`/`smoke-on-box.sh`, `resolve-legs.sh`/`git-env-scrub.sh` + their shellspec suites, and the CI workflow rewires are all on `devel`. Post-merge review commits renamed two interfaces vs the phase prompts: `run-smoke.sh` takes `--filter` (not `-k`) and the workflows pass `PYTEST_FILTER` (not `PYTEST_K`) — read the prompts as history. The §8 multi-box live acceptance ran 2026-06-27 and passed (see §8); the on-box bugs it surfaced were fixed in PRs #597 and #598 (both merged 2026-06-27).
- **Date:** 2026-06-26
- **Branch:** authored directly on `devel` (ADR-text carve-out) / **Component(s):** `scripts/`, `tests/`, `.github/workflows/`
- **Target runtime:** GitHub Actions runners (CI) and developer LXC/KVM boxes (local) — POSIX sh + Python 3.11
- **Test suite:** `shellspec` (shell), `pytest` (Python), and the scripts' own self-checks; CI workflows validated by dispatch

---

## 1. Context

The build/test pipeline has two execution paths — **CI** (GitHub Actions) and **local** (a developer box, currently a single LXC host running QEMU/KVM smoke VMs). They are maintained as separate flows, and the drift between them has produced real, costly failures:

- **Divergent steps cause silent build corruption.** The portable `.pkg` build needs the FreeBSD-ports tree on the build-input branch `pfblockerng/use-github`. CI sparse-cloned that ref into a fresh runner dir; a local build reused a pre-existing `--ports` clone left on `devel`, whose port installs an **empty `pfblockerng_extra.inc` stub**. The result was a `.pkg` that fatals at runtime on the missing `localize_text()` shim — surfacing as "DNSBL feed not loading" and consuming a long debugging session. The fix (ADR-47 P1, PR #591) made `sparse-clone-ports.sh` a single shared step both callers use. The lesson generalises: **any step that lives only in CI YAML, or behaves differently locally, is a latent bug.**

- **Shared mutable state makes parallel runs race.** Local runs share one box and one (bare) git repo. Two concrete collisions occurred while authoring P1:
  - A sibling agent attempted to use the same box concurrently.
  - A shellspec fixture's `git init`/`git add -A`/`git commit`, run under the pre-commit hook (which exports `GIT_DIR`/`GIT_INDEX_FILE`/`GIT_WORK_TREE`), operated on the **real shared repo** instead of its temp fixture, hijacking the shared `devel` ref to a garbage commit chain. Recovery required manual `update-ref` surgery (no remote damage, `origin/devel` was intact). The fixture is now hardened to scrub the inherited git env, but the underlying hazard — a shared, mutable, global checkout — remains for anything that races on it.

The unifying principle the team wants:

> **CI is nothing more than a parallel-dispatch wrapper over the same scripts a local run invokes.** The only legitimate CI↔local divergence is orchestration — *where* legs run (cloud runners vs. local boxes) and *how* they fan out — never the per-leg work itself. A divergence in a *step* is a defect.

This composes with the existing repo conventions: the smoke harness already isolates VMs by `SMOKE_LANE` (port/MAC/overlay keyed per lane, #586) and the build already calls shared scripts (`sparse-clone-ports.sh`, `build-pkg-portable.py`). What is missing is (a) the discipline applied to *every* step, and (b) isolation strong enough that multiple runs — local or CI — never share a mutable path, port, or ref.

---

## 2. Decision

Adopt **one flow, two dispatchers**, with four mechanisms.

### 2.1 Shared per-leg scripts (no logic in YAML)

Every unit of build/test work is a repo script under `scripts/` or `tests/`, tailored to run identically under CI and local. Workflows become thin matrix/dispatch wrappers that set inputs and call the script; they hold no build/test logic. Steps that are genuinely GitHub-specific (artifact upload, OIDC token mint, the matrix definition itself) stay in YAML — that is orchestration, not per-leg work.

First instance already landed: `sparse-clone-ports.sh` is the single "prepare the ports tree at REF" step, with CI as the fresh-clone special case of the local reuse path (PR #591).

### 2.2 Parameterised isolation per run

Every run is keyed by a unique **run-id** (a generalisation of `SMOKE_LANE` from VMs to the whole pipeline). Everything mutable a run touches is derived from the run-id and never shared between concurrent runs:

- the FreeBSD-ports tree directory and the build workdir,
- qcow2 overlays, hostfwd ports, and VM MACs (already lane-keyed),
- **the git checkout/worktree** the run builds and commits from,
- any on-box scratch/state/lock paths.

This directly removes both collision modes above: no two runs share a ports dir, a port, or — crucially — a git ref. A run operates on its own checkout, so a fixture (or a build) can never reach a sibling's repo.

### 2.3 Box selection + mutual exclusion (one script)

A single script (`scripts/select-box.{sh,py}`) obtains an execution host:

- pick a box from a configured pool (initial algorithm: **random**),
- **skip any box already running local CI** (a lease: a per-box lock/marker, acquired on selection and released on completion; stale leases time out),
- return the chosen box and hold the lease for the run's lifetime.

CI's "pool" is the cloud-runner fleet (each leg already lands on a fresh, isolated runner — selection is implicit); local's pool is the set of LXC containers the developer spins up. **Same selection contract, different backend.** The script is the single source of truth for "which box, and is it free", so agents never hand-pick or collide.

### 2.4 CI is the specialised case

CI fans legs across cloud runners (inherently isolated, one leg per runner); local fans them across leased LXC boxes, or sequentially on one box with run-id lanes. The orchestration differs; the per-leg scripts and the isolation keys are **identical**. A local run and a CI leg execute the same script with the same parameters and produce the same artifact — the build already proves this (byte-identical `.pkg` from the shared portable builder).

---

## 3. Consequences

**Positive**

- No CI↔local drift: a class of bugs (the stub `.pkg`) becomes impossible because there is one step, exercised locally before every push.
- Parallel agents (and parallel CI legs) never collide: isolation is by construction, not by remembering to pick a free lane/box.
- The whole pipeline is reproducible and debuggable locally — CI failures reproduce by running the same script.
- Workflows shrink to dispatch, which is easier to read and audit.

**Negative / costs**

- Upfront refactor: parameterise every mutable path/port/ref by run-id; author the selection/lease script; audit CI steps for logic to extract.
- The developer must provision and maintain the LXC pool (infrastructure, user-owned).
- A genuine orchestration divergence remains (GHA-only steps) — acceptable, and explicitly *not* a target for unification.

---

## 4. Alternatives considered

- **Keep CI and local separate, document the local steps.** Rejected: documentation drifts; the stub-`.pkg` bug is exactly a documented-but-unenforced step going wrong.
- **Single-box, lane-only isolation (no box pool).** Viable and strictly simpler — run-id lanes on one box remove the shared-state races (2.2 alone). The box pool (2.3) is the throughput add-on, not a correctness prerequisite; it can be deferred. Both compose: select a box, then lane-isolate within it.
- **A coordination daemon for leases.** Rejected for now in favour of the simplest mechanism that works (per-box lockfile + random pick + retry); revisit only if file-locking proves insufficient.

---

## 5. Resolved design

The three open questions are now resolved. The design is grounded in a survey of the actual build/smoke/git flows and was hardened by an adversarial pass (§7).

### 5.1 One run-id keyed everywhere; the box lease keys per-box state

A single `RUN_ID` keys every per-**run** mutable path; the **box lease** (not `RUN_ID`) keys persistent per-**box** state. Both mint paths share one definition in `scripts/lib/run-id.sh`, so local and CI cannot drift:

- **Local** (minted by `select-box.sh` *after* it leases a box): `RUN_ID=local-<box>-<epoch>-<rand>` — `<box>` = the leased LXC container, `<epoch>` = `date +%s`, `<rand>` ≥ 8 bytes of `/dev/urandom` hex (POSIX; no `$RANDOM`).
- **CI** (`run-id.sh --print-id`, no lease — the ephemeral runner *is* a pre-leased box): `ci-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-<leg>`, where `<leg>` reuses the existing per-leg coords (varslug/major/arch per ADR-20, never bare `${ABI}`; smoke/UI append the marker).
- **No aliasing:** the literal `local-` vs `ci-` prefix is a hard structural split (no `GITHUB_RUN_ID` equals the string `local`); within each space the tails are unique by construction (the adversarial pass confirmed this).

`RUN_ID` keys the *ephemeral* `PFB_RUN_DIR=${PFB_RUN_ROOT}/${RUN_ID}/` (the build `out/` — which also defeats `build-pkg-portable.py`'s deterministic `{pkgname}.pkg` filename collision — and `smoke-diag/`). The *lease* keys the *persistent* per-box state — the ports cache, the `127.0.0.1:53` stub bind, the `ip_unprivileged_port_start` sysctl, `pkill qemu`, the per-box git checkout — all single-writer because only one run holds the box, so they need no run-id suffix. `SMOKE_LANE` stays the within-box port-stride primitive (default lane 0), composed under the run-id umbrella for the degenerate one-shared-box fallback.

### 5.2 The select-box script + the simplest correct lease

`scripts/select-box.sh` is the keystone and sole local entry — the analog of GitHub handing a leg a fresh runner, over a **provided pool** of containers. The pool is an explicit list (`PFB_BOXES`, e.g. `root@10.0.0.23 root@10.0.0.24`) — **no auto-discovery, no `lxc list`/`lxc exec`, no reliance on the LXC host**. It reaches every box **only over ssh**, exactly as the existing harness already does (`ssh root@<box>`). It scrubs `GIT_*` once for the whole pipeline (kills the shared-ref corruption class at the source), leases a box, mints `RUN_ID`, creates `PFB_RUN_DIR` on the leased box, emits eval-able `KEY=value` (mirroring `release-version.sh`), runs the leg in the leased box over ssh, and trap-releases on `EXIT/INT/TERM`. `--print-id` mints without leasing (CI — the runner is already an isolated box, the one permitted orchestration-only divergence); `--release <RUN_ID>` frees a box after verifying the owner. The lease markers live in a host directory **bind-mounted into every box at the same path** (`PFB_LEASE_DIR`, default `/var/lib/pfb/leases`), so the lock is one shared object visible across the whole pool.

The lease is the **only** synchronization primitive in the design, so it must be correct:

- **Acquire** = an atomic `mkdir "${PFB_LEASE_DIR}/<box>.lock"` performed **over ssh into the target box** (the lease dir is the shared bind-mount, so the lock is visible to every box; `mkdir` is create-or-fail on the host's local fs → exactly one racer wins across the pool), then an **atomic owner publish** (`runid agent-host epoch`) — write a temp file in the lockdir and `mv` it onto `owner`, so a reader never sees a half-written owner. The lease dir MUST be a local fs / bind-mount, never NFS/9p/virtio-fs, or `mkdir`/`rename` atomicity is lost.
- **Pick** = random index over the pool (`od /dev/urandom`), advancing on `EEXIST` — avoids a thundering herd on box 0.
- **Retry** = one pass; if all held, a short jittered backoff and re-scan, hard-bounded (default minutes; never past the CLAUDE.md 2 h cap). On exhaustion, exit non-zero printing each held box's owner — never hang, never silent.
- **Stale reclaim** (the part the adversarial pass corrected): a held box is reclaimable when (a) `now-epoch > PFB_LEASE_TTL` (the **primary** backstop — the owner runs off-box over ssh, so a cross-host `kill -0` is unavailable; TTL must sit well above the longest run), or (b) the owner file is absent/empty past a short grace (a crash *between* `mkdir` and the owner publish). Reclaim is **atomic-capture, not `rmdir`+`mkdir`**: a reclaimer renames the stale lockdir to a reclaimer-unique name (`mv "<box>.lock" "<box>.lock.reclaim.<RUN_ID>"`) — `rename(2)` of a directory is atomic, so for one source exactly one concurrent reclaimer wins (the loser gets `ENOENT` and rescans); the winner verifies the captured owner still equals the stale tuple it observed (a TOCTOU guard — never steal a freshly-acquired live lease), then `mkdir`s a fresh lock and publishes its owner. This serializes reclaim through one atomic op, closing the double-grant hole where two reclaimers would otherwise both believe they own the box.
- **Release** is idempotent (owner-runid-checked), armed in the exit trap; a hard-kill miss is reaped by the next contender's stale rules.

### 5.3 The shared per-leg scripts (no logic in YAML)

Three homes for per-leg logic, each one shared script both CI and local call:

- **`scripts/build-leg.sh`** — the missing "build ONE leg" wrapper over `sparse-clone-ports.sh` + `build-pkg-portable.py` with a single unified arg set. It converts today's real step divergence into parameters: `build-pkg-linux.yml` passes *neither* `--pkgversion` nor `--annotate`; `release.yml` passes *both*; `smoke-single.yml` hard-codes `--pkgversion 3.2.16.20260606.2`. `ports_repo`/`ports_ref` also become params (killing `release.yml`'s hard-coded ref). DEST/OUT become box/run-keyed.
- **`scripts/run-smoke.sh`** — the one canonical pytest argv, replacing three drifting copies (`smoke-single.yml`, `ui-tests.yml`, `local-smoke.sh`); marker/timeout/`-k` as params, so the CI-vs-local timeout/verbosity drift cannot recur.
- **`scripts/resolve-legs.sh`** — the shared leg-filter (the `scope`/legs/`-k` jq currently copy-pasted across `smoke.yml`/`ui-tests.yml`) plus the shared image-ref / oras-digest / VM-identity-redaction / diagnostics-scrub helpers.

A small **parity-guard lint test** fails CI if any per-leg job body carries build/test *step* logic — including inline *arg derivation* (the `release-version.sh`/jq/sed prep that feeds a leg), not only the leg invocation — so CI-only step logic cannot survive by living one line above the call. Build parity is "**same script + same defaulting logic**", *not* byte-equal artifacts: the smoke and released `.pkg` are deliberately different builds (different `--pkgversion`, a non-deterministic `--annotate created=` timestamp), so a byte-equal claim is impossible and is explicitly not the goal.

The `GIT_*` scrub gets one mechanical chokepoint for the *test* path too: a shared `scripts/lib/git-env-scrub.sh` sourced from a shellspec helper that every spec includes, plus a parity-guard assertion that every git-touching spec pulls it — so a new spec cannot silently re-open the shared-ref corruption (the per-spec `BeforeEach unset` that even this ADR's P1 relied on stops being a "must-remember").

### 5.4 The smoke execution locus — run ON the leased box (resolved)

A local smoke run **runs entirely on the leased box** (the boxes are the nested-KVM environment; the dev/CI machine only orchestrates). `local-smoke.sh` leases a box and drives an **on-box entrypoint** (`scripts/smoke-on-box.sh`) via `select-box.sh -- <cmd>` (the lease-held form P2 validated — default mode self-releases). The entrypoint, single-writer on its leased box, is responsible for making the box current for *its own* run:

- **Ref management.** Repos live under `/root` (e.g. `/root/pfBlockerNG`). The run **checks out the ref it wants** — every run may switch to any commit/branch/ref — so the orchestrator passes the ref and the on-box bootstrap does `git fetch` + checkout, then re-execs the now-at-ref entrypoint (the bootstrap one-liner is ref-stable; the work runs at the requested ref's own scripts/tests). **FreeBSD-ports** (also under `/root`) is brought up-to-date on `pfblockerng/use-github` via `sparse-clone-ports.sh` (P1, idempotent).
- **Image freshness.** The pfSense + civm qcow2 are pre-baked into the LXC clones but may be stale: the entrypoint **`oras pull`s into `/root/images`, refreshing when the GHCR digest differs and pulling when absent** (digest-compare + tolerate-missing — do both), then points `SMOKE_IMAGE_DIR`/`SMOKE_CLIENT_IMAGE_DIR` there.
- **Build + run on the box.** `build-leg.sh` (P3) builds the `.pkg`; `run-smoke.sh` runs the canonical pytest argv; `pkill qemu` runs **on the box** before boot — single-writer ownership makes it both safe (never touches another box's VMs) and reaping (clears this box's stale qemu, incl. the fixed lane port).

**CI is the degenerate case:** the runner *is* a pre-leased, already-checked-out box (`select-box.sh --print-id`, no lease, no on-box bootstrap) — it calls `run-smoke.sh` directly. So `run-smoke.sh` (the pytest argv) and the host prep are the shared surface; only the lease + on-box bootstrap are local-only, which is the one legitimate orchestration divergence (§2).

---

## 6. Phases

Each phase is independently landable, behaviour-preserving where it can be (the single-box/lane-0 path reproduces today's paths), and carries its own tests.

- **P1 — Shared ports-prep (DONE, PR #591 + a review-hardening follow-up).** `sparse-clone-ports.sh` idempotent: reuse fetches + checks out REF instead of trusting the checked-out branch, so a stale tree can no longer build the empty-stub `.pkg`. Pinned by `tests/shell/sparse_clone_ports_spec.sh`.
- **P2 — Run-id backbone + lease (DONE, PR #595) (local-only, additive).** Add `scripts/lib/run-id.sh` + `scripts/select-box.sh` (the corrected lease) + `tests/shell/select_box_spec.sh` (stub `ssh` on PATH; acquire/conflict/random-spread/TTL/missing-owner-grace/**two-concurrent-reclaimers**/exhaustion/release/no-alias). Validate against the real pool (`PFB_BOXES="root@10.0.0.23 root@10.0.0.24"`, shared lease mount): two concurrent `select-box` invocations get distinct boxes + run-ids. Mechanism only.
- **P3 — Shared BUILD script + converge the build sites (DONE, PR #595).** Add `scripts/build-leg.sh` + spec; rewire `build-pkg-linux.yml` and `release.yml`'s matrix loop to call it; delete the `--pkgversion`/`--annotate`/ports-dir/ports-ref step divergences. Gate: build the smoke leg the old way vs `build-leg.sh` with identical inputs and `cmp` byte-for-byte (reproducible — no version/annotate on that leg); for the release leg, compare manifest fields modulo the known-nondeterministic `created=` timestamp.
- **P4 — Local-smoke parity + shared SMOKE launcher (DONE, PR #595 — shipped as `--filter`/`PYTEST_FILTER`, see Status) (run ON the leased box, §5.4).** Add `scripts/run-smoke.sh` (the one canonical pytest argv, marker/timeout/`-k`/paths as params; a caller path REPLACES the default, not augments) + spec. Add `scripts/smoke-on-box.sh` (the on-box entrypoint: ref checkout + ports-update on `use-github` + `oras` image-refresh into `/root/images` + lease-gated `pkill qemu` + `build-leg.sh` + `run-smoke.sh`). Rewire `local-smoke.sh` to lease via `select-box.sh -- <smoke-on-box>` (the lease-held form — default mode self-releases), trap-release; keep the stub-`:53`/civm/`SMOKE_*` contract but move the host-prep onto the box. Point `conftest.py` `DIAG_DIR` at `PFB_DIAG_DIR` (empty-safe; `SMOKE_LANE` unchanged) and fix the `bind(:0)` TOCTOU by lane-striding the LAN-socket port off base `12340` (delete `_alloc_free_tcp_port`; re-base `_validate_lane`'s ceiling). Rewire `smoke-single.yml`/`ui-tests.yml` to mint `RUN_ID` (`--print-id`, slugged `LEG`) + call `run-smoke.sh` directly (CI runner = pre-leased box, no on-box bootstrap). Gates: `run_smoke_spec` (argv-assembly, PR gate) + the conftest lane-stride/DIAG pytest unit test (PR gate) + a **2-box concurrent local smoke** as the out-of-CI §8 live acceptance.
- **P5 — CI collapse to dispatch + parity guard + docs (DONE, PR #595).** Lift the duplicated leg-resolution into `scripts/resolve-legs.sh` + helpers; each per-leg job body becomes {mint RUN_ID; call one shared script}. Add the parity-guard lint + the `git-env-scrub.sh` chokepoint. Document the model in `architecture-notes.md` / `local-smoke-debian.md` / README.

**Out of scope:** provisioning the LXC containers (user-owned infra); the GHA-only orchestration steps (artifact upload, OIDC, the matrix definition) — the one legitimate divergence.

---

## 7. Adversarial verification

The design was stress-tested by independent adversarial lenses (collision / failure / parity). Four real gaps were found and folded into §5 before this revision:

1. **Stale-reclaim double-grant** — the original `rmdir`+`mkdir` reclaim let two reclaimers both "win" and run on one box (catastrophic: duplicate `:53` bind, one run's `pkill qemu` killing the other's VMs, a concurrent ports checkout re-summoning P1's wrong-branch class). Fixed by atomic `rename`-capture (§5.2).
2. **Acquire-window leak** — a crash between `mkdir` and the owner write left a box stuck "busy" forever (no owner ⇒ no stale rule can fire). Fixed by the missing-owner-after-grace reclaim rule + atomic owner publish (§5.2).
3. **Test-path scrub was a "must-remember"** — only a per-spec `BeforeEach unset` guarded the corruption class. Fixed by the shared `git-env-scrub.sh` + a parity-guard assertion (§5.3).
4. **Build parity mis-specified** — the smoke `.pkg` can never be byte-equal to the released one (`--pkgversion`/non-deterministic `--annotate`). Re-specified as same-script-same-defaulting + a closed legitimate-divergence parameter set, with the parity-guard also forbidding inline arg-derivation (§5.3).

A second adversarial pass (Map→Design→Verify over the real build files) hardened the **P3** design before implementation; its findings are folded into the P3 phase prompt (`03_P3_Shared_Build_Script.txt`):

1. **build-leg stdout leak** — `sparse-clone-ports.sh` runs `git checkout`, which writes branch-tracking chatter to **stdout**; unredirected it corrupts `build-leg.sh`'s `.pkg`-path stdout contract (breaks `dirname`/`mv`/`cmp`/`SMOKE_NIGHTLY_PKG` at every caller). Fixed by muzzling the tree-prep step to stderr; only the builder's path reaches stdout.
2. **release stamp from the wrong ref** — hoisting `created=`/`commit=` into `read-matrix` (which checks out the dispatch HEAD) mis-stamps the `.pkg` when a release-notes commit advances the tagged tip. Fixed by a dedicated `resolve-stamp` job checking out the build job's exact ref (`tag` on a real release, `github.ref` on dry-run).
3. **ports pin that doesn't pin + parity-guard self-contradiction** — the parity gate must pin FreeBSD-ports drift-free (sparse-clone always re-fetches the moving branch; `clone -b` rejects a raw SHA) via a local `file://` clone at a fixed ref for both legs; and the parity-guard must discriminate by flag *target* (forbid `--pkgversion`/`--annotate`/ports literals only on direct `build-pkg-portable.py`/`sparse-clone-ports.sh` calls, allow them on `build-leg.sh`) with build-leg arg-values deny-by-default (literal/input/`needs` only). Plus: extract the release manifest via `zstd -dc | tar` (not tar zstd auto-detect) and slug the colon-bearing `LEG` token for safe artifact and run-key naming (GitHub artifact names and run-dir/path tokens split on `:`).

A third adversarial pass hardened the **P5** design (CI collapse); its findings are folded into the P5 phase prompt (`05_P5_CI_Collapse_Parity_Guard.txt`):

1. **Generalized parity-guard would red-fail the unit suite** — a naive "flag `python -m pytest` in any workflow" Rule 4 matches `test.yml`'s legitimate unit runner (which uses no path, relying on pyproject `testpaths`). Scoped Rule 4 to a `python[3] -m pytest` line that *also* names `tests/smoke`/`tests/smoke/ui` (the smoke bypass), never the bare `pytest` substring (the workflows are full of `pytest_marker:`/`-m "${PYTEST_MARKER}"`); the unit suite stays green.
2. **`resolve-legs.sh` output contract** — `ui-tests.yml` post-processes the raw legs (PROJECT + `build_matrix` + tier×leg cross) in the *same* step, but a value written to `$GITHUB_OUTPUT` can't be read back in-step; so the resolved legs JSON must go to **stdout** for same-step capture (scope/`-k` still ride `$GITHUB_OUTPUT`).
3. **Secret-leak / data-loss in the helper lift** — the `vm-identity`/`scrub` blocks differ across the pair (smoke folds the secret civm MAC into the redaction; ui keeps `test-results/ui-screenshots` and scrubs `test-results/`). The shared subcommands parameterize civm-presence + scrub-root + screenshot-keep **deny-by-default**, so civm redaction can never be dropped (a Plus-secret leak) nor the UI Playwright shots deleted. Plus: the `git-env-scrub` source must sit *below* each script's self-dir resolution; the scrub meta-assertion keys on a bare `git` command token (script-name allowlist secondary); the per-leg helpers live in `smoke-single.yml`/`ui-tests.yml`, not `smoke.yml`.

---

## 8. Acceptance

Per the CLAUDE.md ADR-acceptance rule (green automated coverage, no manual sign-off): each phase's shellspec/pytest gates green, including the §7-hardened `select_box_spec.sh`. The out-of-CI acceptance item (a documented limitation, not a blocker) is a **concurrent multi-box run on the real LXC host** — a local run and a CI-leg-shaped run at once — asserting zero shared-state collisions across ports, `:53`, the ports cache, diagnostics, and git refs.

**Discharged 2026-06-27 — live 2-box concurrent run, passed.** Two concurrent `local-smoke.sh` runs leased distinct boxes (pfb-box-1 `10.0.0.23` / pfb-box-2 `10.0.0.24`) and each ran the full on-box pipeline (ref checkout → FreeBSD-ports update → `oras` image pull → sysctl → `build-leg.sh` into its own run-keyed out dir → full ADR-04 smoke → clean lease release) to completion with **identical results on both boxes** (86 passed / 112 skipped / 262 deselected / 7 failed / 1 error, ~9:18 each) and **zero cross-collision** — distinct run-ids, run dirs, and leases; no port, `:53`, ports-cache, diagnostics, or git-ref interference. That identical-results/zero-collision outcome is the §8 isolation property, proven live. The run surfaced three on-box harness bugs, all fixed and merged the same day: stale-local-branch ref checkout (`git fetch origin <ref>` + `checkout --force FETCH_HEAD`), missing on-box pytest (`.venv` provisioning), and `origin/`-prefix normalization — PR #597; the 7 shared smoke failures were root-caused as pre-existing `devel` smoke-test defects (not ADR-47 or product bugs): the ADR-12 hooks + ADR-36 dot_doq cluster fixed in PR #598, the ADR-43 cluster tracked in issue #568.
