# ADR-47: Local/CI execution parity — CI as parallel dispatch of shared, isolated scripts

- **Status:** **Proposed** (2026-06-26)
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

## 5. Scope and phases

Implementation is staged; each phase is independently landable.

- **P1 — Shared ports-prep (done).** `sparse-clone-ports.sh` idempotent, CI = fresh-clone special case (PR #591).
- **P2 — Extract remaining CI build steps into shared scripts.** Audit `build-pkg-linux.yml` / `release.yml`; move any per-leg logic into `scripts/`; workflows call them.
- **P3 — Run-id parameterisation.** Generalise `SMOKE_LANE` to a pipeline-wide run-id keying ports dir, workdir, overlays, ports, and the git worktree.
- **P4 — Box selection + lease.** The single `select-box` script over the LXC pool; agents acquire/release a box.
- **P5 — Smoke fanout as local parallel dispatch.** The CE+Plus (and beyond) fanout runs as parallel-isolated local legs mirroring CI, sharing the per-leg suite.

**Out of scope:** provisioning the LXC containers themselves; the specific lease backend beyond "simplest that works"; the GHA-only orchestration steps.

---

## 6. Open questions (to resolve during implementation)

- **Lease mechanism:** `flock` on a shared path vs. a per-box marker file vs. a tiny service. Start with the simplest; pin the chosen contract with a self-check.
- **Isolation granularity:** one box per run vs. lanes within a box. Both compose; the box pool is the throughput lever and may be deferred behind lane-only isolation.
- **Run-id source:** how a CI leg's matrix coordinates and a local run's id are minted so they never alias (and so a local id is stable across a run's steps).
