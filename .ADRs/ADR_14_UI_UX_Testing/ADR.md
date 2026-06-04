# ADR-14: Web UI/UX testing on the live pfSense VM (tiered render + functional + browser)

- **Status:** **Implemented (pending smoke test)** (2026-06-04) — all six phases
  landed on `adr/14`; the harness, the three tiers, the reusable matrix workflow,
  the PR gate, and the release gate are in place and statically validated. The
  flip to **Accepted** is the **maintainer's** call after the live-box manual
  smoke + screenshot review in §7 (the live VM exists only in CI; this dev box
  cannot boot/reach it, so the live-run + the §7 reliability numbers are
  CI-pending — see the outstanding Accept criteria in §7).
- **Date:** 2026-06-03 (proposed) / 2026-06-04 (implemented)
- **Branch:** `adr/14` (off **`devel`** — this is **dev-only test/CI infra** that builds on the ADR-04 smoke harness (`tests/smoke/conftest.py` `smoke_vm`, `helpers.py` diagnostics), the portable Linux `.pkg` builder (`build-pkg-linux.yml`), and `smoke.yml`, all of which live on `devel`. (`next` was retired 2026-06-04 into a two-tier `main←devel` model; devel is the default/integration branch.) Nothing here ships in the release archive — `src/` is untouched.) / **Component(s):** `tests/smoke/` (new `ui/` subpackage reusing the `smoke_vm` fixture), `tests/smoke/requirements.txt` (add `requests` + Playwright), `.github/workflows/` (new reusable `ui-tests.yml`; wiring into `test.yml`, `smoke.yml`-style triggers, and `release.yml`), `README.md`/`CLAUDE.md` (docs).
- **Target runtime:** **dev/CI only.** Python 3.11+ (pytest) on a GitHub `ubuntu-latest` runner, driving a live **pfSense CE** WebUI inside QEMU/KVM (the ADR-04 image). Non-stdlib test deps (`requests`, `playwright`) live in `tests/smoke/requirements.txt` — **not** shipped, same discipline as the existing smoke deps. **No `src/` change**; the Unbound plugin, PHP package, and shipped JS are untouched.
- **Test suite:** new `tests/smoke/ui/` (markers `ui_render`, `ui_e2e`, `ui_browser`), reusing `tests/smoke/conftest.py`. **Default `python -m pytest` stays byte-identical** — UI tests are excluded from default collection by the same mechanism as the smoke suite. No `pytest` *oracle* for the PHP itself (it only runs inside pfSense); validation = the live-VM assertions below + a manual screenshot review.

---

## 1. Context

### Today

pfBlockerNG ships a substantial Web UI with **zero automated coverage**:

1. **18 PHP pages** under `src/usr/local/www/pfblockerng/` (`pfblockerng.php`, `_general`, `_ip`, `_dnsbl`, `_feeds`, `_alerts`, `_log`, `_category`/`_category_edit`, `_sync`, `_safesearch`, `_threats`, `_update`, `_blacklist`, `_asn`-related), plus the DNSBL VIP webserver pages (`www/index.php`, `www/dnsbl_default.php`), a **dashboard widget** (`widgets/widgets/pfblockerng.widget.php` + `widgets/include/widget-pfblockerng.inc`), and **client-side JS**: `pfBlockerNG.js` (268 lines) and `widgets/javascript/pfblockerng.js` (198 lines).
2. **The JS carries real UX logic** that static checks can't reach: field enable/disable toggles (`enable_change_in/out`, `enable_change_port_in/out`, `pfBlockerNG.js:213-230`), `pfb_autocomplete*` (`:36`/`:102`), label removal (`:115`), row move handlers (`[name^=Lmove]`/`[name^=Xmove]`, `:145-149`), and a background AJAX state change `pfb_chg_state_bkgd()` (`:124`).
3. **Current automated coverage is structural only.** `python -m pytest` is **pure-logic** (`pfb_unbound.py` + ADR-06/07 + the portable builder). PHP/shell get `php -l` + PHPStan + ShellCheck (`test.yml`) — **symbol/syntax existence, not runtime rendering.** None of these catch a page that 500s, renders a PHP `Warning`/`Notice`, or breaks a form on a real box.
4. **A live WebUI already exists in CI but is barely touched.** The ADR-04 smoke VM exposes the webConfigurator at host `127.0.0.1:8080` → guest `:80` (SLIRP hostfwd, `tests/smoke/boot_vm.sh:119`). `wait_ready.sh:102` polls it (`curl -fsSL http://…:8080/`); `roundtrip.sh` curls `/` → the login page — **unauthenticated reachability only.** The admin password is baked (`SMOKE_ADMIN_PASSWORD`) but **auth is never exercised**.
5. **The harness it would build on is rich and reusable.** `smoke_vm` is a **session-scoped** fixture (`tests/smoke/conftest.py:303`) yielding a `SmokeVM` with an `ssh()` helper (`:144`); `helpers.py` already has `config_get()` (`:403`), `config_set`/`write_config`, and a full diagnostics collector (`snap_state`/`dump_state_diffs`/`dump_diagnostics`, `:829`/`:862`). `smoke.yml` is `workflow_dispatch` + `workflow_call` (+ a nightly `schedule`), builds the branch `.pkg` on Linux (`build-pkg-linux.yml`), runs `pytest -m smoke`, and uploads a `smoke-diagnostics` artifact `if: always()` (`smoke.yml:263`).
6. **The release flow is a gated chain.** A `v[0-9]*.[0-9]*.[0-9]*` tag triggers `release.yml`: `verify-checks` (asserts the **"All tests passed"** check-run for the tagged commit is `success`) → `release` (publish GitHub Release) → `ports-pr` (open a PR on `pfsense/FreeBSD-ports`). There is **no UI gate** in this chain.

### The need (maintainer-confirmed)

Catch WebUI regressions that `php -l`/PHPStan miss — pages that error or render warnings on a real box, and forms that silently stop persisting — **before** they reach a release. Two tiers, by cost/frequency: a **cheap render-smoke that gates PRs touching PHP**, and a **heavier functional + browser pass** (with **screenshots as artifacts**) that runs daily/on-demand. Workflows must be **matrix-parametric over pfSense version** (smoke-style), every leg **re-runnable in isolation** (a not-our-fault flake shouldn't force a full re-run), and the **release pipeline must run the full suite first** while keeping that isolation.

### Load-bearing facts (verify, don't assume — per `CLAUDE.md`)

1. **Feature/infra ADR, not a perf premise (≈ ADR-12, not ADR-01).** The falsifiable risk is **flake & cost**, not speed. Browser E2E over SLIRP-QEMU in CI is the classic flaky/slow trap → §7 defines the kill gate.
2. **These pages only run inside pfSense.** They `require_once` pfSense core (`guiconfig.inc`, …) → **cannot render under a standalone PHP server** without heavy stubbing. The ADR-04 VM is the **only** viable host; a separate harness is out.
3. **The pass/fail oracle is NOT HTTP 200.** A 200 can carry a rendered PHP `Warning`/`Notice`, or a blank body. The oracle must read the **body** (no `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`), a **page-specific content marker**, **and** the on-box `php_error.log` (source of truth) — and for functional tests the **effective** `config.xml`/`pfctl`/unbound state via `helpers.config_get`, never the HTTP response alone.
4. **WebUI protocol must be confirmed on the image, not assumed.** Evidence says **HTTP** (`wait_ready.sh:102` `curl -fsSL http://…:8080/` succeeds → no forced HTTPS redirect), but Phase 1 confirms `config.xml <system><webgui><protocol>` and the exact login form (`__csrf_magic`, `usernamefld`/`passwordfld`, session cookie) against the **live** login page.
5. **Only one smoke image exists today** (pfSense CE, GHCR by digest). The version axis is built **parametric** and run against that one image now; additional images (Plus / other CE) are a later IMAGE_RUNBOOK effort (B1).
6. **Default `pytest` must stay untouched.** UI tests reuse the smoke fixtures and are excluded from default collection exactly as smoke is (markers + the existing ignore), so `python -m pytest` remains byte-identical.

---

## 2. Decision

Add a **tiered Web-UI test harness on the ADR-04 smoke VM**, reusing the `smoke_vm` fixture and `helpers.py`, driven by **authenticated HTTP for breadth** and a **headless browser for JS-only UX + screenshots**, wired into PRs (cheap tier, blocking), a daily/on-demand schedule (heavy tier), and the release pipeline (full suite, re-runnable per leg).

| Area | Decision |
| --- | --- |
| **Tier A — render-smoke** | **Authenticated HTTP** (`requests` + `__csrf_magic` login). GET **every** pfBlockerNG page (the 18 + widget + DNSBL VIP pages) → assert **200**, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a **page-specific marker** present, **and** the on-box `php_error.log` gained no new lines during the sweep. Hermetic, fast. Marker `ui_render`. **Runs per-PR when PHP/JS files change; blocking.** |
| **Tier B — functional (HTTP)** | A curated set of **CSRF POST** flows (save General; add/save an IP feed/alias; toggle a DNSBL setting) → assert the **effective state** via `helpers.config_get`/`pfctl`/unbound, not the HTTP response. Marker `ui_e2e`. Daily/on-demand. |
| **Tier B — browser** | **Headless Playwright/Chromium** against `:8080`, reusing the auth session (inject the session cookie into the browser context to avoid a second login flake). Exercises the **JS-only** behaviours (`enable_change_*`, `pfb_autocomplete*`, `pfb_chg_state_bkgd`, the dashboard widget) and **captures per-page screenshots** uploaded as artifacts. Marker `ui_browser`. Daily/on-demand. **The flaky/heavy tier — gated by the §7 reliability threshold.** |
| **Screenshots (A1)** | **Browser tier only** (HTTP can't screenshot). Tier A stays pure-HTTP/screenshot-less; on failure it captures the page body + `php_error.log` into the diagnostics artifact. |
| **Test home** | `tests/smoke/ui/` subpackage, reusing `tests/smoke/conftest.py` `smoke_vm` + `helpers.py`. Excluded from default collection like the smoke suite → `python -m pytest` unchanged. |
| **Oracle (fact 3)** | Body-content + page-marker + on-box `php_error.log` (Tier A); effective `config.xml`/`pfctl`/unbound (Tier B). **Never** HTTP 200 alone. |
| **Workflows (matrix B1)** | A **reusable** `ui-tests.yml` (`workflow_call` + `workflow_dispatch` + `schedule`), parametric on **image-ref/version** (matrix axis built, single CE image run now) and **tier** (input). Builds the branch `.pkg` via the existing Linux builder, boots the image, runs the selected tier. |
| **Re-run granularity (C1)** | **One GH job per (tier × version)** so "re-run failed jobs" re-runs only the flaky leg. **No silent auto-retry on assertions**; a **bounded retry only on infra steps** (boot/login). Screenshots + logs uploaded `if: always()`. |
| **PR gate (3a)** | Tier A runs on PRs touching `src/**/*.php`, `*.inc`, `src/**/*.js`; folded into the **"All tests passed"** aggregate so `release.yml`'s `verify-checks` already covers it. Blocking. |
| **Release gate (D1)** | `release.yml` `needs:` the reusable UI workflow (Tier A + Tier B) **before** `release`/`ports-pr`, each leg a separate job → the full suite gates a release, but a not-our-fault flake re-runs **in isolation** without redoing the release. |

### Semantics that MUST be preserved (the contract — pin with tests before relying on them)

- **Default suite untouched.** `python -m pytest` is byte-identical (UI excluded from default collection); the smoke suite (`-m smoke`) still passes unchanged.
- **No `src/` change.** This ADR adds tests + CI only; the shipped package (PHP/Python/JS/shell) is not modified.
- **Real oracle.** A page that renders a PHP `Warning`/`Notice`/`Fatal`, returns non-200, or leaves a blank body **fails** — a bare 200 is never a pass (fact 3, pinned in Phase 2 with a deliberately-broken-page check).
- **Auth session is reusable + correct.** Login via the live CSRF form; an authenticated GET returns the page; an **unauthenticated** GET redirects to login (pinned in Phase 1).
- **Hermetic where it claims to be.** Tier A asserts pure rendering and must not require feed downloads; any page that triggers network is either kept out of Tier A or runs with egress as the smoke harness already allows.
- **Isolation.** Each (tier × version) leg is an independent job; a failure in one neither blocks nor masks the others, and is re-runnable alone.

### Explicitly kept / out of scope

- **Visual / pixel-diff / accessibility (a11y) regression** — out (1c). Most page chrome is pfSense-core, not ours; high maintenance, low ROI. Screenshots are **artifacts for human review**, not asserted pixel baselines.
- **A standalone (non-VM) PHP-server harness** — out (fact 2); the pages need the pfSense runtime.
- **Building a second pfSense image (Plus / other CE)** — out for v1 (B1); the matrix axis is built but runs the single existing CE image. New images are a separate IMAGE_RUNBOOK effort.
- **`src/` refactors to make pages more testable** — out; behaviour-preserving test infra only.
- **Silent auto-retry of UI assertions** (`pytest-rerunfailures` on the checks) — out (C1); it masks real flake. Retry is confined to infra setup (boot/login).
- **Cross-browser (Firefox/WebKit) matrix** — out for v1; one headless Chromium.

---

## 3. Consequences

**Positive**

- Catches the class of regression `php -l`/PHPStan structurally cannot: runtime PHP errors/warnings, 500s, blank pages, and broken form persistence — on a **real** pfSense box, before release.
- **Tiered cost:** the cheap HTTP render-smoke gates PRs without browser flake; the heavy browser + screenshot pass runs daily/on-demand and never blocks fast iteration.
- **Reuses existing infra** (`smoke_vm`, `helpers.py`, the Linux `.pkg` build, the diagnostics artifact) → small new surface, consistent operational model.
- **Screenshots-as-artifacts** give a human a fast visual diff across versions without a brittle pixel baseline.
- **Release-gated + re-runnable per leg** → the full suite protects a release while a not-our-fault flake costs one job re-run, not a full pipeline.
- Tiers A + B-HTTP have **standalone value** and are retained even if the browser tier is rejected (mirrors ADR-01's retained prep phases).

**Negative / risks**

- **Browser E2E over SLIRP-QEMU is flaky/slow** — the core risk. Mitigated: gated behind a §7 reliability threshold; cookie-injected sessions; no fixed sleeps (poll readiness); per-leg re-run; demote-or-drop on failure (§7).
- **Per-PR VM boot cost.** Tier A boots a pfSense VM (~smoke-job cost) on every PHP-touching PR. Mitigated: `paths`-gated, image cache (content-keyed), single fast tier.
- **No automated oracle for the PHP itself** (it only runs in pfSense) → screenshot/visual correctness needs a **human**; encoded as a manual smoke step (§7).
- **Oracle false-confidence** if it checks only 200. Mitigated: body + marker + on-box `php_error.log`, pinned against a deliberately-broken page (Phase 2).
- **Version matrix is structural, not yet real** (one image). Mitigated: documented (B1); adding images is a known IMAGE_RUNBOOK task.
- **New test deps** (`requests`, Playwright + browser download) on the runner. Mitigated: dev-only (`tests/smoke/requirements.txt`), cached; never shipped.

---

## 4. Requirements (acceptance)

1. **Default suite unchanged:** `python -m pytest` byte-identical; `pytest -m smoke` still green.
2. **Auth works:** the harness logs into the live webConfigurator via CSRF; an authenticated GET returns the page; an unauthenticated GET redirects to login.
3. **Tier A render-smoke:** every pfBlockerNG page returns 200 with no PHP error/warning in body **and** no new `php_error.log` line, with a page-specific marker present; a deliberately-broken page is **caught** (proves the oracle).
4. **Tier B functional:** the curated CSRF-POST flows change the **effective** `config.xml`/`pfctl`/unbound state as asserted (not just the HTTP response).
5. **Tier B browser:** the JS-only behaviours are exercised and per-page **screenshots** are produced and uploaded as artifacts.
6. **Workflows:** a reusable `ui-tests.yml` is matrix-parametric (image-ref/version) and tier-selectable; one job per (tier × version); diagnostics (screenshots + logs) uploaded `if: always()`.
7. **PR gate:** Tier A runs on PRs touching PHP/JS and is part of the "All tests passed" aggregate (blocking).
8. **Release gate:** `release.yml` runs the UI suite before publishing, each leg re-runnable in isolation.
9. **Lint-clean:** `ruff check`/`ruff format` clean on the new Python; `shellcheck` clean on any new shell; YAML valid.

---

## 5. Constraints (from `CLAUDE.md`)

- **Python:** 4-space indent, 3.11+, type hints on new functions, no bare `except`. Ruff is the canonical linter; keep `.flake8` in sync if config changes. Non-stdlib test deps go in `tests/smoke/requirements.txt` (dev-only), never in `pfb_unbound.py`.
- **No `src/` change** — the shipped PHP/Python/JS/shell are untouched; this is test/CI infra.
- **Shell:** any helper is POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean.
- **Investigation rigor:** confirm the WebUI protocol, login form, and creds against the **live** box + `config.xml` (source of truth), not assumption; assert effective state via the tool/CLI, not a single generated artifact (fact 3/4).
- **Smoke-harness truths still apply** (ADR-04): probe on-box where relevant, content-keyed image cache, `smoke_vm` is session-scoped, diagnostics uploaded on failure.
- Commit style `<scope>: <imperative summary>`; **work in this ADR's `adr/14` worktree (reuse it across phases; create it off the latest `origin/devel` if absent), one commit per phase**; `git fetch` + rebase onto the latest `origin/devel` before every push; the ADR lands on `devel` via a **rebase-only PR** (never a merge); PR bodies via `--body-file`. Promote `devel`→`main` by rebase/replay + `--force-with-lease` (two-tier linear `main←devel`; `next` retired 2026-06-04).
- **Docs:** README/CLAUDE.md updated when the harness lands (final phase) — tiers, markers, how to run locally, the matrix axis, the IMAGE_RUNBOOK note.

---

## 6. Action plan

Each phase = one commit, leaves `python -m pytest` **byte-identical/green** and the tree lint-clean. The **cheap, hermetic tiers land first** (Phases 1–2, standalone value); the **flaky/heavy browser tier (Phase 4) lands behind the §7 reliability gate**; workflows + release wiring close it out.

### Phase 1 — PREP (behaviour-preserving): authenticated WebUI session helper + recon

Prompt: `01_Auth_Session_Prep.txt`

- Reuse `smoke_vm`. Build a reusable `webui` helper (under `tests/smoke/ui/`): CSRF login (`__csrf_magic`, `usernamefld`/`passwordfld`), session-cookie persistence, an authenticated `get(path)`. **RECON & PIN (don't assume, fact 4):** confirm the webConfigurator protocol (`config.xml <system><webgui><protocol>`), the exact login form/cookie names against the **live** login page, and the creds source (baked `SMOKE_ADMIN_PASSWORD`). Pin with a `ui_render`-marked test: login succeeds; an authenticated GET of a known page returns 200 + marker; an **unauthenticated** GET redirects to login. Add `requests` to `tests/smoke/requirements.txt`. **No `src/` change; default suite untouched.**

### Phase 2 — Tier A: HTTP render-smoke sweep (all pages) + the real oracle

Prompt: `02_Render_Smoke_Tier_A.txt`

- Enumerate every pfBlockerNG page (18 + widget + DNSBL VIP). Parametrized `ui_render` test: authenticated GET → 200, body free of `Fatal error`/`Parse error`/`Warning`/`Notice`/`Uncaught`, a **page-specific marker** present, **and** no new `php_error.log` line during the sweep (read on-box via `SmokeVM.ssh`). **Prove the oracle**: a deliberately-broken probe (e.g. a page known to warn, or an injected check) must FAIL the assertion — a bare 200 is never a pass. Standalone-valuable cheap tier.

### Phase 3 — Tier B (functional, HTTP-POST): drive forms, assert effective state

Prompt: `03_Functional_HTTP_Tier_B.txt`

- A curated set of `ui_e2e` flows via CSRF POST: save General settings; add/save an IP feed or alias; toggle a DNSBL setting. After each, assert the **effective** state via `helpers.config_get` (+ `pfctl`/unbound where relevant), **not** the HTTP response. Establishes the functional oracle before any browser code.

### Phase 4 — Tier B (browser): Playwright layer + screenshots (gated by §7)

Prompt: `04_Browser_Screenshots_Tier_B.txt`

- Headless Chromium against `:8080`, reusing the Phase-1 session (inject the cookie into the browser context). Exercise the **JS-only** behaviours (`enable_change_*`, `pfb_autocomplete*`, `pfb_chg_state_bkgd`, the dashboard widget) and capture **per-page screenshots** to an artifact dir. Marker `ui_browser`. Add Playwright to `tests/smoke/requirements.txt`. **Measure the §7 reliability/budget numbers here** — if the browser tier can't hit the threshold, record it and apply the demote/drop decision (the cheap tiers already shipped).

### Phase 5 — Workflows: reusable, matrix-parametric, tiered triggers, diagnostics

Prompt: `05_Workflows_Matrix_Tiers.txt`

- A reusable `ui-tests.yml` (`workflow_call` + `workflow_dispatch` + `schedule`), parametric on image-ref/version (matrix axis built, single CE image run now) and tier (input); builds the branch `.pkg` via `build-pkg-linux.yml`, boots the image, runs the selected tier. **One job per (tier × version)** (C1); **no auto-retry on assertions**, bounded retry only on boot/login; screenshots + logs uploaded `if: always()` (extend the `smoke-diagnostics` pattern). Wire **Tier A** into the per-PR path gated on `paths` (PHP/JS) and into the "All tests passed" aggregate (blocking, 3a); **Tier B** on `schedule` (daily-if-commits) + `workflow_dispatch`.

### Phase 6 — Release integration + docs + manual smoke + DoD

Prompt: `06_Release_Integration_Docs_DoD.txt`

- D1: make `release.yml` `needs:` the reusable UI workflow (Tier A + Tier B) before `release`/`ports-pr`, each leg a separate job re-runnable in isolation. Update README/CLAUDE.md (tiers, markers, local-run, the version-matrix axis + IMAGE_RUNBOOK note). Finalise §7 manual smoke + the explicit reject/pivot criteria; set Status accordingly after the maintainer confirms.

---

## 7. Definition of done

**Done in-repo (all six phases landed on `adr/14`; statically verified on the dev box):**

- `python -m pytest` **byte-identical at 1019** (UI excluded from default collection like smoke); new Python ruff-clean; new shell ShellCheck-clean; all touched YAML parses.
- The harness + the three tiers are implemented under `tests/smoke/ui/` (markers `ui_render`/`ui_e2e`/`ui_browser`), reusing `smoke_vm` + `helpers.py`. The render oracle is **body + page-marker + on-box `php_error.log`** (never 200 alone), pinned by a unit `render_oracle` suite that proves a known-broken page is caught. The browser tier injects the Phase-1 `PHPSESSID` cookie (no second login) and writes per-page screenshots to a git-ignored artifact dir.
- The reusable `ui-tests.yml` (`workflow_call` + `workflow_dispatch` + daily `schedule`) is matrix-parametric (image-ref/version) and tier-selectable, **one GH job per (tier × version)** with `fail-fast: false`, diagnostics uploaded `if: always()`. **Tier A** gates PHP/JS PRs (folded into the **"All tests passed"** aggregate, blocking). **Tier B** is schedule/dispatch only (non-PR-blocking by construction).
- **Release gate (D1):** `release.yml` `needs:` the full UI suite (`tier: all`, the `ui-suite` job) **before** `release`/`ports-pr`, **alongside** the existing `verify-checks` (which is unchanged — the PR-time aggregate gate is not weakened). Because each (tier × version) leg is a distinct job, a single flaky leg is re-runnable in isolation and **does not redo** `release`/`ports-pr` (those run only once all `needs:` are `success`).

**Outstanding — the maintainer's Accept criteria (live box / CI; cannot run on the dev box):**

- Tier A render-smoke passes **on the live VM** with the real oracle, and the deliberately-broken probe is caught there.
- Tier B functional flows change the asserted **effective** state on the live VM; Tier B browser produces per-page screenshots as artifacts (`ui-diagnostics-<tier>-<version>`).
- The **§7 browser reliability numbers** are measured in CI (procedure below) and meet the threshold — **or** the one-line demote/drop switch is applied. These numbers are **CI-pending** (Phase 4 did not fabricate them; the live VM exists only in CI).
- The maintainer completes the **manual smoke** below and reviews the screenshot artifacts.

Status flips **Proposed → Implemented (pending smoke test)** with this phase (2026-06-04); it flips to **Accepted** only after the maintainer confirms the manual smoke + screenshot review on a live pfSense box.

### Reject / pivot criteria (the ADR-01-analog kill gate — decide on evidence)

The browser tier is **already non-PR-blocking by construction** (marker `ui_browser`,
off default collection, schedule/dispatch only — Phase 4 §6) — so it can never block
fast iteration regardless of the outcome below. Its §7 reliability numbers are
**CI-pending** (the live VM exists only in CI; Phase 4 deliberately fabricated no
numbers). The shipped posture: gate the release on **Tier A + Tier B-functional
firmly** and **include the browser leg** in the release `ui-suite` as a separate,
isolated, re-runnable leg; apply the demote/drop on the **first CI evidence** if it
misses the bar.

- **Browser tier too flaky/slow:** if the first CI runs can't reach **≥ 4/5 clean**
  at **≤ ~25 min** per matrix leg (mirroring ADR-04's "≤ ~20 min AND ≥ 4/5"),
  **demote** it out of the gates with the **one-line switch** (Phase-5/6 wiring):
  drop `browser` from `DEFAULT_SCHEDULE_TIERS` in `ui-tests.yml` (kills the nightly
  browser leg) **and** run the release `ui-suite` as `tier: functional` instead of
  `tier: all` (drops it from the release gate). It stays **dispatch-only** — the test
  code is untouched. If even on-demand it can't be made reliable, **drop** the browser
  layer (deselect `-m ui_browser` everywhere, or delete the leg). Either way only the
  screenshots/JS coverage are lost; **Tiers A + B-HTTP retain standalone value and
  ship** (the render + form oracles remain).

  **Measurement procedure (maintainer/CI):** dispatch the `ui_browser` leg via
  `ui-tests.yml` (one job per tier × version) **≥ 5 times** against the CE image;
  record per run CLEAN (all `ui_browser` tests passed, no infra abort) vs total and
  the leg's wall time; compare to the **≥ 4/5 clean AND ≤ ~25 min** bar; record the
  result + the decision back into `RESULTS/04_Results.txt` (replacing its CI-pending
  block) and apply the switch above if it misses.
- **Oracle can't be made meaningful:** if rendered PHP warnings can't be reliably detected (body + `php_error.log` both miss them) such that Tier A passes a known-broken page → the render tier is not trustworthy; pivot to a narrower, log-only oracle or reconsider the tier.
- **Tier A too heavy for PRs:** if the per-PR VM boot + render sweep can't fit a sane budget (≤ ~15 min) reliably, demote Tier A to daily/on-demand (drop the PR gate by removing `ui-render` from `test.yml`'s aggregate `needs:` + its result case); the cheaper checks still run pre-release.

### Manual smoke (owner: maintainer) — required before Accept

> CI can assert rendering/state but not *visual* correctness or true cross-version UX. Confirm on a live pfSense box / via the artifacts.

- [ ] **Tier A green on the live VM.** Dispatch `ui-tests.yml` `tier=render` (or push a PHP/JS PR) → the `ui_render` sweep passes on the CE image with the real oracle (body + marker + `php_error.log`), and the `ui-diagnostics-render-<version>` artifact is present.
- [ ] **Screenshot review.** Dispatch `ui-tests.yml` `tier=browser`, pull the `ui-diagnostics-browser-<version>` artifact; every pfBlockerNG page renders correctly (no broken layout, missing fields, or stray PHP output) — eyeball across `<version>/<page>.png`.
- [ ] **Functional reality.** A settings change made through the real GUI persists and takes effect (matches what `ui_e2e` asserts) — spot-check General + one IP feed + one DNSBL toggle.
- [ ] **JS UX.** The field enable/disable toggles, autocomplete, and the dashboard widget behave in a real browser as the `ui_browser` tier drives them.
- [ ] **Flake reality / §7 numbers.** Run the browser leg **≥ 5×** (the §7 measurement procedure); confirm **≥ 4/5 clean AND ≤ ~25 min/leg**, OR apply the one-line demote/drop switch. Record the measured numbers into `RESULTS/04_Results.txt`.
- [ ] **Release dry-run.** A tag/release dry-run runs the full UI suite first (the `ui-suite` job → one leg per tier × version); confirm `release`/`ports-pr` wait on every leg, and a **forced single-leg failure is re-runnable in isolation** ("Re-run failed jobs") **without** redoing `release`/`ports-pr`.
- [ ] **Multi-version (when a 2nd image exists).** Append the label to `DEFAULT_VERSIONS` + wire its ref; the matrix runs green against the added pfSense image with no harness change beyond the image ref.
