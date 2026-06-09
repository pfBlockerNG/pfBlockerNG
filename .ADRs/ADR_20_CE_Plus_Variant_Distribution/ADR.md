# ADR-20: CE/Plus variant-aware pkg distribution

- **Status:** **Proposed** (2026-06-09)
- **Date:** 2026-06-09
- **Branch:** `adr/20-ce-plus-variant-distribution` (off **`devel`**; `{slug}` =
  sanitised ADR-title slug per CLAUDE.md "Branch naming") / **Component(s):**
  dev-only distribution/CI — `ci-metadata` orphan branch (`supported-versions.json`
  variant field); `scripts/build-pkg-portable.py` (variant-aware manifest deps);
  `scripts/build-repo-portable.py` + `pfBlockerNG/pkg publish.yml` (two-variant
  catalog subtrees); `scripts/add-repo.sh` (CE/Plus auto-detection); a new dynamic
  routing layer (primary: Cloudflare Worker or equivalent). **Supersedes:** ADR-17's
  single-ABI catalog model (§1.4 "one conf per channel + `${ABI}`" and §4 repo URL
  structure). **No shipped (`src/`) code changes** — this is distribution-only, like
  ADR-17/18. ADR-19 (Proposed) consumes this infrastructure once live.
- **Target runtime:** GitHub Actions `ubuntu-latest` — same pure-Python pipeline as
  ADR-17/18 (`build-pkg-portable.py`, `build-repo-portable.py`). Client side: pfSense
  CE 2.8+ (`FreeBSD:15:amd64`, `pkg` 1.21+) and pfSense Plus 26.x+
  (`FreeBSD:16:amd64`, `pkg` 2.5.1+). Routing layer: stateless edge function
  (Cloudflare Worker primary; fallback evaluated in Phase 5).
- **Test suite:** unit cases extend `tests/test_build_pkg_portable.py` (default
  `python -m pytest`); live-VM cases extend `tests/smoke/test_repo_install.py`
  (ADR-17 `repo` marker, deselected from `-m smoke`). **Default `python -m pytest`
  stays unchanged.**

---

## 1. Context

### Today (verified by live probe on CE 2.8.1 + Plus 26.03.1, 2026-06-09)

All facts in this section are from `scripts/probe-pfsense-env.sh` output unless
noted. Fields are cited as they appear in the probe output.

1. **CE and Plus use the SAME `product_name` — the assumed path discriminator does
   not exist.** Both systems report `product_name: pfSense`; both have
   `/usr/local/etc/pfSense/pkg/repos/` with the same structure. `product_label`
   differs (`pfSense` vs `Netgate pfSense Plus`) but is not used in filesystem paths.
   A `/usr/local/etc/pfSense Plus/` directory does **not** exist on Plus. The earlier
   hypothesis that `product_name` differs between variants is **falsified**.

2. **`${ABI}` is a FreeBSD-version discriminator, not a variant discriminator.**
   CE 2.8.1 → `FreeBSD:15:amd64`; Plus 26.03.1 → `FreeBSD:16:amd64`. These differ
   *today* because CE 2.8.x is on FreeBSD 15 and Plus 26.x is on FreeBSD 16. When CE
   2.9.x ships on FreeBSD 16 (plus-RELENG branch confirms CE 2.9.0 targets FreeBSD 16),
   both CE and Plus will share `FreeBSD:16:amd64`. All pkg URL variables (`${ABI}`,
   `${OSNAME}`, `${RELEASE}`, `${VERSION_MAJOR}`, `${VERSION_MINOR}`, `${OSVERSION}`,
   `${ARCH}`) are FreeBSD-derived; **none encode CE vs Plus**.

3. **`HTTP_USER_AGENT` is the reliable server-side discriminator.** pfSense injects
   `HTTP_USER_AGENT` into the pkg environment (`pkg_env()`,
   `src/etc/inc/pkg-utils.inc`), overriding pkg's default `pkg/VERSION` UA for ALL
   repo fetches including third-party repos. Probe-confirmed values:
   - CE 2.8.1: `pfSense/2.8.1-RELEASE:<uniqueid>`
   - Plus 26.03.1: `Netgate pfSense Plus/26.03.1-RELEASE:<uniqueid>`
   The token `Plus` appears in the Plus UA and is absent in CE. A server reading the
   `User-Agent` header can distinguish them on every request. **Unproven in CI**:
   whether this header survives the HTTPS/CDN path to a GitHub Pages-backed server
   is the Phase-1 kill-gate.

4. **`globals.plus.inc` is the reliable local (on-box) discriminator.** CE 2.8.1:
   `globals.plus.inc: ABSENT`. Plus 26.03.1: `globals.plus.inc: EXISTS`. The file is
   conditionally included by `globals.inc` line ~907 (`can_include('globals.plus.inc')`)
   and is a Plus-only file not in the public CE mirror. **`add-repo.sh` can read this
   to auto-detect the variant** without user input.

5. **PHP version differs; Python version is the same today but is not guaranteed to
   stay so.** Probe-confirmed: CE 2.8.1 uses `php83`; Plus 26.03.1 uses `php85`.
   Both use `py311` today. A package built with `php83` as a manifest dep will fail to
   install on Plus (`php83` is not installed); the reverse likewise. Python may diverge
   on future versions. **Manifests must declare the variant-correct dep names** — PHP
   and Python both — injected at build time from `ci-metadata`.

6. **ADR-17 built a single-variant (CE-only in practice) repo.** The catalog at
   `pfblockerng.github.io/pkg/${ABI}` contains only packages built for the CE FreeBSD
   ABI. Plus users on a different FreeBSD ABI would be served a CE-ABI package (wrong
   PHP dep), and when CE and Plus converge on the same FreeBSD ABI the catalog would
   be structurally ambiguous — one `${ABI}` path, two incompatible manifests possible.

7. **Up to N CE + M Plus entries can be active simultaneously (N, M ≥ 1).**
   During a version-transition window — e.g. when the next CE pre-release is public
   while the previous CE is still Netgate-supported — the `ci-metadata` matrix holds
   two CE entries (old FreeBSD 15 + new FreeBSD 16) alongside one or two Plus entries.
   The worst-case overlap is four active entries: CE 2.8.x (FreeBSD 15, php83), CE 2.9.x
   (FreeBSD 16, php?), Plus 26.x (FreeBSD 16, php85), Plus 26.07 (FreeBSD 16, php?).
   The catalog structure (`ce/${ABI}/`, `plus/${ABI}/`) handles this transparently — each
   (channel, FreeBSD-major) pair becomes a distinct subtree — and the routing layer is
   unaffected (it discriminates CE vs Plus only; the ABI is already in the request URL).
   The current active pair confirmed by probe:
   CE 2.8.1 / FreeBSD 15 / php83 / py311 and Plus 26.03.1 / FreeBSD 16 / php85 / py311.

8. **`pfSense.conf` in `/usr/local/etc/pkg/repos/` is a symlink on both systems.**
   It symlinks to `/usr/local/etc/pfSense/pkg/repos/pfSense-repo-0000.conf` on both
   CE and Plus. Our conf (`pfblockerng-devel.conf` etc.) is a peer file in
   `/usr/local/etc/pkg/repos/` and is independent of the pfSense-managed symlink.
   `pfSense-repo-setup -U` regenerates only the `pfSense` conf, never ours.

9. **CE→Plus migration is a full pfSense reinstall; the pkg conf may or may not
   survive.** Netgate's upgrade process removes third-party packages before the base
   upgrade and reinstalls them from the new repo after. If our conf survives the
   upgrade, a CE conf on a Plus system will produce a dep-mismatch error on `pkg
   upgrade` (safe failure, not silent). If it doesn't survive, the user must re-run
   `add-repo.sh` (one-time manual step). The dynamic routing layer (§2) eliminates
   the need for the conf to be variant-correct, because the server routes regardless.

### Premise to falsify cheaply (the ADR-01 guard)

The load-bearing premise is **§1.3 — does the pfSense-injected `User-Agent` header
reach a server** behind HTTPS/CDN as-is, or does the CDN strip/replace it? GitHub
Pages is behind Fastly; a Cloudflare Worker sits in front. The UA is a standard HTTP
request header, not a special extension, so there is no known reason for it to be
stripped — but this is **unverified in the actual network path** and must be confirmed
before Phase 5 is built.

**Phase-1 kill-gate:** a minimal HTTPS endpoint (e.g. a Cloudflare Worker that logs
`request.headers.get('User-Agent')`, or a `requestbin`-style service) is hit by
`pkg update` from both a CE and a Plus box. If the User-Agent is absent or replaced
by a Fastly/Cloudflare generic string, the dynamic routing approach is **rejected**
and the fallback is static variant URLs written by `add-repo.sh` + the meta-package
option (§2 "Meta-package").

The local discriminator (`globals.plus.inc`) is already verified by the probe and
requires no live network test.

---

## 2. Decision

Split the catalog into **two variant subtrees** (`ce/` and `plus/`) under the
existing Pages URL. Use a **dynamic routing layer** as the primary mechanism to
serve the correct variant without requiring the client conf to encode CE vs Plus.
Update `add-repo.sh` to auto-detect and write a static variant URL as the fallback.
Keep the **meta-package option** explicitly open as a deferred complement.

| Area | Decision |
|---|---|
| **Catalog structure** | Two subtrees: `pfblockerng.github.io/pkg/ce/${ABI}/` and `.../plus/${ABI}/`. Nightly likewise: `.../nightly/ce/${ABI}/` and `.../nightly/plus/${ABI}/`. The existing `pfblockerng.github.io/pkg/${ABI}/` path (ADR-17 CE-only) is retained during transition and deprecated once Phase 6 smoke is green. |
| **Manifest deps** | `build-pkg-portable.py` reads PHP and Python dep names from the `ci-metadata` entry for the target variant (`php_version` → `phpNN`, `py_flavor` → `pyNNN-*`). Separate `.pkg` per variant per ABI. No shared package between CE and Plus. |
| **`ci-metadata`** | Add `"variant": "CE"` or `"variant": "Plus"` to each entry in `supported-versions.json`. The matrix may hold N CE + M Plus entries simultaneously (N, M ≥ 1) during transition windows. `read-version-matrix.sh` and the composite action gain a `--variant` filter that returns ALL matching entries, not just one. The build pipeline iterates all active entries per variant. |
| **Dynamic routing (primary)** | A stateless edge function (Cloudflare Worker) at a canonical URL (e.g. `pkg.pfblockerng.io/${ABI}/...`) reads the `User-Agent` header, detects `Plus` → proxies/redirects to `plus/${ABI}/...`; else → `ce/${ABI}/...`. Single URL in the conf; CE→Plus migration is transparent even with a stale conf. **Conditioned on Phase-1 kill-gate** — if UA is stripped, this is dropped. |
| **`add-repo.sh` (fallback)** | Adds CE/Plus auto-detection: check `globals.plus.inc` existence → `VARIANT=plus` else `VARIANT=ce`. Writes static URL `pfblockerng.github.io/pkg/${VARIANT}/${ABI}`. Works independently of the routing layer; is the authoritative bootstrap even when the routing layer is live (sets the correct URL from the start, avoiding a redirect round-trip on every fetch). |
| **Meta-package (deferred, open)** | A `pfblockerng-repo` companion package whose `+POST_INSTALL` calls `add-repo.sh` for the current variant + channel is **not built in this ADR** but is explicitly deferred rather than rejected. Its post-install would run on every `pkg upgrade pfBlockerNG`, refreshing the conf after a CE→Plus migration. Pre-decided mechanism: same `globals.plus.inc` detection, same `add-repo.sh` call. Pick up after Phase 6 if the dynamic routing layer proves operationally costly. |
| **Failure mode (wrong-variant conf)** | A CE conf on a Plus system → `pkg upgrade` requests the CE catalog → server routes to `ce/` (dynamic) → CE package returned → `php83` dep not satisfied on Plus box → clean error, no silent wrong install. Same in reverse. Both are safe; neither corrupts the installation. |
| **CE→Plus migration path** | With dynamic routing: transparent (server routes regardless of conf variant). Without: `pkg upgrade` fails with dep error → user re-runs `add-repo.sh` (one manual step). Either outcome is acceptable. |

### Semantics that MUST be preserved (the contract)

- **ADR-17's install precedence is unchanged.** Our `priority: 100` over Netgate's
  `pfSense` repo (priority 0) still governs install selection. The variant split adds
  a routing layer above the catalog; it does not change how `pkg` selects packages
  from competing repos.
- **The CE 2.8.x package (FreeBSD 15 + php83) continues to install correctly on CE
  boxes** throughout the transition. The existing `pfblockerng.github.io/pkg/${ABI}`
  path is retained (serves the CE build) until the new `ce/${ABI}` path is smoke-green
  and confs are updated.
- **A wrong-variant package must never silently install.** The dep mismatch (php83
  on Plus, php85 on CE) is the natural guard; it must be demonstrated by a test.
- **Default `python -m pytest` is unchanged.** Smoke tree stays `--ignore`d.

### Explicitly kept / out of scope

- **Signed catalogs** — out; ADR-17's `signature_type: none` (TLS-anchored) is
  inherited for both variant subtrees.
- **CE→Plus in-place switch** — out; pfSense's own upgrade process removes packages
  first. The routing layer makes migration transparent at the pkg fetch level; package
  reinstall is still the user's responsibility after an OS upgrade.
- **Meta-package implementation** — deferred (see §2 "Meta-package"), not in scope
  for this ADR's phases. The design is pre-decided; pick up separately.
- **ADR-19 update panel** — that ADR consumes this infrastructure. Its Phase-1
  kill-gate validates reading from the variant-correct repo; this ADR's Phase-6 smoke
  validates the catalog is correct. Neither ADR modifies the other's phases.

---

## 3. Consequences

**Positive**

- **Correct packages for both CE and Plus.** A Plus user gets a `php85`-dep package;
  a CE user gets `php83`. The dep mismatch guard prevents silent wrong installs.
- **CE→Plus upgrade path handled at the server.** With dynamic routing, a CE conf on a
  Plus box gets routed to the Plus catalog automatically — no conf staleness problem.
- **`add-repo.sh` auto-detects variant** — no user input required beyond the channel
  (stable/devel/nightly). The `globals.plus.inc` check is already verified reliable.
- **One-CE-one-Plus constraint simplifies the matrix** to two build targets. No matrix
  fan-out; the pipeline is leaner than ADR-17's multi-version model.
- **Meta-package path is kept open** without committing to build it now.

**Negative / risks**

- **Phase-1 kill-gate may kill the dynamic routing approach.** If the UA is stripped
  by Fastly/Cloudflare in the CDN path, the primary mechanism is dropped and the
  fallback (static variant URL in `add-repo.sh`) becomes the only defense against
  wrong-variant fetches. The CE→Plus migration then degrades to a safe manual step.
- **Cloudflare Worker introduces operational dependency.** Free tier, stateless, no
  KV store — but it is infrastructure outside the repo. Its failure mode is a 502/503
  on pkg fetch; pkg retries and eventually times out; the user sees a pkg error, not a
  silent wrong install. A down routing layer does not corrupt the installation.
- **Catalog transition requires a deprecation window.** The old `${ABI}` path must
  stay live until all existing clients have had their confs refreshed (by re-running
  `add-repo.sh`). ADR-19's "Bootstrap repo" button is the in-GUI path for this.
- **Cross-repo publish complexity increases.** `pfBlockerNG/pkg publish.yml` must
  build and stage two variant subtrees per channel. The pure-Python pipeline handles
  this (no libpkg); complexity is in the workflow YAML, not the generator logic.

---

## 4. Requirements (acceptance)

- `ci-metadata` has a `variant` field on each entry; `read-version-matrix.sh` filters
  by variant.
- A CE build has `php83` (and `py311` or the current CE Python) in the manifest dep
  list; a Plus build has `php85` (and the current Plus Python). A Plus box attempting
  to install the CE package fails with an unsatisfied dep error (pinned by a test).
- The catalog at `ce/${ABI}/` serves CE packages; `plus/${ABI}/` serves Plus packages.
  The legacy `${ABI}/` path serves the CE build during the transition window.
- `add-repo.sh` detects CE vs Plus via `globals.plus.inc` without user input and
  writes the variant-correct static URL.
- (Conditioned on Phase-1 pass) The dynamic routing layer correctly routes CE and Plus
  `pkg` requests to their respective variant subtrees, confirmed by a live fetch from
  both a CE and a Plus box.
- The `repo`-marked live-VM smoke is green for the CE path; Plus smoke documented as
  a maintainer-run manual check (no licensed Plus CI image).
- Default `python -m pytest` green; `ruff`/`mypy` clean.

---

## 5. Constraints (from CLAUDE.md)

- Pure Python, stdlib only in `build-pkg-portable.py` and `build-repo-portable.py`;
  no libpkg on the Linux runner.
- POSIX `sh` for `add-repo.sh`; quote all expansions; no bash-isms.
- `ci-metadata` changes require a PR against the `ci-metadata` orphan branch
  (branch-protected per CLAUDE.md "Updating documentation").
- `pfBlockerNG/pkg publish.yml` lives in the separate `pfBlockerNG/pkg` repo; changes
  there follow that repo's own PR flow. Cross-repo auth via the existing GitHub App
  (`PKG_GITHUB_APP_ID` / `PKG_GITHUB_APP_PRIVATE_KEY`).
- Worktree + **rebase-only PR** for any change touching `tests/`, `scripts/`, or CI
  YAML (not the ADR-docs carve-out).
- **Tests must validate, not merely cover** — wrong-variant install must fail; assert
  before-state (no `ce/` catalog) and after-state (CE package at `ce/${ABI}`) by value.
- ShellCheck clean for `add-repo.sh` changes; `sh -n` syntax check on all `.sh` files
  touched.

---

## 6. Action plan

### Phase 1 — KILL-GATE: User-Agent discrimination + local detection

- **Prompt:** `01_Kill_Gate_UA_And_Detection.txt`
- Prove the two premises before any build pipeline work:
  (a) The pfSense-injected `User-Agent` (`pfSense/...` CE, `Netgate pfSense Plus/...`
  Plus) reaches a server behind HTTPS — deploy a minimal logging endpoint (Cloudflare
  Worker that logs `request.headers.get('User-Agent')` to console, or equivalent),
  hit it via `pkg update` from CE and Plus boxes, and read the Worker logs.
  (b) `globals.plus.inc` EXISTS on Plus and ABSENT on CE (already confirmed by probe
  — record in `01_Results.txt` as GO, no further verification needed).
  Record `USER_AGENT_VISIBLE: GO/REJECT` in `RESULTS/01_Results.txt`. **REJECT dynamic
  routing** if UA is absent or replaced by a CDN string; proceed to Phase 5 with
  static-URL-only design and note the meta-package as the CE→Plus fallback. **If GO,
  all phases proceed as written.**
- **No code changes** — this is a pure verification phase. No commit.

### Phase 2 — `ci-metadata` variant field + variant-aware manifest generation

- **Prompt:** `02_Variant_Matrix_And_Manifests.txt`
- Add `"variant": "CE"` / `"variant": "Plus"` to `supported-versions.json` on
  `ci-metadata`; update `read-version-matrix.sh` and the composite action to support
  `--variant` filtering and expose `variant` in outputs. PR against `ci-metadata`.
- Extend `build-pkg-portable.py` with `--variant CE|Plus`: resolve PHP dep as
  `php{php_version_nodot}` (e.g. `83` → `php83`) and Python dep as `{py_flavor}-*`
  from the matrix entry. Add `--variant` to the build invocation in
  `build-pkg-linux.yml`. Emit separate `.pkg` per variant per FreeBSD major.
- **Tests:** extend `tests/test_build_pkg_portable.py` — CE manifest contains `php83`
  dep, lacks `php85`; Plus manifest contains `php85` dep, lacks `php83`. Assert
  before-state (no `--variant` → old behaviour) and after-state per variant. Run on
  both the current CE entry and the Plus entry from `ci-metadata`.

### Phase 3 — Variant catalog subtrees in the publish pipeline

- **Prompt:** `03_Variant_Catalog_Structure.txt`
- Extend `build-repo-portable.py` to accept `--variant CE|Plus` and generate catalogs
  under `ce/${ABI}/` or `plus/${ABI}/` (and `nightly/ce/`, `nightly/plus/`).
  Retain the legacy `${ABI}/` path pointing at the CE build during the transition.
- Update `pfBlockerNG/pkg publish.yml` to run the generator twice (once per variant)
  and deploy both subtrees in a single Pages deploy action. The existing `repo-publish`
  job in this repo triggers the `pfBlockerNG/pkg` workflow; pass the variant context
  via dispatch inputs.
- **Tests:** extend `tests/test_build_repo_portable.py` — assert `ce/${ABI}/meta.conf`
  exists and its packagesite contains only the CE package; assert `plus/${ABI}/meta.conf`
  contains only the Plus package; assert the legacy `${ABI}/meta.conf` still exists
  with the CE build (transition window).

### Phase 4 — `add-repo.sh` CE/Plus auto-detection + static variant URL

- **Prompt:** `04_Client_Bootstrap.txt`
- Add variant detection to `add-repo.sh`: `if [ -f /etc/inc/globals.plus.inc ]; then
  VARIANT=plus; else VARIANT=ce; fi`. Write the conf URL as
  `https://pfblockerng.github.io/pkg/${VARIANT}/${ABI}` (static, no routing layer
  dependency). Remove the need for a user-supplied variant argument — channel
  (stable/devel/nightly) remains the only argument.
- Update the conf template in `build-repo.sh --print-conf` to match. Run ShellCheck;
  assert the written conf contains `ce/` on a mock CE environment and `plus/` on a
  mock Plus environment (by stubbing the `globals.plus.inc` path in the test).
- **Tests:** extend `tests/test_add_repo_conf.py` — CE detection writes `ce/` URL;
  Plus detection writes `plus/` URL; the two are mutually exclusive (before: wrong URL
  written, after: correct URL, proving the detection works).

### Phase 5 — Dynamic routing layer

- **Prompt:** `05_Dynamic_Routing_Layer.txt`
- **Conditioned on Phase-1 GO for `USER_AGENT_VISIBLE`.** If Phase 1 returned REJECT,
  skip this phase; record in handoff; static URL from Phase 4 is the only mechanism.
- Deploy a Cloudflare Worker at a canonical URL (e.g. `pkg.pfblockerng.io`) that:
  reads `User-Agent`, detects `Plus` string → proxies/redirects to
  `pfblockerng.github.io/pkg/plus/${ABI}/...`; else → `.../ce/${ABI}/...`. The
  `${ABI}` is already present in the incoming request URL (expanded client-side).
  Worker logic is stateless, no KV; failure mode is 502 → pkg error, never silent.
- Smoke-verify from CE and Plus boxes: `pkg update` with the routing URL returns the
  variant-correct `meta.conf` (assert package name and deps in the catalog).
- If Cloudflare Worker proves impractical, document alternative (nginx on a small VM,
  GitHub Actions Pages redirect via `_redirects`, or Netlify) with the same UA-header
  logic; decision recorded in `05_Results.txt`.

### Phase 6 — Smoke: CE and Plus installs from variant repos

- **Prompt:** `06_Smoke_CE_Plus.txt`
- Live-VM `repo`-marked cases in `tests/smoke/test_repo_install.py`:
  - CE (ADR-04 VM): install from `ce/${ABI}` → `pkg query %d` confirms `php83` dep
    satisfied; assert before (installed from legacy `${ABI}`) and after (reinstalled
    from `ce/${ABI}`) — same package, correct dep.
  - Wrong-variant guard (CE VM): configure `plus/${ABI}` repo; attempt install;
    assert failure with unsatisfied `php85` dep (before: no error from CE repo; after:
    dep error from Plus repo).
  - Plus (maintainer manual, no licensed CI image): equivalent checks on a Plus box;
    document in §7 manual smoke checklist.
- Assert the legacy `${ABI}/` path still serves the CE build (transition period).

### Phase 7 — Docs + DoD

- **Prompt:** `07_Docs_DoD.txt`
- Update `README.md`: new `add-repo.sh` invocation (no variant arg), routing layer
  URL, transition note for existing CE users.
- Update `scripts/README.md` (if exists) and `add-repo.sh` header comment.
- Set deprecation timeline for the legacy `${ABI}/` path (e.g. one release cycle after
  all new confs use `ce/`).
- Notify ADR-19 team: variant-correct `<ourrepo>` name for `pkg rquery` is now
  `pfblockerng-ce-devel` or `pfblockerng-plus-devel` (Phase 4 conf name includes
  variant); ADR-19 Phase-1 kill-gate must test against the variant-correct repo.
- Fill §7 DoD.

---

## 7. Definition of done

- Phases 2–4 merged to `devel` via rebase-only PRs (and to `ci-metadata` for Phase 2).
  Phase 5 merged if Phase-1 GO; skipped with note if Phase-1 REJECT.
- `python -m pytest`, `ruff`, `mypy tests/`, ShellCheck, `sh -n` all green on each PR.
- Unit tests cover: CE manifest has `php83` (not `php85`); Plus manifest has `php85`
  (not `php83`); CE detection writes `ce/` URL; Plus detection writes `plus/` URL;
  catalog at `ce/${ABI}/` contains CE package; catalog at `plus/${ABI}/` contains Plus
  package; wrong-variant install fails dep check.
- The `repo`-marked live-VM smoke is GREEN on CE (capture run id). Plus smoke is
  completed manually by the maintainer and recorded in `07_Results.txt`.
- The legacy `${ABI}/` path is still live and serving the CE build at DoD (transition
  window not yet closed).

### Manual smoke checklist (owner: maintainer — what CI cannot cover)

1. On a **Plus 26.x** box with `add-repo.sh devel` run: confirm the conf contains
   `plus/${ABI}`, `pkg update` succeeds, `pkg rquery` returns the Plus build version,
   `php85` dep is satisfied.
2. On a **CE→Plus migration** box (CE conf surviving the upgrade): confirm `pkg upgrade`
   either (a) routes correctly via the dynamic layer to the Plus catalog (if Phase 5
   live), or (b) fails with a clean `php83` unsatisfied dep error and recovers after
   re-running `add-repo.sh`.
3. With the **routing layer down** (Phase 5 only): pkg fetch returns a 5xx; no
   package is installed or corrupted; the error is visible to the user.
4. The **legacy `${ABI}/` path** still serves the CE package and `pkg upgrade` on an
   old-conf CE box succeeds (transition window verification).

### Reject / redesign criteria

- **REJECT dynamic routing** (Phase 1) if `User-Agent` is absent or replaced by a
  CDN string in the actual network path → Phase 5 is skipped; static variant URL from
  Phase 4 is the sole mechanism; meta-package option elevated to next-ADR scope.
- **REJECT variant manifest split** if a shared manifest (without PHP/Python deps
  declared, relying on pfSense shipping them) is confirmed sufficient — i.e. the
  package installs correctly without declaring `php83`/`php85` as deps. Validate on
  both CE and Plus before assuming shared manifests are safe.
- **STOP Phase 3** if the `pfBlockerNG/pkg publish.yml` cross-repo dispatch cannot
  convey variant context cleanly — redesign the dispatch interface before proceeding.
