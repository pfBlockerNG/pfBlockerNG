# ADR-20: CE/Plus variant-aware pkg distribution

> **Amendment (2026-06-14, PR #216):** `add-repo.sh devel` and `add-repo.sh stable` now both
> write the shared `/usr/local/etc/pkg/repos/pfblockerng.conf` (repo `pfblockerng`) — one
> catalog carrying both packages, Netgate-style — superseding the `pfblockerng-devel.conf`
> references below; only `nightly` keeps its own conf. The single-Worker-URL decision (one
> conf, written once, User-Agent routing) is unchanged — only the repo/conf **name** collapsed.
>
> **Amendment (2026-06-15) — routing layer NOT live; §4/§7 acceptance unmet.** The
> catalog/Worker/test *code* (Phases 2–5) landed and unit-tested, but `pfBlockerNG/pkg`'s
> `publish.yml` was never wired to build the variant-keyed catalogs or to generate/deploy
> `routing.json`. So `pfblockerng.github.io/pkg/routing.json` 404s and the Worker returns
> `502 "Routing manifest unavailable"` — the self-hosted **Worker install path is
> non-functional** (the Netgate ports channel is unaffected). The proving smoke (Case 4) was
> left a non-failing `xfail`, which masked the gap in CI. Tracked completion: stamp the
> variant into manifests (#242) → generator variant bucketing → `publish.yml` routing.json +
> variant catalogs → Worker nightly-prefix fix + `wrangler deploy`, then un-`xfail` Case 4.

- **Status:** **Accepted (code) — routing rework landed, awaiting live deploy** (code accepted
  2026-06-10; routing rework B1–B3 landed 2026-06-15, see the amendment + the routing-completion
  handoff). The matrix-driven builder/tree/`routing.json` (B1), the matrix-driven `publish.yml`
  (B2), and the Worker rewrite (B3) are implemented + unit-tested. §4/§7's *"routing.json live with
  active CE+Plus routes"* is unmet until the maintainer runs `publish.yml` (publishes the variant
  tree + `routing.json` to Pages) and `wrangler deploy`s the Worker, then un-`xfail`s Case 4.
- **Date:** 2026-06-09
- **Branch:** `adr/20-ce-plus-variant-distribution` (off **`devel`**; `{slug}` =
  sanitised ADR-title slug per CLAUDE.md "Branch naming") / **Component(s):**
  dev-only distribution/CI — `ci-metadata` orphan branch (`supported-versions.json`
  `variant` + `status` fields); `scripts/build-pkg-portable.py` (variant-aware manifest
  deps); `scripts/build-repo-portable.py` + `pfBlockerNG/pkg publish.yml`
  (version-keyed catalog dirs + routing manifest); `scripts/add-repo.sh` (writes
  single Worker URL — conf written once); routing manifest
  (`pfblockerng.github.io/pkg/routing.json`); Cloudflare Worker (code ships in
  `pfBlockerNG/pkg` repo, deployed via `wrangler deploy` in `publish.yml`).
  **Supersedes:** ADR-17's single-ABI catalog model (§1.4 "one conf per channel +
  `${ABI}`" and §4 repo URL structure). **No shipped (`src/`) code changes** — this is
  distribution-only, like ADR-17/18. ADR-19 (Proposed) consumes this infrastructure
  once live.
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

10. **Legacy builds are a desired capability.** When a pfSense version reaches EOL
    (Netgate drops support), pfBlockerNG should retain the last-built catalog on
    Pages so existing users on that version can still install/upgrade pfBlockerNG at
    their own pace. No new pfBlockerNG builds are made for EOL versions. Current
    examples of what will become legacy once superseded: CE 2.7.x (FreeBSD 14) and
    Plus 25.11.x. These catalogs are retained in the version-keyed layout with
    `"status": "legacy"` in the routing manifest; they are pruned after a grace period
    once Netgate's own EOL notice is final.

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

Split the catalog into **version-keyed directories** (`ce-2.8/`, `ce-2.9/`,
`plus-26.03/`, `plus-26.07/`, etc.) under the existing Pages URL, one dir per
active pfSense version. Use a **dynamic routing layer** (Cloudflare Worker + routing
manifest `routing.json`) as the primary mechanism: the client conf is written once
with a single Worker URL, never changes on pfSense upgrade. Update `add-repo.sh`
to write this Worker URL; the fallback (Phase-1 REJECT only) is local version
detection writing a direct GitHub Pages URL. Keep the **meta-package option**
explicitly open as a deferred complement.

| Area | Decision |
|---|---|
| **Catalog structure** | Version-keyed directories: `pfblockerng.github.io/pkg/ce-2.8/${ABI}/`, `.../ce-2.9/${ABI}/`, `.../plus-26.03/${ABI}/`, `.../plus-26.07/${ABI}/`, etc. One top-level dir per active pfSense version; ABI subdirs inside (pkg still uses `${ABI}` within the path). Nightly likewise: `.../nightly/ce-2.8/${ABI}/` etc. Legacy catalogs (`ce-2.7/`, `plus-25.11/`) retained on Pages with no new builds (§1.10). The existing `pfblockerng.github.io/pkg/${ABI}/` path (ADR-17 CE-only) is retained during transition and deprecated once Phase 6 smoke is green. |
| **Routing manifest** | `routing.json` deployed at `pfblockerng.github.io/pkg/routing.json` by the publish pipeline. Schema: `{"routes": [{"pattern": "pfSense/2.8", "catalog": "ce-2.8", "status": "active"}, {"pattern": "Netgate pfSense Plus/26.03", "catalog": "plus-26.03", "status": "active"}, {"pattern": "pfSense/2.7", "catalog": "ce-2.7", "status": "legacy"}, ...]}`. The Worker fetches and edge-caches this manifest (5 min TTL). Adding a new pfSense version = add an entry to the manifest; no Worker redeploy needed. Legacy entries are pruned from the manifest after the grace period (§1.10). |
| **Manifest deps** | `build-pkg-portable.py` reads PHP and Python dep names from the `ci-metadata` entry for the target variant (`php_version` → `phpNN`, `py_flavor` → `pyNNN-*`). Separate `.pkg` per variant per ABI. No shared package between CE and Plus. |
| **`ci-metadata`** | Add `"variant": "CE"/"Plus"` and `"status": "active"/"legacy"` to each entry in `supported-versions.json`. The matrix may hold N CE + M Plus entries simultaneously (N, M ≥ 1) during transition windows. `read-version-matrix.sh` gains a `--variant` filter returning ALL matching `active` entries. The build pipeline iterates all active entries per variant; legacy entries remain as routing targets only, not build targets. |
| **Dynamic routing (primary)** | Stateless Cloudflare Worker at a canonical URL (e.g. `pkg.pfblockerng.io`). Fetches `routing.json` (edge-cached 5 min), matches the incoming `User-Agent` against route `pattern` prefixes, 302-redirects to `pfblockerng.github.io/pkg/<catalog>/<ABI>/...`. Worker code ships in `pfBlockerNG/pkg` repo; deployed via `wrangler deploy` in `publish.yml`. Adding/retiring a pfSense version = edit `routing.json` only, no Worker redeploy. **Conditioned on Phase-1 kill-gate** — if UA is stripped, this row is dropped. |
| **`add-repo.sh` (primary conf)** | Writes single Worker URL: `url: "https://pkg.pfblockerng.io/${ABI}"`. No variant, no pfSense version in the conf. Conf written once on first install; **never needs re-running on pfSense upgrades** (Worker reroutes automatically based on the new UA). Channel (`devel`/`stable`/`nightly`) remains the only user argument. |
| **`add-repo.sh` (fallback — Phase-1 REJECT only)** | If Phase 1 returns REJECT (UA stripped), detect the pfSense version locally: read `/etc/version` (e.g. `2.8.1` → major.minor `2.8`) and check `globals.plus.inc` for CE vs Plus. Construct the versioned catalog name (e.g. `ce-2.8`) and write a direct static URL `pfblockerng.github.io/pkg/ce-2.8/${ABI}`. This URL is version-specific — users must re-run `add-repo.sh` after a major pfSense upgrade. |
| **Meta-package (deferred, open)** | A `pfblockerng-repo` companion package whose `+POST_INSTALL` calls `add-repo.sh` for the current variant + channel is **not built in this ADR** but is explicitly deferred rather than rejected. Its post-install would run on every `pkg upgrade pfBlockerNG`, refreshing the conf after a CE→Plus migration. Pre-decided mechanism: same `globals.plus.inc` detection, same `add-repo.sh` call. Pick up after Phase 6 if the dynamic routing layer proves operationally costly. |
| **Failure mode (wrong-variant conf)** | A stale CE conf on a Plus box: `pkg upgrade` hits the Worker → Worker reads Plus UA → routes to `plus-26.03/${ABI}/` → Plus package returned → correct `php85` dep satisfied. No error, fully transparent. Worker down → 5xx → `pkg` error, no silent wrong install. routing.json unreachable → Worker 500 → `pkg` error. All failure modes are clean errors, never silent. |
| **CE→Plus migration path** | With dynamic routing (Phase-1 GO): transparent. Worker reads the new Plus UA and routes to the Plus catalog automatically — no conf change needed. Without (Phase-1 REJECT): `pkg upgrade` hits a version-specific CE URL → CE package returned → dep error if PHP version differs → user re-runs `add-repo.sh` (one manual step). |

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
- **Conf written once, never changes on pfSense upgrade.** With the Worker URL in the
  conf, a user who runs `add-repo.sh` once gets automatic routing to the correct
  catalog on every future pfSense version bump — no re-run of `add-repo.sh` needed,
  no conf staleness, no manual step after an OS upgrade. This is the primary UX win.
- **CE→Plus migration is transparent.** With dynamic routing, the Worker reads the
  new Plus UA and routes to the Plus catalog automatically — no conf update required.
- **Routing table is dynamic.** Adding a new pfSense version (e.g. CE 2.9.x) = add
  one entry to `routing.json`. No Worker redeploy. No CI pipeline change. The conf
  on every existing client immediately starts routing to the new version.
- **`add-repo.sh` requires only the channel arg** — variant and version are handled
  automatically (Worker URL primary; local detection fallback).
- **Legacy builds retained** for EOL versions, providing a graceful off-ramp for
  users who cannot upgrade their pfSense version immediately.
- **Meta-package path is kept open** without committing to build it now.

**Negative / risks**

- **Phase-1 kill-gate may kill the dynamic routing approach.** If the UA is stripped
  by Fastly/Cloudflare in the CDN path, the primary mechanism is dropped and the
  fallback (version-specific static URL in `add-repo.sh`) becomes the only defense.
  The CE→Plus migration then degrades to a safe manual step (re-run `add-repo.sh`);
  the conf-written-once UX win is lost.
- **Cloudflare Worker introduces operational dependency.** Free tier (100 k req/day),
  stateless, no KV store — but it is infrastructure outside this repo. Its failure
  mode is a 5xx on pkg fetch; pkg retries and eventually times out; the user sees a
  pkg error, not a silent wrong install. A down routing layer does not corrupt the
  installation.
- **routing.json unavailable → Worker fails loudly.** If `pfblockerng.github.io` is
  down, the Worker cannot fetch routing.json → 500 → pkg error. The Worker is a thin
  proxy; all catalog state is on Pages. Acceptable: no silent wrong install.
- **Catalog transition requires a deprecation window.** The old `${ABI}` path must
  stay live until all existing clients have had their confs refreshed (by re-running
  `add-repo.sh`). ADR-19's "Bootstrap repo" button is the in-GUI path for this.
- **Cross-repo publish complexity increases.** `pfBlockerNG/pkg publish.yml` must
  build version-keyed dirs, generate `routing.json`, and deploy the Worker. The
  pure-Python pipeline handles the catalog (no libpkg); the Worker is deployed by
  `wrangler deploy` (Node.js tool) in the same workflow.

---

## 4. Requirements (acceptance)

- `ci-metadata` has `"variant"` (`CE`/`Plus`) and `"status"` (`active`/`legacy`)
  fields on each entry; `read-version-matrix.sh` filters by variant, returning only
  `active` entries as build targets.
- A CE build has `php83` (and `py311` or the current CE Python) in the manifest dep
  list; a Plus build has `php85` (and the current Plus Python). A Plus box attempting
  to install the CE package fails with an unsatisfied dep error (pinned by a test).
- Version-keyed catalog dirs (`ce-2.8/${ABI}/`, `plus-26.03/${ABI}/`, etc.) exist on
  Pages. Each contains only packages for that pfSense version+variant. The legacy
  `${ABI}/` path (ADR-17) is retained during the transition window.
- `routing.json` is deployed at `pfblockerng.github.io/pkg/routing.json` with at least
  one `active` CE entry and one `active` Plus entry. The Worker resolves UA patterns
  to catalog dirs using this manifest.
- `add-repo.sh` writes the single Worker URL (`pkg.pfblockerng.io/${ABI}`) with only
  the channel as a user argument; no variant or pfSense version required.
- (Conditioned on Phase-1 pass) The Worker correctly routes CE and Plus `pkg` requests
  to version-keyed catalog dirs, confirmed by live fetches from CE and Plus boxes.
  Updating `routing.json` to add a new pfSense version requires no Worker redeploy.
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

### Phase 2 — `ci-metadata` variant + status fields + variant-aware manifest generation

- **Prompt:** `02_Variant_Matrix_And_Manifests.txt`
- Add `"variant": "CE"/"Plus"` and `"status": "active"` to `supported-versions.json`
  on `ci-metadata`; update `read-version-matrix.sh` and the composite action to support
  `--variant` filtering (returns only `active` entries) and expose `variant` in outputs.
  PR against `ci-metadata`.
- Extend `build-pkg-portable.py` with `--variant CE|Plus`: resolve PHP dep as
  `php{php_version_nodot}` (e.g. `83` → `php83`) and Python dep as `{py_flavor}-*`
  from the matrix entry. Add `--variant` to the build invocation in
  `build-pkg-linux.yml`. Emit separate `.pkg` per variant per FreeBSD major.
- **Tests:** extend `tests/test_build_pkg_portable.py` — CE manifest contains `php83`
  dep, lacks `php85`; Plus manifest contains `php85` dep, lacks `php83`. Assert
  before-state (no `--variant` → old behaviour) and after-state per variant. Run on
  both the current CE entry and the Plus entry from `ci-metadata`.

### Phase 3 — Version-keyed catalog dirs + routing manifest

- **Prompt:** `03_Variant_Catalog_Structure.txt`
- Extend `build-repo-portable.py` to accept `--catalog-name ce-2.8` (explicit
  version-keyed name) and generate catalogs under `<outdir>/<catalog-name>/${ABI}/`.
  Also generate `routing.json` from the active entries in `ci-metadata` (or from an
  explicit `--routing-entries` JSON arg). Retain the legacy `${ABI}/` path pointing
  at the CE build during the transition.
- Update `pfBlockerNG/pkg publish.yml` to build all active version-keyed dirs, generate
  `routing.json`, and deploy all subtrees (version-keyed + legacy ABI path) in a
  single Pages deploy action.
- **Tests:** extend `tests/test_build_repo_portable.py` — assert `ce-2.8/${ABI}/meta.conf`
  exists with only CE packages; assert `plus-26.03/${ABI}/meta.conf` with only Plus
  packages; assert legacy `${ABI}/meta.conf` still exists; assert `routing.json`
  contains the expected route entries with correct catalog names and statuses.

### Phase 4 — `add-repo.sh` single Worker URL + fallback

- **Prompt:** `04_Client_Bootstrap.txt`
- **Primary (Phase-1 GO):** `add-repo.sh` writes the single Worker URL:
  `url: "https://pkg.pfblockerng.io/${ABI}"`. No variant, no version in the conf.
  Channel (`devel`/`stable`/`nightly`) is the only argument. Conf written once, never
  re-run on pfSense upgrades. Update the conf template in `build-repo.sh --print-conf`.
- **Fallback (Phase-1 REJECT only):** detect pfSense version from `/etc/version` +
  `globals.plus.inc`; construct catalog name (e.g. `ce-2.8`); write
  `url: "https://pfblockerng.github.io/pkg/ce-2.8/${ABI}"`. Document that users must
  re-run `add-repo.sh` after a major pfSense upgrade when using this fallback path.
- **Tests:** extend `tests/test_add_repo_conf.py` — Worker URL written by default
  (primary); fallback path writes version-specific URL on Phase-1-REJECT simulation;
  assert mutual exclusion and before-state.

### Phase 5 — Dynamic routing layer (Worker + routing.json)

- **Prompt:** `05_Dynamic_Routing_Layer.txt`
- **Conditioned on Phase-1 GO for `USER_AGENT_VISIBLE`.** If Phase 1 returned REJECT,
  skip this phase; record in handoff; fallback static URL from Phase 4 is the only mechanism.
- Deploy a Cloudflare Worker at `pkg.pfblockerng.io` that: fetches `routing.json` from
  Pages (edge-cached 5 min TTL), matches the `User-Agent` prefix against route
  `pattern` fields, 302-redirects to `pfblockerng.github.io/pkg/<catalog>/<ABI>/...`.
  Worker code ships in `pfBlockerNG/pkg` repo (`infra/worker/`); deployed by
  `wrangler deploy` in `publish.yml` on each release. **No Worker redeploy needed when
  a new pfSense version is added** — update `routing.json` only.
  Worker logic is stateless, no KV; failure mode: routing.json fetch fails → 500 →
  pkg error, never silent.
- Update `add-repo.sh` to write the Worker URL as the primary conf (superseding Phase 4).
- Smoke-verify from CE and Plus boxes: `pkg update` with the Worker URL returns the
  correct version-keyed `meta.conf`; assert route is re-evaluated when `routing.json`
  is updated (simulate by updating the manifest and waiting for cache TTL).
- If Cloudflare Worker proves impractical, document an alternative (nginx, Netlify)
  with the same logic; decision recorded in `05_Results.txt`.

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
  (not `php83`); version-keyed catalog dirs (`ce-2.8/${ABI}/`, `plus-26.03/${ABI}/`)
  contain only their variant's packages; `routing.json` has correct entries + statuses;
  `add-repo.sh` writes Worker URL (primary) and version-specific fallback URL; wrong-
  variant install fails dep check.
- The `repo`-marked live-VM smoke is GREEN on CE (capture run id). Plus smoke is
  completed manually by the maintainer and recorded in `07_Results.txt`.
- The legacy `${ABI}/` path is still live and serving the CE build at DoD (transition
  window not yet closed).
- `routing.json` is live at `pfblockerng.github.io/pkg/routing.json` with at least one
  active CE and one active Plus route.

### Manual smoke checklist (owner: maintainer — what CI cannot cover)

1. On a **Plus 26.x** box with `add-repo.sh devel` run: confirm the conf contains
   the Worker URL, `pkg update` succeeds, `pkg rquery` returns the Plus build version,
   `php85` dep is satisfied.
2. On a **CE 2.8.x** box: run `add-repo.sh devel`; confirm Worker URL in conf; confirm
   `pkg install pfBlockerNG-devel` fetches from the Worker URL and installs the CE
   build with `php83` satisfied.
3. On a **CE→Plus migration** box (CE conf surviving the upgrade, Phase-5 live): confirm
   `pkg upgrade` routes to the Plus catalog automatically — no conf update needed.
4. With the **routing layer down** (Phase 5 only): pkg fetch returns a 5xx; no
   package is installed or corrupted; the error is visible to the user.
5. The **legacy `${ABI}/` path** still serves the CE package and `pkg upgrade` on an
   old-conf CE box succeeds (transition window verification).
6. Update `routing.json` to add a new fictitious route entry; confirm the Worker
   picks it up within the cache TTL (≤5 min) without a Worker redeploy.

### Reject / redesign criteria

- **REJECT dynamic routing** (Phase 1) if `User-Agent` is absent or replaced by a
  CDN string in the actual network path → Phase 5 is skipped; version-specific static
  URL fallback from Phase 4 is the sole mechanism; conf-written-once UX win is lost;
  meta-package option elevated to next-ADR scope.
- **REJECT variant manifest split** if a shared manifest (without PHP/Python deps
  declared, relying on pfSense shipping them) is confirmed sufficient — i.e. the
  package installs correctly without declaring `php83`/`php85` as deps. Validate on
  both CE and Plus before assuming shared manifests are safe.
- **STOP Phase 3** if `build-repo-portable.py` cannot cleanly accept a
  `--catalog-name` / explicit routing entries without restructuring — redesign the
  generator interface before proceeding.
- **STOP Phase 5** if `wrangler deploy` cannot be integrated cleanly into
  `pfBlockerNG/pkg publish.yml` (auth, token scope, or Node.js toolchain constraints)
  — document the blocker in `05_Results.txt` and fall back to Phase 4's static URL.

---

## Amendment (2026-06-10): nightly channel CE/Plus variant split

**All three channels (stable, devel, nightly) carry a CE/Plus variant split.**
This was implicit in the catalog-structure decision above ("Nightly likewise:
`.../nightly/ce-2.8/${ABI}/`…") but the implementation details were not spelled out.

### How stable and devel work (no channel prefix in path)

Both `stable` and `devel` write the Worker URL without any path prefix:

```text
url: "https://pkg.pfblockerng.workers.dev/${ABI}"
```

- `add-repo.sh devel` → conf `pfblockerng-devel.conf`, `URL_SUBPATH=""`
  → URL: `https://pkg.pfblockerng.workers.dev/${ABI}`
- `add-repo.sh stable` → conf `pfblockerng.conf`, `URL_SUBPATH=""`
  → URL: `https://pkg.pfblockerng.workers.dev/${ABI}`

The Worker receives a request like `/FreeBSD:15:amd64/packagesite.pkg`, reads the
`User-Agent`, finds the catalog (`ce-2.8` or `plus-26.03`), and redirects to:

```text
pfblockerng.github.io/pkg/ce-2.8/FreeBSD:15:amd64/packagesite.pkg
```

Channel distinction lives entirely in the **package name** and **repo conf name**,
never in the catalog URL. Both channels coexist in the same variant-keyed catalog dir.

### How nightly works (nightly/ prefix in path)

`add-repo.sh nightly` → conf `pfblockerng-nightly.conf`, `URL_SUBPATH="nightly/"`
→ URL: `https://pkg.pfblockerng.workers.dev/nightly/${ABI}`

The Worker receives `/nightly/FreeBSD:15:amd64/packagesite.pkg`. Without special
handling it would produce the wrong target (prepending `ce-2.8` before the `nightly/`
segment). The Worker must strip the channel prefix before routing.

### Worker path-stripping for nightly

The Cloudflare Worker must detect the `/nightly/` path prefix and strip it before
constructing the redirect target:

```javascript
// Strip channel prefix (nightly) so catalog + ABI path are constructed correctly.
let channelPrefix = '';
let abiPath = url.pathname;
const m = url.pathname.match(/^\/(nightly)\//);
if (m) {
    channelPrefix = m[1] + '/';                    // "nightly/"
    abiPath = url.pathname.slice(m[0].length - 1); // strip prefix, keep leading /
}
// route.catalog = "ce-2.8" or "plus-26.03" (routing.json has no channel knowledge)
const target = `https://pfblockerng.github.io/pkg/${channelPrefix}${route.catalog}${abiPath}`;
```

Result for a nightly CE box (`pfSense/2.8.1` UA, ABI `FreeBSD:15:amd64`):

```text
/nightly/FreeBSD:15:amd64/packagesite.pkg
  channelPrefix="nightly/"  abiPath="/FreeBSD:15:amd64/packagesite.pkg"
  → pfblockerng.github.io/pkg/nightly/ce-2.8/FreeBSD:15:amd64/packagesite.pkg
```

`routing.json` remains channel-agnostic — catalog names are `"ce-2.8"`,
`"plus-26.03"` with no `"nightly/"` prefix. The channel prefix is a path concern
handled at the Worker edge.

### `catalog_name_from_version` API extension

`catalog_name_from_version(pfsense_version, variant, *, channel="")` gains an
optional keyword-only `channel` argument. When supplied (e.g. `channel="nightly"`),
the returned string is prefixed: `"nightly/ce-2.8"`. `build_repo(catalog_name=)`
already accepts slash-containing strings, placing the ABI subtree under
`<out>/nightly/ce-2.8/<ABI>/`.

### Test coverage (added in same commit)

- `test_catalog_name_from_version_nightly` — nightly prefix for CE and Plus; no-channel
  unchanged; patch stripping with nightly.
- `test_nightly_catalog_under_versioned_subdir` — CE nightly build lands at
  `nightly/ce-2.8/<ABI>/`; release path and legacy root untouched.
- `test_nightly_plus_catalog_under_versioned_subdir` — CE + Plus nightly coexist under
  `nightly/`; no cross-contamination between the two variant dirs.
