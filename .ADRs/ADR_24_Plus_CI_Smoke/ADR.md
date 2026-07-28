# ADR-24: pfSense Plus in the CI smoke fan-out

- **Status:** **Accepted** (2026-06-15; proposed 2026-06-12). All phases are live on `devel`
  and `ci-metadata`: the matrix carries the Plus entry (`channel: "Plus"`, `ci: true`,
  `image_name: "pfsense-plus"`); `smoke.yml` / `smoke-fanout.yml` / `build-pkg-linux.yml` are
  Plus-aware (per-leg `image_name` + ABI/PHP, `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID`
  secrets), and the Plus-leg diagnostics redaction shipped (`RESULTS/diag_redaction_Results.txt`).
  The maintainer confirms the Plus leg runs in the CI fan-out; the §7 manual checklist is
  retained as reference and any deviation is handled as a **bug**, not an Accept blocker.
- **Date:** 2026-06-12
- **Branch:** `adr/24-pfsense-plus-in-the-ci-smoke` (off `devel`); matrix flip via PR
  against `ci-metadata`
- **Component(s):**
  `tests/smoke/boot_vm.sh`, `tests/smoke/conftest.py`,
  `scripts/read-version-matrix.sh`, `.github/actions/read-version-matrix/`,
  `.github/workflows/smoke.yml`, `.github/workflows/smoke-fanout.yml`,
  `supported-versions.json` + `supported-versions.schema.json` (on `ci-metadata`),
  docs (`CLAUDE.md`, `scripts/README.md`)
- **Target runtime:** GitHub Actions ubuntu-latest (QEMU/KVM); POSIX sh; jq
- **Test suite:** `tests/` (pytest), live legs via `smoke-fanout.yml`

## 1. Context

### 1.1 Today — Plus is structurally excluded from CI

The supported-version matrix (`supported-versions.json`, `ci-metadata` orphan branch)
carries a Plus entry (`26.03`, FreeBSD 16, PHP 8.5) with `ci: false`, and the exclusion
is enforced in **three** independent places:

1. `scripts/read-version-matrix.sh:123` — the CI matrix is
   `select(.ci == true and .channel == "CE")`; a Plus entry can never appear in
   `ci_matrix` even with `ci: true`.
2. `.github/workflows/smoke-fanout.yml` "Count legs + assert no Plus entries" — a hard
   PLUS GUARD fails the run if any entry has `channel != "CE"` or `ci != true`.
3. The matrix's own `lifecycle_policy.plus` text: "Plus entries are always ci=false …
   never run Plus in CI — licensing."

The original reason was the **absence of a licensed Plus CI image**. That reason is
ending: a maintainer-owned licensed Plus qcow2 (Proxmox VM 104) is being published to
**private** GHCR as `ghcr.io/pfblockerng/pfsense-plus:26.03` via
`scripts/image-publish.sh` (see `scripts/README.md` § "pfSense Plus images").

### 1.2 Today — single-image assumptions in the harness

- **Image name:** `smoke.yml` composes the pull ref from the repo-level
  `SMOKE_IMAGE_NAME` variable (default `pfsense-ce`) + the per-leg `pfsense_version`
  tag (`smoke.yml:144–161`). One name for all legs — no per-leg image name exists.
  `smoke-fanout.yml` passes only `pfsense_version` to the callee.
- **MAC address:** `tests/smoke/boot_vm.sh:37` hardcodes `VM_MAC="BC:24:11:37:9C:AC"`
  (the CE source-VM pin; pfSense matches interface assignment by MAC — a different MAC
  drops the boot to the interface-reassignment console). `scripts/image-upgrade.sh`
  defaults the same pin but already has `--mac`. `conftest.py` boots exclusively via
  `boot_vm.sh` (`tests/smoke/conftest.py:60`), so the harness has exactly one MAC plumb
  point.
- **The Plus VM identity (MAC + SMBIOS uuid) is license-critical and SECRET:** the
  Plus license/NDI registration is keyed to BOTH the source-VM MAC and its SMBIOS
  type-1 uuid (the Netgate Device ID is derived from MAC + uuid). Every boot of the
  Plus image MUST use them, and they differ from the CE pins. Because they identify a
  licensed instance, they are held in the **`SMOKE_PLUS_MAC` + `SMOKE_PLUS_SMBIOS_UUID`
  GitHub secrets** (optionally `SMOKE_PLUS_NDI`), NEVER the public `ci-metadata` matrix.
- **GHCR auth:** `smoke.yml` already logs in (`SMOKE_GHCR_USER`/`TOKEN` secrets,
  falling back to `github.actor`/`GITHUB_TOKEN`, `smoke.yml:176–181`) — pulling a
  private package needs only the package granting this repo read access; no new
  secret.
- **Deps are baked, `pkg add` runs offline** (CLAUDE.md "Smoke tests"): the CE image
  bakes RUN_DEPENDS via `scripts/misc/install_deps_CE_2.8.sh`. A Plus image must bake
  the FreeBSD-16 equivalents — at image-prep time, on the appliance; CI never reaches
  Netgate's subscription-gated Plus pkg repo.

### 1.3 Load-bearing constraints

- **The Plus image must remain PRIVATE** (Netgate-licensed). CI may pull it; nothing
  may republish, attach, or expose it. `smoke.yml` uploads a `smoke-diagnostics`
  artifact (logs + scrubbed `config.xml`) on every run — scrubbing must also cover
  Plus license identifiers (NDI/token) before any Plus leg runs.
- The fan-out's AND-gate (`all-smoke-passed`) semantics must be preserved: any leg
  red → gate red; zero legs → red.
- `pfsense_version` doubles as the GHCR tag (CE `2.8`; Plus `26.03` works
  identically — `YY.MM` is a valid tag).
- The qcow2 carries no MAC; MAC is a boot-time QEMU argument. Publishing is
  MAC-agnostic; only the run path needs plumbing.

## 2. Decision

Plus becomes a first-class CI smoke leg. The matrix entry is the source of truth for
the per-leg **image name** (public); the per-leg **VM identity** (MAC + SMBIOS uuid)
is license/NDI-keyed and therefore comes from **GitHub secrets**, never the public
matrix. The harness defaults stay CE so every change before the final matrix flip is
behaviour-preserving.

### 2.1 Decision table

| Area | Current | New |
| ---- | ------- | --- |
| `boot_vm.sh` MAC | hardcoded `BC:24:11:37:9C:AC` | `VM_MAC="${SMOKE_VM_MAC:-BC:24:11:37:9C:AC}"` — env override, CE default |
| `boot_vm.sh` SMBIOS uuid | hardcoded CE uuid | `VM_SMBIOS_UUID="${SMOKE_VM_SMBIOS_UUID:-58fd7964-…}"` — env override, CE default (Plus NDI is derived from MAC + uuid, so the uuid is as license-keyed as the MAC) |
| `conftest.py` | no identity awareness | unchanged — boots `boot_vm.sh` via `subprocess` inheriting `os.environ`, so `SMOKE_VM_MAC`/`SMOKE_VM_SMBIOS_UUID` propagate with no edit |
| Matrix schema | per-entry: version/channel/freebsd/php/py/ci… | + optional `image_name` (default `pfsense-ce`); the **MAC/uuid are NOT in the matrix** (license/NDI-keyed secrets). Existing entries valid unchanged |
| `read-version-matrix.sh` CI filter | `.ci == true and .channel == "CE"` | `.ci == true` (any channel); each emitted entry carries a resolved `image_name`. (`mac` stays a CE-public default placeholder — ignored for Plus, which overrides from the secret.) |
| `smoke.yml` VM identity | none | a "Resolve VM identity" step keys on the image: CE → public pin; non-CE (Plus) → `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` secrets (fail-closed if absent), masked, and emitted as the diagnostics redaction set |
| `smoke-fanout.yml` PLUS GUARD | fails on `channel != "CE"` | becomes a CI GUARD: fails on `ci != true` only; `secrets: inherit` so smoke.yml reads `SMOKE_PLUS_*`; leg name gains the channel (`Smoke (CE 2.8)` / `Smoke (Plus 26.03)`) |
| `smoke.yml` inputs | `pfsense_version`, `image_ref` | + `image_name` (default `pfsense-ce`); pytest gets `SMOKE_VM_MAC`/`SMOKE_VM_SMBIOS_UUID`/`SMOKE_REDACT_VALUES` from the resolve step |
| Plus diagnostics | none | runner-side: drop console screenshots (NDI/serial as pixels) + literal-redact the secret identity; in-guest: value-redact the whole bundle (MAC in ifconfig, uuid in dmesg, + live serial) before tar |
| Plus matrix entry | `ci: false` | `ci: true`, `image_name: pfsense-plus` (the MAC/uuid live in the `SMOKE_PLUS_*` secrets, not the entry; flipped LAST, via `ci-metadata` PR) |
| `image-refresh.yml` / `image-upgrade.sh` | CE upgrade-in-place | **unchanged — CE-only.** Plus refresh stays manual (`image-publish.sh` from Proxmox VM 104); `pfSense-upgrade` on Plus needs subscription auth CI doesn't hold |
| Docs (`CLAUDE.md`, `scripts/README.md`, matrix `lifecycle_policy`) | "never Plus", "ci: false for Plus" | rewritten: Plus runs in CI from a private licensed image; refresh manual |

### 2.2 Semantics that MUST be preserved (the contract)

1. **CE legs are bit-identical:** with no `image_name`/`mac` in a matrix entry and no
   new inputs supplied, every composed ref, QEMU command line, and workflow behaviour
   is unchanged. (All defaults = today's values.)
2. **AND-gate unchanged:** any failing leg (CE or Plus) reddens `all-smoke-passed`;
   zero legs stays red.
3. **`ci: false` still excludes:** a `ci: false` entry (of either channel) never
   produces a leg; the fan-out guard hard-fails if one leaks through.
4. **Plus boots ONLY with its secret identity:** the Plus leg's QEMU NIC MAC + SMBIOS
   uuid equal the `SMOKE_PLUS_MAC` / `SMOKE_PLUS_SMBIOS_UUID` secrets; no code path may
   fall back to the CE pin for a Plus image (license/NDI keyed to MAC + uuid), and the
   resolve step fails closed if a non-CE image is selected without those secrets.
5. **The Plus image stays private AND its identity never leaks:** no workflow step
   pushes, re-tags, attaches, or uploads the Plus qcow2 (cache keys/digests are fine);
   the secret identity (MAC + uuid [+ NDI] + live serial) is value-redacted out of the
   `smoke-diagnostics` bundle — in-guest across the whole bundle before tar, and
   runner-side across the boot `vm*.log` — and console screenshots are dropped for a
   non-CE image (a banner shows the NDI/serial as pixels). The actuator-style
   sensitive-tag scrub of `config.xml` runs for every leg as before.
6. **Build matrix untouched:** `build_matrix`, `python_versions`, `php_versions`
   outputs are unchanged (Plus was already in the build matrix).

### 2.3 Explicitly kept / out of scope

- `image-refresh.yml`/`image-upgrade.sh` stay CE-only; automated Plus image refresh is
  a future ADR (needs a subscription-auth story). Manual republish documented instead.
- `build-pkg-linux.yml`/`build-pkg.yml` unchanged (Plus already builds).
- No public exposure of the Plus image or a Plus channel in the ADR-17 pkg repo.
- The CE MAC pin and `image-upgrade.sh --mac` default are unchanged.
- `tests/smoke/` test bodies unchanged — cases are channel-agnostic (DNSBL block
  shapes, `unique_domain()`); anything genuinely CE-specific found during the live
  run is a finding to record, not silently patch.

## 3. Consequences

**Positive**

- Plus regressions (PHP 8.5, FreeBSD 16, py311) surface in CI instead of on users.
- The matrix entry is the one place a new image (CE or Plus) is wired in — no
  workflow YAML edit to add a version, preserving the ADR-09 property.
- Harness MAC/image parameterization also unblocks local multi-image testing.

**Negative / risks**

- **License exposure risk:** a leaked Plus image or NDI is a real licensing problem —
  mitigated by package privacy, the no-republish contract (§2.2.5), and diagnostics
  scrubbing. If Netgate's terms turn out to forbid CI use of a licensed instance,
  this ADR is REJECTED and Plus reverts to `ci: false` (one-line matrix revert).
- The licensed image's registration is keyed to one MAC — parallel Plus legs reuse
  the same MAC inside isolated SLIRP user-nets (no L2 collision), but Netgate-side
  online check-ins from concurrent boots are an unknown; the smoke harness keeps
  egress blocked during tests, which contains this.
- CI minutes roughly double per fan-out (one extra leg).

## 4. Requirements (acceptance)

1. `boot_vm.sh` boots with `SMOKE_VM_MAC` + `SMOKE_VM_SMBIOS_UUID` when set, CE pins
   otherwise.
2. `read-version-matrix.sh` CI matrix includes the Plus entry iff `ci: true`, with
   `image_name` resolved (default for CE entries that omit it). The MAC/uuid are NOT
   in the matrix — they are secrets.
3. `smoke-fanout.yml` runs one leg per `ci: true` entry, passing `image_name`; carries
   `secrets: inherit` so smoke.yml reads `SMOKE_PLUS_*`; guard fails on any `ci != true`
   leak.
4. `smoke.yml` composes `ghcr.io/pfblockerng/pfsense-plus:26.03` for the Plus leg and,
   via the resolve step, exports `SMOKE_VM_MAC`/`SMOKE_VM_SMBIOS_UUID` (from the
   secrets) + `SMOKE_REDACT_VALUES` to the pytest env; fails closed when a non-CE image
   lacks the secrets.
5. Full fan-out dispatch: CE leg(s) green AND Plus leg green; `all-smoke-passed`
   green.
6. CE-only dispatch (pre-flip state) produces byte-identical refs/QEMU args AND a
   byte-identical diagnostics bundle to today (§2.2.1 — pinned before the flip;
   `SMOKE_REDACT_VALUES` empty → redaction is a strict no-op).
7. A Plus-leg `smoke-diagnostics` artifact contains no MAC, SMBIOS uuid, NDI, serial,
   or other license token (value-redacted in-guest + runner-side; screenshots dropped).

## 5. Constraints (from CLAUDE.md)

- POSIX sh only; quote expansions; ShellCheck clean.
- Workflows touching code run `scripts/setup-hooks.sh` before committing (none here
  commit).
- Matrix edits via PR against `ci-metadata` (audit trail); never touch `main`/`devel`
  for matrix content.
- Red→green discipline (per ADR-21 precedent): behaviour-pinning tests fail
  pre-change where the surface is testable off-CI; live-leg evidence covers the rest
  and is recorded in RESULTS.
- Worktree + rebase-only PR flow for everything in `tests/`, `scripts/`, `.github/`.

## 6. Action plan

### Phase 1 — Harness parameterization (behaviour-preserving)

Prompt: `01_Harness_Mac_Image_Param.txt`

- `boot_vm.sh`: `VM_MAC="${SMOKE_VM_MAC:-BC:24:11:37:9C:AC}"`; header comment
  documents the Plus MAC + license-keying. `conftest.py`: pass `SMOKE_VM_MAC`
  through to the `boot_vm.sh` environment when set.
- `sh -n` + ShellCheck; pytest green; grep-pin the default (a unit test asserting the
  CE default string is present in `boot_vm.sh` — guards accidental default drift).

### Phase 2 — Matrix reader: ci-only filter + per-entry image/mac

Prompt: `02_Matrix_Reader_Channels.txt`

- `read-version-matrix.sh`: CI filter → `select(.ci == true)`; emit `image_name`
  (default `pfsense-ce`) and `mac` (default `BC:24:11:37:9C:AC`) on every CI-matrix
  entry. Composite action passthrough if it names fields.
- Tests: drive the script against a fixture ref (temp git repo with a synthetic
  `supported-versions.json`) asserting: Plus excluded at `ci:false`; included with
  fields once `ci:true`; CE defaults resolved. Red first (Plus-included case fails on
  the unmodified script).

### Phase 3 — Workflows: per-leg image name + MAC

Prompt: `03_Workflows_Per_Leg.txt`

- `smoke.yml`: `image_name` + `mac` inputs (defaults = today); ref composition uses
  `image_name`; export `SMOKE_VM_MAC=<mac>` to the pytest step.
- `smoke-fanout.yml`: PLUS GUARD → CI GUARD (`ci != true` only); pass
  `matrix.image_name`/`matrix.mac`; leg name `Smoke (${{ matrix.channel }}
  ${{ matrix.pfsense_version }})`. Update the header invariant comments.
- `actionlint`/YAML sanity; a CE-only dispatch (matrix unflipped) must resolve
  identical refs (record run id — §4.6 evidence).

### Phase 4 — Matrix flip on `ci-metadata` + live fan-out

Prompt: `04_Matrix_Flip_Live.txt`

- **Preconditions (maintainer, manual — gate the flip on these):**
  `ghcr.io/pfblockerng/pfsense-plus:26.03` published from Proxmox VM 104 and
  **private**; package grants this repo read access; Plus image has baked deps
  (FreeBSD-16 RUN_DEPENDS) + the smoke SSH key; diagnostics scrub verified for NDI.
- Set the `SMOKE_PLUS_MAC` + `SMOKE_PLUS_SMBIOS_UUID` (optionally `SMOKE_PLUS_NDI`)
  Actions secrets to the Plus source-VM identity (license/NDI-keyed — secrets, never
  the matrix).
- PR against `ci-metadata`: Plus entry `ci: true` + `image_name: pfsense-plus` (the
  MAC/uuid stay in the secrets, NOT the entry); schema gains the optional `image_name`
  field; `lifecycle_policy.plus` text rewritten.
- Dispatch `smoke-fanout.yml`; both legs + AND-gate green; pull a Plus-leg
  diagnostics artifact and verify no license identifier (§4.7).

### Phase 5 — Docs reconciliation

Prompt: `05_Docs.txt`

- `CLAUDE.md` ("Build vs CI split", "smoke fan-out … Never Plus") and
  `scripts/README.md` (CI-matrix notes + the Plus image section) updated to the new
  reality; note the manual-refresh carve-out. Docs-only — direct to `devel`.

## 7. Definition of done

Evidence in `RESULTS/05_Results.txt` (and per-phase RESULTS):

- `python -m pytest`, `ruff`, `mypy tests/`, ShellCheck/`sh -n` → green/clean.
- §4.6 pinned: pre-flip CE-only dispatch identical to today (run id + ref logs).
- Fan-out run id with CE + Plus legs green and `all-smoke-passed` green.
- Plus-leg diagnostics artifact inspected: no NDI/license token (§4.7).
- Matrix PR merged on `ci-metadata`; docs updated.

**Manual smoke checklist (maintainer):**

1. `oras manifest fetch ghcr.io/pfblockerng/pfsense-plus:26.03` succeeds with repo
   token; the package page shows **Private**.
2. Boot the published Plus qcow2 locally via `boot_vm.sh` with `SMOKE_VM_MAC` +
   `SMOKE_VM_SMBIOS_UUID` set to the Plus source-VM identity (the values held in the
   `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` secrets): no interface-reassignment
   prompt; license status intact in the GUI.
3. Boot it once WITHOUT the overrides (CE pins): expect the reassignment prompt /
   unregistered state — proving the identity is load-bearing (then discard the overlay).
4. `pkg info` on the Plus guest shows the baked RUN_DEPENDS (no network installs
   during smoke).

**Reject criteria:**

- Netgate licensing terms (or observed enforcement, e.g. registration invalidated by
  CI boots) forbid this use → revert Plus to `ci: false`; keep Phases 1–3
  (behaviour-preserving, independently valuable).
- The Plus leg cannot pass without per-test special-casing that diverges from CE
  semantics — that is a product finding, not a harness patch; stop and file issues.
- Any §2.2 contract item fails after Phase 3 (pre-flip).

## 8. Post-merge amendment (2026-07-28 — issue #1806)

The `arch` field this ADR's matrix schema assumed (§2.2 "carrying its resolved `arch`") is
**retired**. Every `pfSense-pkg-pfBlockerNG` port is `NO_ARCH` (issue #1806, superseding the
issue #199 ARM/aarch64 plan this ADR's schema left room for): a real package's manifest ABI is
CPU-wildcarded (`FreeBSD:<major>:*`), so `supported-versions.json` entries no longer carry an
`arch` field at all — a stray one on an old row is tolerated-ignored, never resurrected as a
default. This does not touch this ADR's CE+Plus fan-out decision, the CI matrix shape (still one
row per version, `image_name`/`mac` resolution unchanged), or the Plus identity/redaction design
(§2.7) — those are unaffected. What changed:

1. **The BUILD matrix (`--print-build`) now dedupes to one row per distinct `freebsd_major`.**
   One wildcard-ABI `.pkg` build serves every arch AND every edition/version sharing a major, so
   the release-artifact fan-out (`release.yml`) collapses from one leg per (variant, version) to
   one leg per major, named `pfBlockerNG-relpkg-fbsd<major>`. The CI matrix this ADR defines
   stays **one row per version** (never deduped) — a smoke leg still boots one VM per pfSense
   version, exactly as this ADR specifies.
2. **A new `extra_pkgs` field** (array of port origins) lets an entry declare a RUN_DEPENDS its
   own edition's upstream repo doesn't carry (e.g. CE's `textproc/py-charset-normalizer`, absent
   from Netgate's CE mirror but present in Plus's). Orthogonal to this ADR's CE/Plus CI design.
3. **`tests/smoke/_matrix.py`'s `_own_entry()` gained a `SMOKE_IMAGE_REF`-based disambiguator.**
   With `arch` gone, two editions sharing a `freebsd_major` (a real shape now, not just this
   ADR's §1 transition-window note) can both match a `SMOKE_ABI` lookup; the topology now breaks
   the tie by image name and refuses loudly rather than silently picking one when it can't.

See `docs/misc/architecture-notes.md` "Self-hosted pkg distribution — ABI is NOT 1:1..." for the
full design and `scripts/README.md` "Supported-version matrix" for the current schema.
