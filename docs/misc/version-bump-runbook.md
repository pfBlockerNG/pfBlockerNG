# Version-bump runbook (stubs, matrix, smoke images)

Procedure for bumping the minimum supported pfSense version and regenerating the PHP stubs. The
**rules** (when to regenerate, stub-over-baseline preference) live in `CLAUDE.md` → "Updating
documentation"; this file is the step-by-step.

## Regenerating `stubs/pfsense/`

Run when min CE is bumped:

```sh
python scripts/update-pfsense-stubs.py            # newest public source
python scripts/update-pfsense-stubs.py --version X.Y.Z
```

Downloads pfSense source, emits one stub per module (`util.php`, `interfaces.php`, …) with
cross-file dedup. Defaults to **2.7.2** (`STUB_SOURCE_VERSION`): the public mirror is frozen
there (no `RELENG_2_8_0`) and signatures are stable 2.7→2.8, all PHPStan level 0 needs (symbol
existence). Regenerate from a real 2.8 checkout if/when available.

Also regenerate (or hand-edit) when pfBlockerNG calls a new un-stubbed pfSense function — add it
to the right `stubs/pfsense/` file manually. `globals.php` is **always** hand-maintained (array
shapes can't be auto-derived); `logging.php` + `supplemental.php` likewise never regenerated
(`supplemental.php` holds CE-2.8 functions absent from the 2.7.2 source, e.g.
`config_read_file`). PHPStan is the gate; prefer a real stub over a `phpstan-baseline.neon`
suppression.

## ADR-08 IDN homoglyph analyzer — no UCD table to regenerate

The ADR-08 IDN homoglyph analyzer (inlined in `src/usr/local/pkg/pfblockerng/pfb_unbound.py`,
backing **IDN Blocking → Confusable**) ships **no** Unicode data table: it resolves each code
point's script from the **stdlib `unicodedata.name()`** leading token (`LATIN…`→Latin,
`CJK…`→Han, …), so nothing regenerates on a UCD bump. It reads the runtime stdlib UCD (Python
3.11 ships 14.0.0, 3.12/3.13 15.1.0, 3.14 16.0.0); name tokens are stable across those for the
scripts in scope. The corpus/oracle GOLDEN (`tests/fixtures/adr08_*`) is pinned to UCD 15.1.0
and `tests/test_adr08_*` proves the analyzer agrees with it across versions. It lives **in
`pfb_unbound.py`** (not a sibling module) so it rides the existing chroot copy + `pkg-plist`
entry — no new shipped file, no extra deploy wiring.

## When the minimum pfSense version changes

1. **Update the supported-version matrix** — edit `supported-versions.json` on the
   **`ci-metadata` orphan branch** via a PR against `ci-metadata`. Single source of truth for
   supported versions + their `(freebsd_version, php_version)` build pair; workflows read it at
   runtime via `scripts/read-version-matrix.sh` + `.github/actions/read-version-matrix/` (see
   `scripts/README.md`). Build + CI: every `ci: true` entry — **CE and Plus** (ADR-24) — gets
   `.pkg` builds **and** live-VM smoke. Plus runs from a **PRIVATE, licensed** GHCR image
   (`pfsense-plus`); its VM identity (NIC MAC + SMBIOS uuid, keying the Netgate Device ID) comes
   from the `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` (+ optional `SMOKE_PLUS_NDI`) secrets —
   **never** the matrix — and the harness redacts it from diagnostics. Adding the entry + letting
   **version-tracker** (`version-tracker.yml`) run (or dispatching it) triggers
   `build-pkg-linux.yml`, `image-refresh.yml` (CE **and** Plus — see step 2), `smoke.yml`
   automatically — **no workflow YAML edit needed**.
2. **Refresh the smoke images** (ADR-04 + ADR-09) — `image-refresh.yml` (`Upgrade pfSense smoke
   images`) is a **CE + Plus matrix fan-out**: a `plan` job reads `ci-metadata`, and each
   `ci:true` variant is refreshed **only when its `upgrade.available` flag is set** (a curated
   per-variant signal that a public pre-release / GA / patch exists). Absent/`false` → that
   variant is skipped, so most days the run is a clean no-op. Each leg runs
   `scripts/image-upgrade.sh --type ce|plus --upgrade-pkgs` (and `--branch <id>` when
   `upgrade.branch` is set, to reach a **pre-release / development** build — the branch is stored
   in pfSense's `system/pkg_repo_conf_path` and applied via `pkg_switch_repo()`): pulls the
   current GHCR tag, conditionally upgrades baked deps, runs `pfSense-upgrade`, then an **alive
   health gate** (≤300 s for webConfigurator HTTP or a live `pfctl` ruleset) and publishes only
   when healthy — fail-closed. GA/patches within a floating tag (2.8.0→2.8.1, both tag `2.8`)
   self-replace that tag (`--force`); a new Major.Minor publishes a new tag. The **Plus** leg
   takes its license/NDI identity from the `SMOKE_PLUS_MAC`/`SMOKE_PLUS_SMBIOS_UUID` secrets and
   refuses to boot on mismatch. A non-blocking post-publish smoke runs per variant on a discarded
   overlay (informational; authoritative validation is the fan-out, step 3; the Plus post-smoke
   skips cleanly if the Plus secrets are absent). Manual seed via `scripts/image-publish.sh`
   remains the fallback when the gate fails (and for the initial Plus image seed). To enable an
   upgrade, set the entry's `upgrade` block in `ci-metadata` (`{available, branch, target, from}`;
   `from` defaults to the entry's own floating tag = self-replace). See
   `.ADRs/ADR_04_VM_Smoke_Tests/IMAGE_RUNBOOK.md`. (ADR-09 supersedes ADR-04 §2's "re-baseline on
   a major jump": `image-refresh.yml` handles all jumps via upgrade-in-place; a fresh re-seed is
   triggered only by a gate failure. Reconciling the ADR-04 §2 text is a tracked follow-up.)
3. **Run the smoke fan-out** — dispatch `smoke.yml` (no inputs; reads the CI matrix).
   Runs the ADR-04 suite against **all** `ci: true` entries — **CE and Plus** (ADR-24) — in
   parallel (`fail-fast: false`); the `all-smoke-passed` AND-gate fails if **any** leg fails.
   version-tracker triggers it daily; dispatch manually to verify a new image.
4. **Re-diff the portable `.pkg` against a real `make package` build** (manual; also do this
   whenever the FreeBSD-ports fork's `Mk/` framework moves). `build-pkg-portable.py` is the sole
   `.pkg` builder — its `make package` fidelity was validated by a one-time field-by-field diff
   (the FreeBSD `build-pkg.yml` oracle was retired in `68992f4c`), and that validation rots as
   libpkg and the ports framework evolve. On a FreeBSD box (a dev pfSense VM works): check out the
   same port + source commit, run `make package`, then diff the two archives member-by-member
   (`tar -tvf`; extract both `+MANIFEST`s and compare field-by-field after `json`/UCL
   normalization). Expected benign divergences — file `sum` type (`1$sha256` vs modern
   `2$blake2b`), tar flavor/uid, mtime, and best-effort dep versions — are enumerated in
   `docs/build-pkg-portable.md` ("Fidelity vs `make package`"); anything else is a builder bug to
   fix before the bump lands.
5. **Sweep the version-literal checker + seeded escapes** (issue #940) — as soon as the matrix
   moves, `test.yml`'s tripwire step (`scripts/check_version_literals.py --verify-matrix`) fails
   if the new version falls outside the checker's **windowed CE/Plus numeric shapes**
   (`_TOKEN_ALTERNATIVES`); widen the window and update the checker's tests. Then sweep every
   `version-literal-ok` escape (`git grep -n version-literal-ok -- src scripts .github`): the
   escaped `workflow_dispatch` fallback defaults and dev-tooling defaults still name the OLD
   version and need bumping by hand — the escape comment exempts them from the gate, so nothing
   else will remind you.
