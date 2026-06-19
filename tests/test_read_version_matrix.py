"""Tests for scripts/read-version-matrix.sh — the BUILD/CI matrix reader (ADR-24 Phase 2).

The reader cats supported-versions.json from a git ref and emits, as JSON, the BUILD
matrix (all entries) and the CI matrix. ADR-24 changes the CI filter from
`.ci == true and .channel == "CE"` to `.ci == true` (any channel), and has each
CI-matrix entry carry a resolved `image_name` (default `pfsense-ce`) + `mac`
(default the CE pin `BC:24:11:37:9C:AC`) so existing CE entries that omit those
fields need no edit while a `ci: true` Plus entry can enter CI with its own image/MAC.

These tests do not merely run the script — they pin the behaviour that matters:

  * a `ci: false` Plus entry is EXCLUDED from the CI matrix (the §2.2.3 contract);
  * a `ci: true` Plus entry is INCLUDED (the channel no longer filters) — the RED
    scenario pre-change, since today's filter pins `.channel == "CE"`;
  * every CI-matrix entry carries `image_name` + `mac`, defaulted when the JSON
    omits them, and passed through verbatim when present;
  * the BUILD matrix and the derived `python_versions` / `php_versions` outputs are
    unaffected by the new fields (§2.2.6 — build matrix untouched).

Each test builds a SYNTHETIC supported-versions.json, commits it to a throwaway git
repo on a ref, and runs the script with `--ref`/`--file` pointed at it (subprocess,
cwd = the temp repo) — the same shape as the other script-driving tests in tests/.
No network; needs git + jq (both present on the CI runner and locally).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "read-version-matrix.sh"


def _clean_git_env() -> dict[str, str]:
    """Env with every GIT_* var stripped.

    The test drives git in a throwaway repo (cwd=tmp_path) and the script itself
    shells out to git. When the suite runs under the pre-commit hook, git exports
    GIT_DIR / GIT_INDEX_FILE / GIT_WORK_TREE / GIT_PREFIX into the hook's
    environment; those would override `cwd` and point every git invocation at the
    REAL repo (where a `ci-metadata` ref already exists — `git branch ci-metadata`
    then fails rc 128, and `git show` reads the wrong matrix). Scrub them so the
    temp repo is the sole git context, matching a clean standalone `pytest` run.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


CE_DEFAULT_IMAGE_NAME = "pfsense-ce"
CE_DEFAULT_MAC = "BC:24:11:37:9C:AC"
# A clearly-fake DOCUMENTATION MAC for the explicit-pass-through fixture. The real
# Plus source-VM MAC is a license/NDI-keyed SECRET (SMOKE_PLUS_MAC) and must NEVER
# appear in the repo (ADR-24); this test only proves the reader emits an explicit
# `mac` field verbatim, so any non-default value exercises that branch.
FAKE_DOC_MAC = "02:00:00:00:00:01"

# Skip the whole module if git or jq is missing — the script hard-requires both,
# and a missing tool is an environment gap, not a behaviour regression.
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("jq") is None,
    reason="read-version-matrix.sh requires git + jq",
)


def _ce_entry(**overrides: Any) -> dict[str, Any]:
    """A minimal valid CE matrix entry (ci:true); override any field."""
    entry: dict[str, Any] = {
        "pfsense_version": "2.8",
        "channel": "CE",
        "freebsd_version": "15.0-RELEASE",
        "freebsd_major": "15",
        "php_version": "8.3",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "active",
        "ci": True,
    }
    entry.update(overrides)
    return entry


def _plus_entry(**overrides: Any) -> dict[str, Any]:
    """A minimal valid Plus matrix entry; override any field (e.g. ci)."""
    entry: dict[str, Any] = {
        "pfsense_version": "26.03",
        "channel": "Plus",
        "freebsd_version": "16.0-RELEASE",
        "freebsd_major": "16",
        "php_version": "8.5",
        "py_flavor": "py311",
        "variant": "Plus",
        "status": "active",
        "ci": False,
    }
    entry.update(overrides)
    return entry


def _route_only_entry(**overrides: Any) -> dict[str, Any]:
    """A role=route-only CE matrix entry (EOL: served from frozen .pkg, never built)."""
    entry: dict[str, Any] = {
        "pfsense_version": "2.7",
        "channel": "CE",
        "freebsd_version": "14.0-RELEASE",
        "freebsd_major": "14",
        "php_version": "8.2",
        "py_flavor": "py311",
        "variant": "CE",
        "status": "EOL",
        "ci": False,
        "role": "route-only",
    }
    entry.update(overrides)
    return entry


def _make_matrix_ref(tmp_path: Path, versions: list[dict[str, Any]], *, ref: str = "ci-metadata") -> Path:
    """Create a git repo in tmp_path with supported-versions.json committed on `ref`.

    Returns the repo path. The script reads via `git show <ref>:<file>` relative to
    cwd, so callers run the script with cwd = this path.
    """
    repo = tmp_path / "matrix-repo"
    repo.mkdir(parents=True)

    def _git(*args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
            env=_clean_git_env(),
        )

    _git("init", "-q", "-b", "main")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    # Throwaway repo — never sign (a signing-enabled global config would otherwise
    # break the commit and is irrelevant to what this test pins).
    _git("config", "commit.gpgsign", "false")
    _git("config", "tag.gpgsign", "false")

    matrix = {
        "description": "synthetic test matrix",
        "versions": versions,
    }
    (repo / "supported-versions.json").write_text(json.dumps(matrix, indent=2) + "\n")
    _git("add", "supported-versions.json")
    _git("commit", "-q", "-m", "matrix")
    # Put it on the requested ref name (a local branch is a valid git ref the script
    # can `git show` — its internal `git fetch origin ci-metadata` failure is ignored).
    if ref != "main":
        _git("branch", ref)
    return repo


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the script in `repo` with the given args; assert it succeeded."""
    proc = subprocess.run(
        ["sh", str(_SCRIPT), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        env=_clean_git_env(),
    )
    assert proc.returncode == 0, f"script failed (rc={proc.returncode})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return proc


def _ci_matrix(repo: Path, ref: str = "ci-metadata") -> list[dict[str, Any]]:
    proc = _run(repo, "--ref", ref, "--file", "supported-versions.json", "--print-ci")
    return json.loads(proc.stdout)  # type: ignore[no-any-return]


def _build_matrix(repo: Path, ref: str = "ci-metadata") -> list[dict[str, Any]]:
    proc = _run(repo, "--ref", ref, "--file", "supported-versions.json", "--print-build")
    return json.loads(proc.stdout)  # type: ignore[no-any-return]


def _route_matrix(repo: Path, ref: str = "ci-metadata") -> list[dict[str, Any]]:
    proc = _run(repo, "--ref", ref, "--file", "supported-versions.json", "--print-route")
    return json.loads(proc.stdout)  # type: ignore[no-any-return]


def _test_matrices(repo: Path, ref: str = "ci-metadata") -> tuple[list[str], list[str]]:
    """Return (python_versions, php_versions) parsed from --print-test output."""
    proc = _run(repo, "--ref", ref, "--file", "supported-versions.json", "--print-test")
    # Output is two labelled JSON blocks: "python_versions:\n[...]\n\nphp_versions:\n[...]"
    out = proc.stdout
    py_label = "python_versions:"
    php_label = "php_versions:"
    py_start = out.index(py_label) + len(py_label)
    php_idx = out.index(php_label)
    py_json = out[py_start:php_idx].strip()
    php_json = out[php_idx + len(php_label) :].strip()
    return json.loads(py_json), json.loads(php_json)


# --------------------------------------------------------------------------- #
# Scenario a — ci:false Plus entry is EXCLUDED (passes today; regression pin).
# --------------------------------------------------------------------------- #
def test_ci_matrix_excludes_plus_entry_with_ci_false(tmp_path: Path) -> None:
    """A Plus entry with ci:false never enters the CI matrix (§2.2.3)."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry(), _plus_entry(ci=False)])
    ci = _ci_matrix(repo)
    channels = {e["channel"] for e in ci}
    assert channels == {"CE"}, f"ci:false Plus must be excluded; got {ci!r}"
    assert all(e["ci"] is True for e in ci)


# --------------------------------------------------------------------------- #
# Scenario b — ci:true Plus entry is INCLUDED (RED today: channel filter drops it).
# --------------------------------------------------------------------------- #
def test_ci_matrix_includes_plus_entry_with_ci_true(tmp_path: Path) -> None:
    """A Plus entry with ci:true enters the CI matrix — the channel no longer filters."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry(), _plus_entry(ci=True)])
    ci = _ci_matrix(repo)
    channels = {e["channel"] for e in ci}
    assert channels == {"CE", "Plus"}, f"ci:true Plus must be included; got {ci!r}"
    plus = [e for e in ci if e["channel"] == "Plus"]
    assert len(plus) == 1 and plus[0]["pfsense_version"] == "26.03"


# --------------------------------------------------------------------------- #
# Scenario c — defaults applied when image_name/mac omitted (RED today: no fields).
# --------------------------------------------------------------------------- #
def test_ci_matrix_entries_default_image_name_and_mac(tmp_path: Path) -> None:
    """Each CI-matrix entry carries image_name/mac, defaulting to the CE image + pin."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry()])  # omits image_name + mac
    ci = _ci_matrix(repo)
    assert len(ci) == 1
    entry = ci[0]
    assert entry["image_name"] == CE_DEFAULT_IMAGE_NAME
    assert entry["mac"] == CE_DEFAULT_MAC


# --------------------------------------------------------------------------- #
# Scenario d — explicit image_name/mac pass through verbatim (RED today: no fields).
# --------------------------------------------------------------------------- #
def test_ci_matrix_entries_pass_through_explicit_image_name_and_mac(tmp_path: Path) -> None:
    """Explicit image_name/mac in the JSON are emitted verbatim — no default override."""
    repo = _make_matrix_ref(
        tmp_path,
        [_plus_entry(ci=True, image_name="pfsense-plus", mac=FAKE_DOC_MAC)],
    )
    ci = _ci_matrix(repo)
    assert len(ci) == 1
    entry = ci[0]
    assert entry["image_name"] == "pfsense-plus"
    assert entry["mac"] == FAKE_DOC_MAC


# --------------------------------------------------------------------------- #
# Scenario d2 — EMPTY-STRING image_name/mac normalize to the defaults.
# `//` alone treats only null/missing as absent, so a literal "" would flow
# through and later be read as a CE fallback by downstream workflows — silently
# mis-routing a Plus leg. The reader must coerce "" to the default too.
# --------------------------------------------------------------------------- #
def test_ci_matrix_empty_string_image_name_and_mac_normalize_to_defaults(tmp_path: Path) -> None:
    """An empty-string image_name/mac is treated as absent → CE image + pin (not "")."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry(image_name="", mac="")])
    ci = _ci_matrix(repo)
    assert len(ci) == 1
    entry = ci[0]
    assert entry["image_name"] == CE_DEFAULT_IMAGE_NAME, f"empty image_name must default; got {entry['image_name']!r}"
    assert entry["mac"] == CE_DEFAULT_MAC, f"empty mac must default; got {entry['mac']!r}"


# --------------------------------------------------------------------------- #
# Scenario e — BUILD matrix + derived test matrices unaffected (§2.2.6 regression).
# --------------------------------------------------------------------------- #
def test_build_and_test_matrices_unchanged_by_new_fields(tmp_path: Path) -> None:
    """The new CI-matrix fields do not perturb build_matrix / python_versions / php_versions."""
    versions = [_ce_entry(), _plus_entry(ci=True, image_name="pfsense-plus", mac=FAKE_DOC_MAC)]
    repo = _make_matrix_ref(tmp_path, versions)

    build = _build_matrix(repo)
    # BUILD matrix is the verbatim versions array — both entries, no injected fields
    # on the CE entry (image_name/mac resolution is a CI-matrix concern only).
    assert [e["pfsense_version"] for e in build] == ["2.8", "26.03"]
    ce_build = next(e for e in build if e["channel"] == "CE")
    assert "image_name" not in ce_build and "mac" not in ce_build

    py, php = _test_matrices(repo)
    assert py == ["3.11"]  # both entries are py311
    assert php == ["8.3", "8.5"]  # distinct, sorted


# --------------------------------------------------------------------------- #
# Scenario f — arch defaults to amd64 when omitted (issue #199).
# A pre-#199 matrix has no `arch` field; every entry must resolve to amd64 so the
# build path emits the unchanged FreeBSD:N:amd64 ABI. RED before the reader injects
# arch (the field would simply be absent).
# --------------------------------------------------------------------------- #
def test_build_matrix_defaults_arch_to_amd64_when_omitted(tmp_path: Path) -> None:
    """An entry without an `arch` field resolves to amd64 in the BUILD matrix (and CI inherits it)."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry()])  # omits arch
    build = _build_matrix(repo)
    assert len(build) == 1
    assert build[0]["arch"] == "amd64", f"omitted arch must default to amd64; got {build[0].get('arch')!r}"
    # CI matrix inherits the resolved arch (no separate injection).
    ci = _ci_matrix(repo)
    assert len(ci) == 1 and ci[0]["arch"] == "amd64"


# --------------------------------------------------------------------------- #
# Scenario g — explicit aarch64 passes through verbatim (issue #199 — the point).
# An aarch64 Plus entry (Netgate ARM appliances) must carry arch=aarch64 into both
# the BUILD and CI matrices so release.yml/version-tracker build a FreeBSD:N:aarch64
# .pkg. RED before #199 (no arch field is propagated at all).
# --------------------------------------------------------------------------- #
def test_build_matrix_passes_through_explicit_aarch64(tmp_path: Path) -> None:
    """An explicit arch=aarch64 is emitted verbatim in the BUILD matrix and inherited by CI."""
    repo = _make_matrix_ref(
        tmp_path,
        [_ce_entry(), _plus_entry(ci=True, arch="aarch64", image_name="pfsense-plus", mac=FAKE_DOC_MAC)],
    )
    build = _build_matrix(repo)
    arches = {e["pfsense_version"]: e["arch"] for e in build}
    assert arches == {"2.8": "amd64", "26.03": "aarch64"}, f"explicit aarch64 must pass through; got {arches!r}"
    # The ci:true aarch64 Plus entry carries aarch64 into the CI matrix too.
    ci = _ci_matrix(repo)
    plus = [e for e in ci if e["channel"] == "Plus"]
    assert len(plus) == 1 and plus[0]["arch"] == "aarch64"


# --------------------------------------------------------------------------- #
# Scenario h — empty-string arch normalizes to amd64 (the other invalid input).
# `//` alone treats only null/missing as absent, so a literal "" would otherwise
# flow through and a downstream ABI build would emit `FreeBSD:N:` (no arch) — the
# same trap guarded for image_name/mac. The reader must coerce "" to amd64.
# --------------------------------------------------------------------------- #
def test_build_matrix_empty_string_arch_normalizes_to_amd64(tmp_path: Path) -> None:
    """An empty-string arch is treated as absent → amd64 (never a bare `FreeBSD:N:` ABI)."""
    repo = _make_matrix_ref(tmp_path, [_ce_entry(arch="")])
    build = _build_matrix(repo)
    assert len(build) == 1
    assert build[0]["arch"] == "amd64", f"empty arch must default to amd64; got {build[0]['arch']!r}"


# --------------------------------------------------------------------------- #
# Scenario i — route-only entry EXCLUDED from build/ci/test, INCLUDED in route.
# An EOL pfSense version with role=route-only must never fan out a build or smoke
# leg, but must appear in --print-route so the generator knows to serve its frozen
# .pkg. This is the core Part-2 (ADR-27 §2.4) gate.
# --------------------------------------------------------------------------- #
def test_route_only_excluded_from_build_ci_test_included_in_route(tmp_path: Path) -> None:
    """A route-only entry is absent from build/ci/test and present in route.

    Before: matrix with only build entries → route output is identical to build
    (back-compat; no regression). After adding a route-only entry: build/ci/test
    unchanged, route gains the extra entry.
    """
    # BEFORE: build-only matrix — route == build (back-compat baseline).
    repo = _make_matrix_ref(tmp_path, [_ce_entry()])
    build_before = _build_matrix(repo)
    route_before = _route_matrix(repo)
    assert [e["pfsense_version"] for e in build_before] == ["2.8"], "before: build has the CE entry"
    assert [e["pfsense_version"] for e in route_before] == ["2.8"], "before: route == build (back-compat)"

    # AFTER: add a route-only entry → build/ci/test stay unchanged; route gains it.
    repo2 = _make_matrix_ref(tmp_path / "r2", [_ce_entry(), _route_only_entry()])
    build_after = _build_matrix(repo2)
    ci_after = _ci_matrix(repo2)
    py_after, php_after = _test_matrices(repo2)
    route_after = _route_matrix(repo2)

    build_versions = {e["pfsense_version"] for e in build_after}
    assert build_versions == {"2.8"}, f"route-only must be excluded from build; got {build_versions!r}"

    ci_versions = {e["pfsense_version"] for e in ci_after}
    assert ci_versions == {"2.8"}, f"route-only must be excluded from ci; got {ci_versions!r}"

    assert py_after == ["3.11"], f"route-only must not add a python version to --print-test; got {py_after!r}"
    assert php_after == ["8.3"], f"route-only must not add a php version to --print-test; got {php_after!r}"

    route_versions = {e["pfsense_version"] for e in route_after}
    assert route_versions == {"2.8", "2.7"}, f"route must include the route-only entry; got {route_versions!r}"
    route_only_entry = next(e for e in route_after if e["pfsense_version"] == "2.7")
    assert route_only_entry["role"] == "route-only", "route-only role must be present in route matrix"


# --------------------------------------------------------------------------- #
# Scenario j — absent role treated as build (back-compat mapping).
# An entry with NO `role` field must appear in --print-build exactly as before —
# the (.role // "build") default is the contract.
# --------------------------------------------------------------------------- #
def test_absent_role_treated_as_build(tmp_path: Path) -> None:
    """An entry without a `role` field is treated as role=build (present in build, absent in route-only set).

    Before: the CE entry (no role field) appears in build — proving this is the
    current state. Asserting it also appears in route confirms route is a superset of build
    (no regression: route == build when there are no route-only entries).
    """
    repo = _make_matrix_ref(tmp_path, [_ce_entry()])  # no 'role' field
    build = _build_matrix(repo)
    route = _route_matrix(repo)

    # BEFORE: entry with no role is in build (the current / back-compat behaviour).
    assert any(e["pfsense_version"] == "2.8" for e in build), "no-role entry must be in build"
    # Also in route (route is a superset of build; with no route-only entries they are identical).
    assert any(e["pfsense_version"] == "2.8" for e in route), "no-role entry must also be in route"
    # Absent role never appears in the route matrix as 'route-only'.
    assert all(e.get("role") != "route-only" for e in route), "no-role entry must not carry role=route-only"


# --------------------------------------------------------------------------- #
# Scenario k — no-route-only matrices: build output byte-identical (back-compat).
# With ZERO route-only entries, the build matrix must be identical to the route
# matrix (both == all entries). Pinned as a before/after regression guard.
# --------------------------------------------------------------------------- #
def test_no_route_only_build_equals_route(tmp_path: Path) -> None:
    """With no route-only entries, --print-build and --print-route emit the same versions.

    This is the exact back-compat contract: adding the role seam must not change
    the output for any matrix that has no route-only entries (i.e. today's real matrix).
    """
    versions = [_ce_entry(), _plus_entry(ci=True)]
    repo = _make_matrix_ref(tmp_path, versions)
    build = _build_matrix(repo)
    route = _route_matrix(repo)

    build_vs = sorted(e["pfsense_version"] for e in build)
    route_vs = sorted(e["pfsense_version"] for e in route)
    assert build_vs == route_vs, (
        f"without route-only entries, build == route (back-compat); build={build_vs!r} route={route_vs!r}"
    )
