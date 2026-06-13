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


def _make_matrix_ref(tmp_path: Path, versions: list[dict[str, Any]], *, ref: str = "ci-metadata") -> Path:
    """Create a git repo in tmp_path with supported-versions.json committed on `ref`.

    Returns the repo path. The script reads via `git show <ref>:<file>` relative to
    cwd, so callers run the script with cwd = this path.
    """
    repo = tmp_path / "matrix-repo"
    repo.mkdir()

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
        [_plus_entry(ci=True, image_name="pfsense-plus", mac="BC:24:11:9C:FE:85")],
    )
    ci = _ci_matrix(repo)
    assert len(ci) == 1
    entry = ci[0]
    assert entry["image_name"] == "pfsense-plus"
    assert entry["mac"] == "BC:24:11:9C:FE:85"


# --------------------------------------------------------------------------- #
# Scenario e — BUILD matrix + derived test matrices unaffected (§2.2.6 regression).
# --------------------------------------------------------------------------- #
def test_build_and_test_matrices_unchanged_by_new_fields(tmp_path: Path) -> None:
    """The new CI-matrix fields do not perturb build_matrix / python_versions / php_versions."""
    versions = [_ce_entry(), _plus_entry(ci=True, image_name="pfsense-plus", mac="BC:24:11:9C:FE:85")]
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
