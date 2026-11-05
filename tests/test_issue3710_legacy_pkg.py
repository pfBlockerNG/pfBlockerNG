"""Issue #3710: the shipped v3.3.13 .pkg (``SMOKE_LEGACY_PKG``) reaches the smoke suite.

The settings-family lifecycle smoke installs the release a 3.2 user is told to run over the
branch build. Three things must hold, and each is pinned here off-box:

* the harness fixture ``legacy_pkg`` skips only when there is no branch package at all and
  FAILS (never skips) when the package it needs was not fetched;
* CI's smoke job fetches it before pytest and hands it over, and a failed fetch stops the job;
* the tag and the sha256 of every asset are written in exactly one place.

The on-box path (``smoke-on-box.sh`` -> ``fetch-legacy-pkg.sh``) is covered by
``tests/shell/smoke_on_box_spec.sh`` and ``tests/shell/fetch_legacy_pkg_spec.sh``.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from tests.smoke import conftest as smoke_conftest

ROOT = Path(__file__).resolve().parent.parent
FETCH_LEGACY_PKG = ROOT / "scripts" / "fetch-legacy-pkg.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"
SMOKE_CONFTEST = ROOT / "tests" / "smoke" / "conftest.py"


def _pinned_tag() -> str:
    """The pin, asked of the script that owns it: the harness never carries a second copy."""
    done = subprocess.run(["sh", str(FETCH_LEGACY_PKG), "--print-tag"], capture_output=True, text=True, check=True)
    tag = done.stdout.strip()
    assert re.fullmatch(r"v\d+\.\d+\.\d+", tag), f"--print-tag printed {done.stdout!r}"
    return tag


def _legacy_pkg_fixture() -> Any:
    return cast(Any, smoke_conftest.legacy_pkg).__wrapped__()


# --------------------------------------------------------------------------- #
# The legacy_pkg fixture
# --------------------------------------------------------------------------- #


def test_legacy_pkg_skips_when_no_branch_package_was_built(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No SMOKE_PKG means no deployable package at all (a dev box collecting): skip, like prev_pkg."""
    monkeypatch.delenv("SMOKE_PKG", raising=False)
    monkeypatch.setenv("SMOKE_LEGACY_PKG", str(tmp_path / "never-read.pkg"))

    with pytest.raises(pytest.skip.Exception, match="SMOKE_PKG not set"):
        _legacy_pkg_fixture()


@pytest.mark.parametrize("state", ["unset", "empty", "missing-file", "directory"])
def test_legacy_pkg_fails_when_the_branch_package_exists_but_the_legacy_one_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str
) -> None:
    """A leg that built SMOKE_PKG but did not fetch SMOKE_LEGACY_PKG is a broken leg, never a skipped test."""
    monkeypatch.setenv("SMOKE_PKG", "branch.pkg")
    if state == "unset":
        monkeypatch.delenv("SMOKE_LEGACY_PKG", raising=False)
    elif state == "empty":
        monkeypatch.setenv("SMOKE_LEGACY_PKG", "")
    elif state == "missing-file":
        monkeypatch.setenv("SMOKE_LEGACY_PKG", str(tmp_path / "absent.pkg"))
    else:
        monkeypatch.setenv("SMOKE_LEGACY_PKG", str(tmp_path))

    try:
        _legacy_pkg_fixture()
    except pytest.skip.Exception as skipped:
        # Escaping the test body it would be reported as a SKIPPED test: exactly the "not
        # applicable" reading this fixture exists to prevent. Turn it into a failure here.
        pytest.fail(f"legacy_pkg skipped instead of failing: {skipped}", pytrace=False)
    except pytest.fail.Exception as failed:
        assert "fetch-legacy-pkg" in str(failed), f"the failure must name the fetch step, got: {failed}"
    else:
        pytest.fail("legacy_pkg returned although SMOKE_LEGACY_PKG is not a file")


def test_legacy_pkg_returns_the_fetched_file_and_names_the_pinned_tag_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pkg = tmp_path / "dir with space" / "pfSense-pkg-pfBlockerNG-3.3.13-CE-2.8.pkg"
    pkg.parent.mkdir()
    pkg.write_bytes(b"pkg")
    monkeypatch.setenv("SMOKE_PKG", "branch.pkg")
    monkeypatch.setenv("SMOKE_LEGACY_PKG", str(pkg))

    result = _legacy_pkg_fixture()

    assert result == pkg
    assert isinstance(result, Path)
    identity = [line for line in capsys.readouterr().out.splitlines() if line.startswith("PFB_LEGACY_PKG ")]
    assert identity == [f"PFB_LEGACY_PKG tag={_pinned_tag()} path={pkg}"]


def test_legacy_pkg_is_session_scoped() -> None:
    """One fetch per run: a module-scoped fixture would re-announce (and re-validate) per module."""
    tree = ast.parse(SMOKE_CONFTEST.read_text(encoding="utf-8"))
    (legacy_pkg,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "legacy_pkg"]
    scopes = [
        kw.value.value
        for dec in legacy_pkg.decorator_list
        if isinstance(dec, ast.Call) and ast.unparse(dec.func) == "pytest.fixture"
        for kw in dec.keywords
        if kw.arg == "scope" and isinstance(kw.value, ast.Constant)
    ]
    assert scopes == ["session"], f"legacy_pkg must carry @pytest.fixture(scope='session'), found scopes {scopes}"


# --------------------------------------------------------------------------- #
# CI wiring: smoke-single.yml, job `smoke`
# --------------------------------------------------------------------------- #


def _smoke_steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["smoke"]["steps"]
    return steps


def _fetch_step() -> dict[str, Any]:
    steps = [s for s in _smoke_steps() if "scripts/fetch-legacy-pkg.sh" in str(s.get("run", ""))]
    assert len(steps) == 1, f"steps running fetch-legacy-pkg.sh: {[s.get('name') for s in steps]}"
    return steps[0]


def _index(predicate: Any) -> int:
    indexes = [i for i, step in enumerate(_smoke_steps()) if predicate(step)]
    assert len(indexes) == 1, f"expected exactly one matching step, found {indexes}"
    return indexes[0]


def test_the_smoke_job_fetches_the_legacy_package_after_the_image_ref_and_before_pytest() -> None:
    fetched = _index(lambda s: "scripts/fetch-legacy-pkg.sh" in str(s.get("run", "")))
    ref = _index(lambda s: s.get("id") == "ref")
    pytest_step = _index(lambda s: "run-smoke.sh" in str(s.get("run", "")))

    assert ref < fetched < pytest_step


def test_the_legacy_package_fetch_cannot_be_skipped_past_or_ignored() -> None:
    step = _fetch_step()

    assert "continue-on-error" not in step
    # Only the `smoke` marker collects the lifecycle module that reads it; the `repo` flows must not pay for it.
    assert str(step.get("if", "")).replace(" ", "") == "${{(inputs.pytest_marker||'smoke')=='smoke'}}"
    assert str(step["run"]).lstrip().startswith("set -eu")


def test_the_legacy_package_is_fetched_for_the_leg_image() -> None:
    step = _fetch_step()
    env = step["env"]

    # The script picks edition and version from the image the leg boots, so the asset matches the guest.
    assert env["IMAGE_REF"] == "${{ steps.ref.outputs.ref }}"
    assert env["PFSENSE_VERSION"] == "${{ inputs.pfsense_version }}"
    assert re.search(r'--image-ref\s+"\$IMAGE_REF"', step["run"]), step["run"]
    assert re.search(r'--pfsense-version\s+"\$PFSENSE_VERSION"', step["run"]), step["run"]


def test_pytest_receives_the_legacy_package() -> None:
    pytest_step = _smoke_steps()[_index(lambda s: "run-smoke.sh" in str(s.get("run", "")))]

    assert pytest_step["env"]["SMOKE_LEGACY_PKG"] == "${{ env.SMOKE_LEGACY_PKG }}"


def _run_step(tmp_path: Path, fetcher_exit: int) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the step's own shell with a fake scripts/fetch-legacy-pkg.sh and a GITHUB_ENV file."""
    step = _fetch_step()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "fetch-legacy-pkg.sh").write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" > "$ARGV_LOG"\n'
        f"[ {fetcher_exit} -eq 0 ] || {{ echo 'fetch-legacy-pkg: download failed' >&2; exit {fetcher_exit}; }}\n"
        "printf '%s\\n' \"$FAKE_PKG_OUT\"\n",
        encoding="utf-8",
    )
    github_env = tmp_path / "github_env"
    github_env.write_text("", encoding="utf-8")
    env = {
        "PATH": "/usr/bin:/bin",
        "GITHUB_ENV": str(github_env),
        "ARGV_LOG": str(tmp_path / "argv"),
        "FAKE_PKG_OUT": str(tmp_path / "out dir" / "legacy.pkg"),
        **{
            name: f"value-of-{name}" for name in (step.get("env") or {}) if name not in {"IMAGE_REF", "PFSENSE_VERSION"}
        },
        "IMAGE_REF": "ghcr.io/pfblockerng/pfsense-plus:26.03",
        "PFSENSE_VERSION": "26.03",
    }
    done = subprocess.run(
        ["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    return done, github_env


def test_the_step_exports_the_fetched_package_path_for_the_pytest_step(tmp_path: Path) -> None:
    done, github_env = _run_step(tmp_path, fetcher_exit=0)

    assert done.returncode == 0, done.stderr
    assert github_env.read_text(encoding="utf-8") == f"SMOKE_LEGACY_PKG={tmp_path / 'out dir' / 'legacy.pkg'}\n"
    argv = (tmp_path / "argv").read_text(encoding="utf-8")
    assert argv == "--image-ref ghcr.io/pfblockerng/pfsense-plus:26.03 --pfsense-version 26.03\n"


def test_a_failed_fetch_fails_the_step_and_exports_nothing(tmp_path: Path) -> None:
    done, github_env = _run_step(tmp_path, fetcher_exit=3)

    assert done.returncode != 0
    assert "fetch-legacy-pkg: download failed" in done.stderr
    assert github_env.read_text(encoding="utf-8") == ""


# --------------------------------------------------------------------------- #
# The pins live in one place
# --------------------------------------------------------------------------- #


def test_every_asset_hash_is_written_in_exactly_one_tracked_non_doc_file() -> None:
    """smoke-on-box.sh, the workflow and the harness call the script; none carries a hash."""
    pins = re.findall(r"'([0-9a-f]{64})'", FETCH_LEGACY_PKG.read_text(encoding="utf-8"))
    assert len(pins) == 5, f"expected one pin per shipped asset, found {pins}"
    for pin in pins:
        found = subprocess.run(
            ["git", "-C", str(ROOT), "grep", "--untracked", "-l", "-F", pin, "--", ".", ":!docs", ":!graphify-out"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert found.stdout.split() == ["scripts/fetch-legacy-pkg.sh"], f"{pin}: {found.stdout}{found.stderr}"
