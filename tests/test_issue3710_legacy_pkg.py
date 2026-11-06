"""Issue #3710: the shipped v3.3.13 .pkg (``SMOKE_LEGACY_PKG``) reaches the smoke suite.

The settings-family lifecycle smoke installs the release a 3.2 user is told to run, after the branch build. Two
behaviours are pinned here off-box:

* the harness fixture ``legacy_pkg`` skips only when there is no branch package at all and FAILS (never skips) when
  the package it needs was not fetched;
* CI's smoke job fetches it before pytest and hands it over: a failed download or hash check stops the job, a leg the
  release shipped no package for carries on without it (the lifecycle module then fails at the fixture, the rest of the
  run is unaffected).

The on-box path (``smoke-on-box.sh`` -> ``fetch-legacy-pkg.sh``) is covered by ``tests/shell/smoke_on_box_spec.sh`` and
``tests/shell/fetch_legacy_pkg_spec.sh``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from tests.smoke import conftest as smoke_conftest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"
# fetch-legacy-pkg.sh's exit code for "the release shipped no package for this leg".
NO_PINNED_ASSET = 3


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
    """A leg that built SMOKE_PKG but has no SMOKE_LEGACY_PKG is a broken leg, never a skipped test."""
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


def test_legacy_pkg_returns_the_fetched_file_and_names_it_once(
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
    assert identity == [f"PFB_LEGACY_PKG path={pkg}"]


# --------------------------------------------------------------------------- #
# CI wiring: smoke-single.yml, job `smoke`
# --------------------------------------------------------------------------- #


def _fetch_step() -> dict[str, Any]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["smoke"]["steps"]
    found = [s for s in steps if "scripts/fetch-legacy-pkg.sh" in str(s.get("run", ""))]
    assert len(found) == 1, f"steps running fetch-legacy-pkg.sh: {[s.get('name') for s in found]}"
    return found[0]


def _run_step(tmp_path: Path, fetcher_exit: int) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the step's own shell with a fake scripts/fetch-legacy-pkg.sh and a GITHUB_ENV file."""
    step = _fetch_step()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "fetch-legacy-pkg.sh").write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" > "$ARGV_LOG"\n'
        f"[ {fetcher_exit} -eq 0 ] || {{ echo 'fetch-legacy-pkg: stub exit {fetcher_exit}' >&2; "
        f"exit {fetcher_exit}; }}\n"
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
    # The script picks edition and version from the image the leg boots, so the asset matches the guest.
    argv = (tmp_path / "argv").read_text(encoding="utf-8")
    assert argv == "--image-ref ghcr.io/pfblockerng/pfsense-plus:26.03 --pfsense-version 26.03\n"


@pytest.mark.parametrize("exit_code", [1, 2, 127])
def test_a_failed_fetch_fails_the_step_and_exports_nothing(tmp_path: Path, exit_code: int) -> None:
    done, github_env = _run_step(tmp_path, fetcher_exit=exit_code)

    assert done.returncode != 0, (
        f"expected the step to fail on fetch exit {exit_code}, got rc=0\n{done.stdout}{done.stderr}"
    )
    assert f"fetch-legacy-pkg: stub exit {exit_code}" in done.stderr
    assert github_env.read_text(encoding="utf-8") == ""


def test_a_leg_with_no_shipped_package_passes_the_step_and_exports_nothing(tmp_path: Path) -> None:
    """Only the lifecycle module needs the package: its leg-wide absence must not stop the whole job."""
    done, github_env = _run_step(tmp_path, fetcher_exit=NO_PINNED_ASSET)

    assert done.returncode == 0, (
        f"expected the step to pass on fetch exit {NO_PINNED_ASSET}\n{done.stdout}{done.stderr}"
    )
    assert github_env.read_text(encoding="utf-8") == ""
    assert "no shipped v3.3.13 package" in done.stdout + done.stderr
