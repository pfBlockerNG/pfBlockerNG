"""Issue #3455 S1: the previous-devel .pkg (``SMOKE_PREV_PKG``) reaches the smoke suite.

The HA mixed-version rows install a package built from the last devel commit before the
per-field sync series on node B. Three things must hold, and each is pinned here off-box:

* the harness fixture ``prev_pkg`` skips only when there is no branch package at all and
  FAILS (never skips) when the package it needs was not built;
* CI's smoke job builds it before pytest and hands it over, and a failed build stops the job;
* the commit it is built from is pinned in exactly one place.

The on-box path (``smoke-on-box.sh`` -> ``build-prev-pkg.sh``) is covered by
``tests/shell/smoke_on_box_spec.sh`` and ``tests/shell/build_prev_pkg_spec.sh``.
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
BUILD_PREV_PKG = ROOT / "scripts" / "build-prev-pkg.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "smoke-single.yml"
SMOKE_CONFTEST = ROOT / "tests" / "smoke" / "conftest.py"
FIXTURE_ENV = ("SMOKE_PKG", "SMOKE_PREV_PKG")


def _pinned_ref() -> str:
    """The pin, asked of the script that owns it: the harness never carries a second copy."""
    done = subprocess.run(["sh", str(BUILD_PREV_PKG), "--print-ref"], capture_output=True, text=True, check=True)
    ref = done.stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{40}", ref), f"--print-ref printed {done.stdout!r}"
    return ref


def _prev_pkg_fixture() -> Any:
    return cast(Any, smoke_conftest.prev_pkg).__wrapped__()


# --------------------------------------------------------------------------- #
# The prev_pkg fixture
# --------------------------------------------------------------------------- #


def test_prev_pkg_skips_when_no_branch_package_was_built(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No SMOKE_PKG means no deployable package at all (a dev box collecting): skip, like peer_vm."""
    monkeypatch.delenv("SMOKE_PKG", raising=False)
    monkeypatch.setenv("SMOKE_PREV_PKG", str(tmp_path / "never-read.pkg"))

    with pytest.raises(pytest.skip.Exception, match="SMOKE_PKG not set"):
        _prev_pkg_fixture()


@pytest.mark.parametrize("state", ["unset", "empty", "missing-file", "directory"])
def test_prev_pkg_fails_when_the_branch_package_exists_but_the_previous_one_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str
) -> None:
    """A leg that built SMOKE_PKG but not SMOKE_PREV_PKG is a broken leg, never a skipped test."""
    monkeypatch.setenv("SMOKE_PKG", "branch.pkg")
    if state == "unset":
        monkeypatch.delenv("SMOKE_PREV_PKG", raising=False)
    elif state == "empty":
        monkeypatch.setenv("SMOKE_PREV_PKG", "")
    elif state == "missing-file":
        monkeypatch.setenv("SMOKE_PREV_PKG", str(tmp_path / "absent.pkg"))
    else:
        monkeypatch.setenv("SMOKE_PREV_PKG", str(tmp_path))

    try:
        _prev_pkg_fixture()
    except pytest.skip.Exception as skipped:
        # Escaping the test body it would be reported as a SKIPPED test: exactly the "not
        # applicable" reading this fixture exists to prevent. Turn it into a failure here.
        pytest.fail(f"prev_pkg skipped instead of failing: {skipped}", pytrace=False)
    except pytest.fail.Exception as failed:
        assert "build-prev-pkg" in str(failed), f"the failure must name the build step, got: {failed}"
    else:
        pytest.fail("prev_pkg returned although SMOKE_PREV_PKG is not a file")


def test_prev_pkg_returns_the_built_file_and_names_the_pinned_commit_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pkg = tmp_path / "dir with space" / "pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg"
    pkg.parent.mkdir()
    pkg.write_bytes(b"pkg")
    monkeypatch.setenv("SMOKE_PKG", "branch.pkg")
    monkeypatch.setenv("SMOKE_PREV_PKG", str(pkg))

    result = _prev_pkg_fixture()

    assert result == pkg
    assert isinstance(result, Path)
    identity = [line for line in capsys.readouterr().out.splitlines() if line.startswith("PFB_PREV_PKG ")]
    assert identity == [f"PFB_PREV_PKG ref={_pinned_ref()} path={pkg}"]


def test_prev_pkg_is_session_scoped() -> None:
    """One build per run: a module-scoped fixture would re-announce (and re-validate) per module."""
    tree = ast.parse(SMOKE_CONFTEST.read_text(encoding="utf-8"))
    (prev_pkg,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "prev_pkg"]
    scopes = [
        kw.value.value
        for dec in prev_pkg.decorator_list
        if isinstance(dec, ast.Call) and ast.unparse(dec.func) == "pytest.fixture"
        for kw in dec.keywords
        if kw.arg == "scope" and isinstance(kw.value, ast.Constant)
    ]
    assert scopes == ["session"], f"prev_pkg must carry @pytest.fixture(scope='session'), found scopes {scopes}"


# --------------------------------------------------------------------------- #
# CI wiring: smoke-single.yml, job `smoke`
# --------------------------------------------------------------------------- #


def _smoke_steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["smoke"]["steps"]
    return steps


def _prev_build_step() -> dict[str, Any]:
    steps = [s for s in _smoke_steps() if "scripts/build-prev-pkg.sh" in str(s.get("run", ""))]
    assert len(steps) == 1, f"steps running build-prev-pkg.sh: {[s.get('name') for s in steps]}"
    return steps[0]


def _index(predicate: Any) -> int:
    indexes = [i for i, step in enumerate(_smoke_steps()) if predicate(step)]
    assert len(indexes) == 1, f"expected exactly one matching step, found {indexes}"
    return indexes[0]


def test_the_smoke_job_builds_the_previous_package_after_the_branch_package_and_before_pytest() -> None:
    built = _index(lambda s: "scripts/build-prev-pkg.sh" in str(s.get("run", "")))
    located = _index(lambda s: s.get("id") == "paths")
    pytest_step = _index(lambda s: "run-smoke.sh" in str(s.get("run", "")))

    assert located < built < pytest_step


def test_the_previous_package_build_cannot_be_skipped_past_or_ignored() -> None:
    step = _prev_build_step()

    assert "continue-on-error" not in step
    # Only the `smoke` marker selects the HA rows that read it; the `repo` marker flows must not pay for it.
    assert str(step.get("if", "")).replace(" ", "") == "${{(inputs.pytest_marker||'smoke')=='smoke'}}"
    assert str(step["run"]).lstrip().startswith("set -eu")


def test_the_previous_package_is_built_like_the_branch_package() -> None:
    step = _prev_build_step()
    env = step["env"]

    # Same runtime tuple and channel (--like) as the branch build; the script pins the ports recipe.
    assert env["BRANCH_PKG"] == "${{ steps.paths.outputs.pkg }}"
    assert env["ABI"] == "${{ inputs.abi }}"
    assert env["PHP_VERSION"] == "${{ inputs.php_version }}"
    assert env["PY_FLAVOR"] == "${{ inputs.py_flavor }}"
    assert '--like "$BRANCH_PKG"' in step["run"]


def test_pytest_receives_the_previous_package() -> None:
    pytest_step = _smoke_steps()[_index(lambda s: "run-smoke.sh" in str(s.get("run", "")))]

    assert pytest_step["env"]["SMOKE_PREV_PKG"] == "${{ env.SMOKE_PREV_PKG }}"


def _run_step(tmp_path: Path, builder_exit: int) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the step's own shell with a fake scripts/build-prev-pkg.sh and a GITHUB_ENV file."""
    step = _prev_build_step()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build-prev-pkg.sh").write_text(
        '#!/bin/sh\nprintf \'%s\\n\' "$*" > "$ARGV_LOG"\nprintf \'%s\\n\' "${PFB_RUN_ROOT-unset}" > "$RUN_ROOT_LOG"\n'
        f"[ {builder_exit} -eq 0 ] || {{ echo 'build-prev-pkg: build failed' >&2; exit {builder_exit}; }}\n"
        "printf '%s\\n' \"$FAKE_PKG_OUT\"\n",
        encoding="utf-8",
    )
    github_env = tmp_path / "github_env"
    github_env.write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner temp"
    runner_temp.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "GITHUB_ENV": str(github_env),
        "RUNNER_TEMP": str(runner_temp),
        "ARGV_LOG": str(tmp_path / "argv"),
        "RUN_ROOT_LOG": str(tmp_path / "run-root"),
        "FAKE_PKG_OUT": str(tmp_path / "out dir" / "prev.pkg"),
        **{
            name: f"value-of-{name}"
            for name in (step.get("env") or {})
            if name not in {"BRANCH_PKG", "ABI", "PHP_VERSION", "PY_FLAVOR"}
        },
        "BRANCH_PKG": "/branch dir/pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg",
        "ABI": "FreeBSD:15:amd64",
        "PHP_VERSION": "8.3",
        "PY_FLAVOR": "py311",
    }
    done = subprocess.run(
        ["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False
    )
    return done, github_env


def test_the_step_exports_the_built_package_path_for_the_pytest_step(tmp_path: Path) -> None:
    done, github_env = _run_step(tmp_path, builder_exit=0)

    assert done.returncode == 0, done.stderr
    assert github_env.read_text(encoding="utf-8") == f"SMOKE_PREV_PKG={tmp_path / 'out dir' / 'prev.pkg'}\n"
    argv = (tmp_path / "argv").read_text(encoding="utf-8")
    assert "--like /branch dir/pfSense-pkg-pfBlockerNG-edge-4.0.0.a1.pkg" in argv
    assert "--abi FreeBSD:15:amd64 --php 8.3 --py-flavor py311" in argv
    # Without the export build-leg.sh falls back to /var/tmp/pfb-runs; like the nightly step, use RUNNER_TEMP.
    assert (tmp_path / "run-root").read_text(encoding="utf-8") == f"{tmp_path / 'runner temp'}/pfb-runs\n"


def test_a_failed_build_fails_the_step_and_exports_nothing(tmp_path: Path) -> None:
    done, github_env = _run_step(tmp_path, builder_exit=3)

    assert done.returncode != 0
    assert "build-prev-pkg: build failed" in done.stderr
    assert github_env.read_text(encoding="utf-8") == ""


# --------------------------------------------------------------------------- #
# The pin lives in one place
# --------------------------------------------------------------------------- #


def test_the_pinned_commit_is_written_in_exactly_one_tracked_non_doc_file() -> None:
    """smoke-on-box.sh and the workflow call the script; neither carries the SHA."""
    ref = _pinned_ref()
    found = subprocess.run(
        ["git", "-C", str(ROOT), "grep", "--untracked", "-l", "-F", ref, "--", ".", ":!docs", ":!graphify-out"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert found.stdout.split() == ["scripts/build-prev-pkg.sh"], found.stdout + found.stderr
