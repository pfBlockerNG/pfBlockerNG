"""Issue #2673: default pytest is xdist; Tests cancel is pull_request only."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
TEST_YML = ROOT / ".github" / "workflows" / "test.yml"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _addopts_tokens() -> list[str]:
    return _pyproject()["tool"]["pytest"]["ini_options"]["addopts"].split()


def test_dev_group_pins_pytest_xdist_exactly() -> None:
    specs = _pyproject()["dependency-groups"]["dev"]
    assert "pytest-xdist==3.8.0" in specs
    smoke = _pyproject()["dependency-groups"]["smoke"]
    assert not any("pytest-xdist" in spec for spec in smoke)


def test_default_addopts_is_xdist_and_still_ignores_smoke() -> None:
    tokens = _addopts_tokens()
    assert "--ignore=tests/smoke" in tokens
    # `-n auto` is two tokens; a fused `-nauto` would not be what CI runs.
    n = tokens.index("-n")
    assert tokens[n + 1] == "auto"


def _extract_job(text: str, job_name: str) -> str:
    match = re.search(rf"^  {re.escape(job_name)}:\n", text, re.MULTILINE)
    assert match is not None, f"job {job_name!r} not found"
    start = match.end()
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\n", text[start:], re.MULTILINE)
    end = start + nxt.start() if nxt else len(text)
    return text[start:end]


def test_tests_workflow_cancels_in_progress_pull_requests_only() -> None:
    text = TEST_YML.read_text(encoding="utf-8")
    match = re.search(r"^concurrency:\n((?:  .+\n)+)", text, re.MULTILINE)
    assert match is not None, "Tests workflow must declare workflow-level concurrency"
    body = match.group(1)
    assert "github.event.pull_request.number || github.ref" in body
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in body
    assert re.search(r"cancel-in-progress:\s*true\s*$", body, re.MULTILINE) is None


def test_slow_tests_jobs_pin_timeout_minutes() -> None:
    text = TEST_YML.read_text(encoding="utf-8")
    expected = {
        "test": 20,
        "shell-tests": 20,
        "php-static-analysis": 10,
        "php-unit": 15,
    }
    for name, minutes in expected.items():
        job = _extract_job(text, name)
        hit = re.search(r"^    timeout-minutes: (\d+)\s*$", job, re.MULTILINE)
        assert hit is not None, f"{name} missing job-level timeout-minutes:\n{job[:200]}"
        assert int(hit.group(1)) == minutes, f"{name}: {hit.group(1)} != {minutes}"


def test_informational_cov_is_still_a_second_pytest_run() -> None:
    text = TEST_YML.read_text(encoding="utf-8")
    junit = "uv run pytest --junitxml=/tmp/pytest-junit.xml"
    cov = "uv run pytest --cov=pfb_unbound --cov-branch"
    assert text.count(junit) == 1
    assert text.count(cov) == 1
    assert text.index(junit) < text.index(cov)
