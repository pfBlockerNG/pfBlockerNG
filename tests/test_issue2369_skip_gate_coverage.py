from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pytest
import yaml

from scripts import check_skip_allowlist as checker

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github/workflows"


@dataclass(frozen=True)
class Row:
    workflow: str
    job: str
    step: str
    producer: str
    suite: str
    report: str
    same_step: bool
    node: bool = False


ROWS = (
    Row("test.yml", "test", "Run tests", "uv run pytest", "pytest", "/tmp/pytest-junit.xml", False),
    Row(
        "test.yml",
        "php-unit",
        "Run PHPUnit (with coverage)",
        "vendor/bin/phpunit",
        "phpunit",
        "/tmp/phpunit-junit.xml",
        False,
    ),
    Row(
        "test.yml",
        "shell-tests",
        "Run shellspec",
        'shellspec --shell "$DASH"',
        "shellspec",
        "/tmp/shellspec-report/results_junit.xml",
        False,
    ),
    Row(
        "test.yml",
        "widget-js-tests",
        "Run the Dashboard widget JS tests",
        "tests/js/*.test.js",
        "widget-js",
        "/tmp/widget-js-junit.xml",
        True,
        True,
    ),
    Row(
        "test.yml",
        "webassets-vendor",
        "Lezer grammar parse tests (regexp + pfb regex-list)",
        "lezer-regexp/test/parse.test.js",
        "webassets-grammar",
        "/tmp/webassets-grammar-junit.xml",
        True,
        True,
    ),
    Row(
        "test.yml",
        "webassets-vendor",
        "Lezer grammar parse tests (regexp + pfb regex-list)",
        "lezer-pfb-regex-list/test/parse.test.js",
        "webassets-listgrammar",
        "/tmp/webassets-listgrammar-junit.xml",
        True,
        True,
    ),
    Row(
        "test.yml",
        "webassets-vendor",
        "Lezer grammar parse tests (regexp + pfb regex-list)",
        "test/cm-lint.test.js",
        "webassets-bundle",
        "/tmp/webassets-bundle-junit.xml",
        True,
        True,
    ),
    Row(
        "build-pkg-linux.yml",
        "build",
        "Verify direct portable-builder parity",
        "tests/shell/build_leg_ports_parity_env.sh",
        "ports-parity",
        "/tmp/ports-parity-junit/results_junit.xml",
        True,
    ),
    Row(
        "ui-tests.yml",
        "ui",
        "Run the UI tier (pytest -m ${{ steps.tier.outputs.marker }})",
        'sh scripts/run-smoke.sh "$@"',
        "ui",
        "/tmp/ui-junit.xml",
        True,
    ),
    Row(
        "smoke-single.yml",
        "smoke",
        "Run the live-VM matrix (pytest -m ${{ inputs.pytest_marker || 'smoke' }})",
        'sh scripts/run-smoke.sh "$@"',
        "smoke",
        "smoke-diag/pytest-junit.xml",
        True,
    ),
)


def _workflow_texts() -> dict[str, str]:
    return {path.name: path.read_text() for path in WORKFLOW_DIR.glob("*.yml")}


def _step(workflow: dict[str, object], row: Row) -> dict[str, object] | None:
    jobs = workflow.get("jobs", {})
    job = jobs.get(row.job, {}) if isinstance(jobs, dict) else {}
    steps = job.get("steps", []) if isinstance(job, dict) else []
    return next((step for step in steps if step.get("name") == row.step), None)


def _discovered_rows(texts: dict[str, str]) -> Counter[tuple[str, str, str]]:
    found: Counter[tuple[str, str, str]] = Counter()
    command = re.compile(
        r"^(?:uv run(?: --locked)? pytest\b|vendor/bin/phpunit|shellspec --shell|"
        r"(?:command )?node --test\b|npm run test:(?:grammar|listgrammar|bundle)|"
        r"sh scripts/run-smoke\.sh)"
    )
    for filename, text in texts.items():
        workflow = yaml.safe_load(text)
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                step_name = step.get("name", "")
                if "informational" in step_name.lower():
                    continue
                for raw in str(step.get("run", "")).splitlines():
                    line = raw.strip()
                    if "skip-allowlist-node-canary.test.mjs" not in line and command.match(line):
                        found[(filename, job_name, step_name)] += 1
    return found


def _validation_errors(texts: dict[str, str]) -> list[str]:
    errors: list[str] = []
    expected = Counter((row.workflow, row.job, row.step) for row in ROWS)
    discovered = _discovered_rows(texts)
    if discovered != expected:
        errors.append(f"test-row table mismatch: expected={expected!r}, discovered={discovered!r}")

    if len({row.suite for row in ROWS}) != len(ROWS):
        errors.append("suite prefixes are not unique")
    if len({row.report for row in ROWS}) != len(ROWS):
        errors.append("report destinations are not unique")

    parsed = {name: yaml.safe_load(text) for name, text in texts.items()}
    for row in ROWS:
        step = _step(parsed[row.workflow], row)
        if step is None:
            errors.append(f"{row.workflow}/{row.job}: missing step {row.step!r}")
            continue
        run = str(step.get("run", ""))
        run_lines = [line.strip() for line in run.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        producer_lines = [line for line in run_lines if row.producer in line]
        if not producer_lines:
            errors.append(f"{row.suite}: producer command is missing")

        producer_flags = {
            "pytest": ("--junitxml=/tmp/pytest-junit.xml",),
            "phpunit": ("--log-junit /tmp/phpunit-junit.xml",),
            "shellspec": ("-o junit", "--reportdir /tmp/shellspec-report"),
            "ports-parity": ("-o junit", "--reportdir /tmp/ports-parity-junit"),
            "ui": ('set -- "$@" --junitxml=/tmp/ui-junit.xml',),
            "smoke": ('set -- "$@" --junitxml=smoke-diag/pytest-junit.xml',),
        }
        if any(not any(flag in line for line in run_lines) for flag in producer_flags.get(row.suite, ())):
            errors.append(f"{row.suite}: JUnit producer flags are missing")

        if row.same_step:
            gate = run
        else:
            job_steps = parsed[row.workflow]["jobs"][row.job]["steps"]
            gate_step = next((item for item in job_steps if item.get("name") == "Skip allowlist"), None)
            gate = str(gate_step.get("run", "")) if gate_step else ""

        prefix = f"check_skip_allowlist.py --suite {row.suite} --allowlist tests/skip-allowlist.txt "
        gate_lines = gate.splitlines()
        check_rows = [(index, line.strip().rstrip(" \\")) for index, line in enumerate(gate_lines) if prefix in line]
        checks = [line for _, line in check_rows]
        if len(checks) != 2:
            errors.append(f"{row.suite}: expected canary and real checker calls, got {len(checks)}")
            continue
        if row.node:
            canary_report = checks[0].split()[-1]
            if "canary" not in canary_report or not any(
                f"--test-reporter-destination={canary_report}" in line and "skip-allowlist-node-canary.test.mjs" in line
                for line in run_lines
            ):
                errors.append(f"{row.suite}: native Node canary reporter is missing")
        elif "tests/fixtures/skip-allowlist-canary.xml" not in checks[0]:
            errors.append(f"{row.suite}: known-skip canary is missing")
        if row.report not in checks[1]:
            errors.append(f"{row.suite}: checker reads a different report")
        canary_index = check_rows[0][0]
        canary_guard = gate_lines[canary_index + 1].strip() if canary_index + 1 < len(gate_lines) else ""
        if not canary_guard.startswith("&& { echo 'red canary failed:"):
            errors.append(f"{row.suite}: canary does not require nonzero")
        if row.node and not any(
            row.producer in line
            and f"--test-reporter-destination={row.report}" in line
            and "--test-reporter=spec --test-reporter-destination=stdout" in line
            for line in run_lines
        ):
            errors.append(f"{row.suite}: native JUnit and live reporter destinations are incomplete")
    return errors


def test_source_derived_table_covers_every_blocking_test_row_and_all_wiring_is_complete() -> None:
    assert _validation_errors(_workflow_texts()) == []


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda text: text.replace("/tmp/widget-js-junit.xml", "/tmp/wrong-widget.xml", 1), "widget-js"),
        (lambda text: text.replace("--suite widget-js", "--suite unknown-widget", 1), "widget-js"),
        (lambda text: text.replace("skip-allowlist-node-canary.test.mjs", "missing-canary.test.mjs", 1), "widget-js"),
        (
            lambda text: text.replace(
                "tests/js/*.test.js", "tests/js/*.test.js\n          node --test surprise.test.js", 1
            ),
            "test-row table mismatch",
        ),
    ],
)
def test_validator_rejects_planted_missing_malformed_unknown_or_unenumerated_wiring(
    mutation: Callable[[str], str], expected: str
) -> None:
    texts = _workflow_texts()
    texts["test.yml"] = mutation(texts["test.yml"])
    assert expected in "\n".join(_validation_errors(texts))


@pytest.mark.parametrize("suite", [row.suite for row in ROWS])
def test_checker_accepts_every_source_derived_suite_prefix(suite: str, tmp_path: Path) -> None:
    report = tmp_path / "report.xml"
    report.write_text("<testsuites/>")
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("# empty\n")
    assert checker.main(["--suite", suite, "--allowlist", str(allowlist), str(report)]) == 0


def test_local_runner_wires_reports_canaries_checker_and_cleanup_for_existing_suites() -> None:
    script = (ROOT / "scripts/agent/run-gates.sh").read_text()
    expected = {
        "pytest": "--junitxml=",
        "phpunit": "--log-junit",
        "shellspec": "-o junit",
    }
    for suite, report_flag in expected.items():
        assert report_flag in script, suite
        assert script.count(f"check_skip_allowlist.py --suite {suite} --allowlist tests/skip-allowlist.txt") >= 2
    assert "skip-allowlist-canary.xml" in script
    assert "trap" in script and "skip_report" in script and "rm -rf" in script
