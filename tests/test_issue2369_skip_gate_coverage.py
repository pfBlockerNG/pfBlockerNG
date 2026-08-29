from __future__ import annotations

import shlex
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
        "tools/webassets/lezer-regexp/test/parse.test.js",
        "webassets-grammar",
        "/tmp/webassets-grammar-junit.xml",
        True,
        True,
    ),
    Row(
        "test.yml",
        "webassets-vendor",
        "Lezer grammar parse tests (regexp + pfb regex-list)",
        "tools/webassets/lezer-pfb-regex-list/test/parse.test.js",
        "webassets-listgrammar",
        "/tmp/webassets-listgrammar-junit.xml",
        True,
        True,
    ),
    Row(
        "test.yml",
        "webassets-vendor",
        "Lezer grammar parse tests (regexp + pfb regex-list)",
        "tools/webassets/test/cm-lint.test.js",
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


def _shell_line(raw: str) -> tuple[str, ...]:
    try:
        argv = tuple(shlex.split(raw, comments=True, posix=True))
    except ValueError:
        return ()
    return argv[1:] if argv[:1] == ("command",) else argv


def _shell_commands(script: str) -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = []
    pending = ""
    for raw in script.splitlines():
        stripped = raw.strip()
        continuation = stripped.endswith("\\")
        piece = stripped[:-1] if continuation else stripped
        pending = f"{pending} {piece}".strip()
        if not continuation:
            argv = _shell_line(pending)
            if argv:
                commands.append(argv)
            pending = ""
    return commands


def _starts(argv: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return argv[: len(prefix)] == prefix


def _contains_args(argv: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    width = len(expected)
    return any(argv[index : index + width] == expected for index in range(len(argv) - width + 1))


def _is_test_command(argv: tuple[str, ...]) -> bool:
    return any(
        _starts(argv, prefix)
        for prefix in (
            ("uv", "run", "pytest"),
            ("uv", "run", "--locked", "pytest"),
            ("vendor/bin/phpunit",),
            ("shellspec", "--shell"),
            ("node", "--test"),
            ("npm", "run", "test:grammar"),
            ("npm", "run", "test:listgrammar"),
            ("npm", "run", "test:bundle"),
            ("sh", "scripts/run-smoke.sh"),
        )
    )


def _discovered_rows(texts: dict[str, str]) -> Counter[tuple[str, str, str]]:
    found: Counter[tuple[str, str, str]] = Counter()
    for filename, text in texts.items():
        workflow = yaml.safe_load(text)
        for job_name, job in workflow.get("jobs", {}).items():
            for step in job.get("steps", []):
                step_name = step.get("name", "")
                if "informational" in step_name.lower():
                    continue
                for argv in _shell_commands(str(step.get("run", ""))):
                    if "tests/fixtures/skip-allowlist-node-canary.test.mjs" not in argv and _is_test_command(argv):
                        found[(filename, job_name, step_name)] += 1
    return found


def _checker_report(argv: tuple[str, ...], suite: str) -> str | None:
    prefix = (
        "python3",
        "scripts/check_skip_allowlist.py",
        "--suite",
        suite,
        "--allowlist",
        "tests/skip-allowlist.txt",
    )
    return argv[len(prefix)] if _starts(argv, prefix) and len(argv) > len(prefix) else None


def _canary_rejects_skip(argv: tuple[str, ...]) -> bool:
    try:
        guard = argv.index("&&")
        exit_command = argv.index("exit", guard)
        return argv[exit_command + 1].rstrip(";") == "1"
    except (ValueError, IndexError):
        return False


def _validation_errors(texts: dict[str, str]) -> list[str]:
    errors: list[str] = []
    expected = Counter((row.workflow, row.job, row.step) for row in ROWS)
    try:
        discovered = _discovered_rows(texts)
        parsed = {name: yaml.safe_load(text) for name, text in texts.items()}
    except yaml.YAMLError as error:
        return [f"workflow YAML is invalid: {error}"]
    if discovered != expected:
        errors.append(f"test-row table mismatch: expected={expected!r}, discovered={discovered!r}")

    if len({row.suite for row in ROWS}) != len(ROWS):
        errors.append("suite prefixes are not unique")
    if len({row.report for row in ROWS}) != len(ROWS):
        errors.append("report destinations are not unique")

    for row in ROWS:
        step = _step(parsed[row.workflow], row)
        if step is None:
            errors.append(f"{row.workflow}/{row.job}: missing step {row.step!r}")
            continue
        run = str(step.get("run", ""))
        run_commands = _shell_commands(run)
        producer_start = {
            "pytest": ("uv", "run", "pytest"),
            "phpunit": ("vendor/bin/phpunit",),
            "shellspec": ("shellspec", "--shell"),
            "ports-parity": ("shellspec", "--shell"),
            "widget-js": ("node", "--test"),
            "webassets-grammar": ("node", "--test"),
            "webassets-listgrammar": ("node", "--test"),
            "webassets-bundle": ("node", "--test"),
            "ui": ("sh", "scripts/run-smoke.sh"),
            "smoke": ("sh", "scripts/run-smoke.sh"),
        }[row.suite]
        argument_producers = {
            "ports-parity",
            "widget-js",
            "webassets-grammar",
            "webassets-listgrammar",
            "webassets-bundle",
        }
        expected_command = tuple(shlex.split(row.producer))
        producer_commands = [
            argv
            for argv in run_commands
            if _starts(argv, producer_start)
            and (row.producer in argv if row.suite in argument_producers else _starts(argv, expected_command))
        ]
        if not producer_commands:
            errors.append(f"{row.suite}: producer command is missing")

        producer_flags: dict[str, tuple[tuple[str, ...], ...]] = {
            "pytest": (("--junitxml=/tmp/pytest-junit.xml",),),
            "phpunit": (("--log-junit", "/tmp/phpunit-junit.xml"),),
            "shellspec": (("-o", "junit"), ("--reportdir", "/tmp/shellspec-report")),
            "ports-parity": (("-o", "junit"), ("--reportdir", "/tmp/ports-parity-junit")),
            "ui": (("set", "--", "$@", "--junitxml=/tmp/ui-junit.xml"),),
            "smoke": (("set", "--", "$@", "--junitxml=smoke-diag/pytest-junit.xml"),),
        }
        flag_commands = (
            [argv for argv in run_commands if _starts(argv, ("set", "--", "$@"))]
            if row.suite in {"ui", "smoke"}
            else producer_commands
        )
        if any(
            not any(_contains_args(argv, flag) for argv in flag_commands) for flag in producer_flags.get(row.suite, ())
        ):
            errors.append(f"{row.suite}: JUnit producer flags are missing")

        if row.same_step:
            gate = run
        else:
            job_steps = parsed[row.workflow]["jobs"][row.job]["steps"]
            gate_step = next((item for item in job_steps if item.get("name") == "Skip allowlist"), None)
            gate = str(gate_step.get("run", "")) if gate_step else ""

        check_commands = [
            (report, argv) for argv in _shell_commands(gate) if (report := _checker_report(argv, row.suite)) is not None
        ]
        if len(check_commands) != 2:
            errors.append(f"{row.suite}: expected canary and real checker calls, got {len(check_commands)}")
            continue
        canary_report, canary_check = check_commands[0]
        real_report, _ = check_commands[1]
        if row.node:
            expected_canary = (
                "/tmp/widget-js-canary.xml" if row.suite == "widget-js" else "/tmp/webassets-node-canary.xml"
            )
            if canary_report != expected_canary or not any(
                _starts(argv, ("node", "--test"))
                and "--test-reporter=junit" in argv
                and f"--test-reporter-destination={expected_canary}" in argv
                and "tests/fixtures/skip-allowlist-node-canary.test.mjs" in argv
                for argv in run_commands
            ):
                errors.append(f"{row.suite}: native Node canary reporter is missing")
        elif canary_report != "tests/fixtures/skip-allowlist-canary.xml":
            errors.append(f"{row.suite}: known-skip canary is missing")
        if real_report != row.report:
            errors.append(f"{row.suite}: checker reads a different report")
        if not _canary_rejects_skip(canary_check):
            errors.append(f"{row.suite}: canary does not require nonzero")
        if row.node and not any(
            "--test-reporter=junit" in argv
            and f"--test-reporter-destination={row.report}" in argv
            and "--test-reporter=spec" in argv
            and "--test-reporter-destination=stdout" in argv
            for argv in producer_commands
        ):
            errors.append(f"{row.suite}: native JUnit and live reporter destinations are incomplete")
    return errors


def test_source_derived_table_covers_every_blocking_test_row_and_all_wiring_is_complete() -> None:
    texts = _workflow_texts()
    assert sum(_discovered_rows(texts).values()) == len(ROWS) == 10
    assert _validation_errors(texts) == []


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


@pytest.mark.parametrize(
    "suite",
    ["widget-js", "webassets-grammar", "webassets-listgrammar", "webassets-bundle"],
)
def test_each_node_suite_rejects_duplicate_ids_even_when_xml_file_differs(
    suite: str,
    tmp_path: Path,
) -> None:
    report = tmp_path / "duplicates.xml"
    report.write_text(
        "<testsuites><testsuite>"
        '<testcase classname="test" name="same" file="first.test.js"/>'
        '<testcase classname="test" name="same" file="second.test.js"><skipped/></testcase>'
        "</testsuite></testsuites>"
    )
    with pytest.raises(checker.ReportError, match="duplicate testcase id"):
        checker.parse_report(report, suite)


def test_local_runner_wires_reports_and_cleanup_for_existing_suites() -> None:
    script = (ROOT / "scripts/agent/run-gates.sh").read_text()
    expected = {
        "pytest": "--junitxml=",
        "phpunit": "--log-junit",
        "shellspec": "-o junit",
    }
    for suite, report_flag in expected.items():
        assert report_flag in script, suite
    assert "trap" in script and "skip_report" in script and "rm -rf" in script
