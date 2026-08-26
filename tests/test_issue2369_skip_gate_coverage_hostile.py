"""Mutations for blocking test-command shapes the #2369 row scanner must detect."""

import runpy
from pathlib import Path

_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_issue2369_skip_gate_coverage.py")))
_validation_errors = _HELPERS["_validation_errors"]
_workflow_texts = _HELPERS["_workflow_texts"]


def _mutate_widget_step(extra_command: str) -> dict[str, str]:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        f"tests/js/*.test.js\n          {extra_command}",
        1,
    )
    return texts


def test_unreported_plain_pytest_row_is_rejected() -> None:
    errors = _validation_errors(_mutate_widget_step("uv run pytest tests/unlisted-blocking-row.py"))
    assert any("test-row table mismatch" in error for error in errors)


def test_command_prefixed_node_row_is_rejected() -> None:
    errors = _validation_errors(_mutate_widget_step("command node --test tests/unlisted-blocking-row.test.js"))
    assert any("test-row table mismatch" in error for error in errors)


def test_local_report_cleanup_traps_hup_and_quit() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts/agent/run-gates.sh").read_text()
    assert "exit 129' HUP" in script
    assert "exit 131' QUIT" in script


def test_node_checker_must_read_the_native_canary_before_the_real_report() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "check_skip_allowlist.py --suite widget-js --allowlist tests/skip-allowlist.txt /tmp/widget-js-canary.xml",
        "check_skip_allowlist.py --suite widget-js --allowlist tests/skip-allowlist.txt /tmp/widget-js-junit.xml",
        1,
    )
    errors = _validation_errors(texts)
    assert any("native Node canary" in error for error in errors)


def test_producer_path_in_a_comment_does_not_satisfy_the_row() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        "\n          # tests/js/*.test.js",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: producer command is missing" in error for error in errors)


def test_non_node_rows_require_their_native_junit_producer_flags() -> None:
    mutations = (
        ("test.yml", "-o junit --reportdir /tmp/shellspec-report", "shellspec"),
        ("build-pkg-linux.yml", "-o junit --reportdir /tmp/ports-parity-junit", "ports-parity"),
        ("ui-tests.yml", 'set -- "$@" --junitxml=/tmp/ui-junit.xml', "ui"),
        (
            "smoke-single.yml",
            'set -- "$@" --junitxml=smoke-diag/pytest-junit.xml',
            "smoke",
        ),
    )
    for filename, producer_flag, suite in mutations:
        texts = _workflow_texts()
        texts[filename] = texts[filename].replace(producer_flag, "true # reporter removed", 1)
        errors = _validation_errors(texts)
        assert any(f"{suite}: JUnit producer flags are missing" in error for error in errors)


def test_each_shared_webassets_prefix_requires_its_own_canary_guard() -> None:
    texts = _workflow_texts()
    guarded = (
        "check_skip_allowlist.py --suite webassets-listgrammar --allowlist "
        "tests/skip-allowlist.txt /tmp/webassets-node-canary.xml \\\n"
        "            && { echo 'red canary failed: an unlisted skip did not fail the gate'; exit 1; }"
    )
    texts["test.yml"] = texts["test.yml"].replace(
        guarded,
        guarded.split(" \\\n", 1)[0],
        1,
    )
    errors = _validation_errors(texts)
    assert any("webassets-listgrammar: canary does not require nonzero" in error for error in errors)


def _local_runner_canary_errors(script: str) -> list[str]:
    errors: list[str] = []
    reports = {
        "pytest": (
            "$PFB_SKIP_REPORT_DIR/pytest.xml",
            'uv run --locked pytest --junitxml="$PFB_SKIP_REPORT_DIR/pytest.xml"',
        ),
        "phpunit": (
            "$PFB_SKIP_REPORT_DIR/phpunit.xml",
            'vendor/bin/phpunit --log-junit "$PFB_SKIP_REPORT_DIR/phpunit.xml"',
        ),
        "shellspec": (
            "$PFB_SKIP_REPORT_DIR/shellspec/results_junit.xml",
            "shellspec --shell $(command -v dash || command -v sh) -o junit "
            '--reportdir "$PFB_SKIP_REPORT_DIR/shellspec"',
        ),
    }
    for suite, (report, command) in reports.items():
        prefix = f"scripts/check_skip_allowlist.py --suite {suite} --allowlist tests/skip-allowlist.txt "
        canary = prefix + "tests/fixtures/skip-allowlist-canary.xml && { echo"
        real = prefix + f'"{report}"'
        if command + " || exit $?;" not in script:
            errors.append(f"{suite}: suite status is not preserved")
        if canary not in script:
            errors.append(f"{suite}: canary checker/guard is missing")
        if real not in script:
            errors.append(f"{suite}: real checker is missing")
    if 'rm -rf "$skip_report_dir"\' EXIT' not in script:
        errors.append("EXIT cleanup is missing")
    for signal, status in (("HUP", 129), ("INT", 130), ("QUIT", 131), ("TERM", 143)):
        if f"exit {status}' {signal}" not in script:
            errors.append(f"{signal} cleanup is missing")
    return errors


def test_local_runner_canary_validator_rejects_a_duplicate_real_check() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts/agent/run-gates.sh").read_text()
    assert _local_runner_canary_errors(script) == []
    mutated = script.replace(
        "scripts/check_skip_allowlist.py --suite pytest --allowlist "
        "tests/skip-allowlist.txt tests/fixtures/skip-allowlist-canary.xml && { echo",
        "scripts/check_skip_allowlist.py --suite pytest --allowlist "
        'tests/skip-allowlist.txt "$PFB_SKIP_REPORT_DIR/pytest.xml"; { echo',
        1,
    )
    assert "pytest: canary checker/guard is missing" in _local_runner_canary_errors(mutated)
