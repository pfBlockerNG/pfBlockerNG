"""Mutations for blocking test-command shapes the #2369 row scanner must detect."""

import runpy
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

_HELPERS = runpy.run_path(str(Path(__file__).with_name("test_issue2369_skip_gate_coverage.py")))
_validation_errors = _HELPERS["_validation_errors"]
_workflow_texts = _HELPERS["_workflow_texts"]
_checker = _HELPERS["checker"]
_checker_report = _HELPERS["_checker_report"]
_shell_commands = _HELPERS["_shell_commands"]


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


def test_command_prefixed_pytest_row_is_rejected() -> None:
    errors = _validation_errors(_mutate_widget_step("command uv run pytest tests/unlisted-blocking-row.py"))
    assert any("test-row table mismatch" in error for error in errors)


def test_local_report_cleanup_traps_hup_and_quit() -> None:
    script = (Path(__file__).resolve().parents[1] / "scripts/agent/run-gates.sh").read_text()
    assert "exit 129' HUP" in script
    assert "exit 131' QUIT" in script


def test_tab_prefixed_command_and_comment_shapes_are_rejected() -> None:
    command_errors = _validation_errors(_mutate_widget_step("command\tuv run pytest tests/unlisted-blocking-row.py"))
    assert any("test-row table mismatch" in error or "workflow YAML is invalid" in error for error in command_errors)

    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        "\t# tests/js/*.test.js",
        1,
    )
    comment_errors = _validation_errors(texts)
    assert any(
        "widget-js: producer command is missing" in error or "workflow YAML is invalid" in error
        for error in comment_errors
    )


def test_native_node_canary_fixture_stays_a_hostile_skip() -> None:
    fixture_path = Path(__file__).resolve().parent / "fixtures/skip-allowlist-node-canary.test.mjs"
    assert fixture_path.is_file(), "native Node canary fixture is missing"
    fixture = fixture_path.read_text()
    assert 'describe("nested # suite :: punctuation!"' in fixture
    assert 'it("skips # hash, punctuation: a::b!"' in fixture
    assert 'skip: "environment reason #42"' in fixture


def test_native_node_canary_report_is_rejected_with_exact_skip_semantics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable; the fixture byte assertions remain active")
    root = Path(__file__).resolve().parents[1]
    fixture = root / "tests/fixtures/skip-allowlist-node-canary.test.mjs"
    assert fixture.is_file(), "native Node canary fixture is missing"
    report = tmp_path / "node-canary.xml"
    subprocess.run(
        [
            node,
            "--test",
            "--test-reporter=junit",
            f"--test-reporter-destination={report}",
            str(fixture),
        ],
        cwd=root,
        check=True,
    )
    rc = _checker.main(
        [
            "--suite",
            "widget-js",
            "--allowlist",
            str(root / "tests/skip-allowlist.txt"),
            str(report),
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    # issue #3117: Node 24's JUnit reporter uses classname="test"; Node 26 uses
    # the enclosing describe name. The gate still rejects the skip; only the
    # classname half of the id changes. Accept both so a host newer than CI's
    # pin is not a false red.
    node24 = "widget-js:test::skips # hash, punctuation: a::b!  reason: environment reason #42"
    node26 = (
        "widget-js:nested # suite :: punctuation!::skips # hash, punctuation: a::b!  reason: environment reason #42"
    )
    assert node24 in err or node26 in err, err


def test_node26_junit_classname_canary_is_rejected_with_exact_skip_semantics(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Static Node-26 reporter shape so a CI pin bump to 26 cannot silently
    # change every Node skip id without this row going red first.
    root = Path(__file__).resolve().parents[1]
    report = root / "tests/fixtures/skip-allowlist-node26-canary.xml"
    rc = _checker.main(
        [
            "--suite",
            "widget-js",
            "--allowlist",
            str(root / "tests/skip-allowlist.txt"),
            str(report),
        ]
    )
    assert rc == 1
    assert (
        "widget-js:nested # suite :: punctuation!::skips # hash, punctuation: a::b!  reason: environment reason #42"
    ) in capsys.readouterr().err


@pytest.mark.parametrize(
    ("suite", "canary_report", "real_report"),
    [
        ("widget-js", "/tmp/widget-js-canary.xml", "/tmp/widget-js-junit.xml"),
        (
            "webassets-grammar",
            "/tmp/webassets-node-canary.xml",
            "/tmp/webassets-grammar-junit.xml",
        ),
        (
            "webassets-listgrammar",
            "/tmp/webassets-node-canary.xml",
            "/tmp/webassets-listgrammar-junit.xml",
        ),
        (
            "webassets-bundle",
            "/tmp/webassets-node-canary.xml",
            "/tmp/webassets-bundle-junit.xml",
        ),
    ],
)
def test_each_node_checker_reads_its_native_canary_before_its_real_report(
    suite: str,
    canary_report: str,
    real_report: str,
) -> None:
    texts = _workflow_texts()
    prefix = f"check_skip_allowlist.py --suite {suite} --allowlist tests/skip-allowlist.txt "
    texts["test.yml"] = texts["test.yml"].replace(
        prefix + canary_report,
        prefix + real_report,
        1,
    )
    errors = _validation_errors(texts)
    assert any(f"{suite}: native Node canary" in error for error in errors)


def test_producer_path_in_a_comment_does_not_satisfy_the_row() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        "\n          # tests/js/*.test.js",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: producer command is missing" in error for error in errors)


def test_inline_comment_does_not_supply_the_producer_path() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        "# tests/js/*.test.js",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: producer command is missing" in error for error in errors)


def test_producer_path_must_be_an_exact_shell_argument() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "tests/js/*.test.js",
        "not-tests/js/*.test.js",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: producer command is missing" in error for error in errors)


def test_echoed_checker_text_is_not_a_checker_invocation() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "python3 scripts/check_skip_allowlist.py --suite widget-js",
        "echo python3 scripts/check_skip_allowlist.py --suite widget-js",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: expected canary and real checker calls, got 1" in error for error in errors)


def test_direct_reporter_flags_must_stay_on_the_producer_command() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "run: uv run pytest --junitxml=/tmp/pytest-junit.xml",
        "run: |\n          uv run pytest\n          echo --junitxml=/tmp/pytest-junit.xml",
        1,
    )
    errors = _validation_errors(texts)
    assert any("pytest: JUnit producer flags are missing" in error for error in errors)


def test_node_producers_require_the_junit_reporter_not_only_a_destination() -> None:
    texts = _workflow_texts()
    texts["test.yml"] = texts["test.yml"].replace(
        "--test-reporter=junit --test-reporter-destination=/tmp/widget-js-junit.xml",
        "--test-reporter-destination=/tmp/widget-js-junit.xml",
        1,
    )
    errors = _validation_errors(texts)
    assert any("widget-js: native JUnit" in error for error in errors)


def test_node_reporter_flags_cannot_be_detached_into_a_synthetic_echo() -> None:
    texts = _workflow_texts()
    real = (
        "node --test --test-reporter=spec --test-reporter-destination=stdout "
        "--test-reporter=junit --test-reporter-destination=/tmp/widget-js-junit.xml "
        "tests/js/*.test.js"
    )
    detached = (
        "node --test tests/js/*.test.js\n"
        "          echo --test-reporter=spec --test-reporter-destination=stdout "
        "--test-reporter=junit --test-reporter-destination=/tmp/widget-js-junit.xml "
        "tests/js/*.test.js"
    )
    texts["test.yml"] = texts["test.yml"].replace(real, detached, 1)
    errors = _validation_errors(texts)
    assert any("widget-js: native JUnit" in error for error in errors)


def test_non_node_rows_require_their_native_junit_producer_flags() -> None:
    mutations = (
        ("test.yml", "--log-junit /tmp/phpunit-junit.xml", "phpunit"),
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
    checker = (
        "python3 scripts/check_skip_allowlist.py --suite webassets-listgrammar --allowlist "
        "tests/skip-allowlist.txt /tmp/webassets-node-canary.xml"
    )
    guarded = (
        f'{checker} && :; canary_status=$?; [ "$canary_status" -eq 1 ] || '
        '{ echo "red canary failed: an unlisted skip did not fail the gate '
        '(checker exit $canary_status, expected 1)"; exit 1; }'
    )
    texts["test.yml"] = texts["test.yml"].replace(guarded, checker, 1)
    errors = _validation_errors(texts)
    assert any("webassets-listgrammar: canary does not require nonzero" in error for error in errors)


def _simple_commands(script: str) -> list[tuple[tuple[str, ...], str | None]]:
    lexer = shlex.shlex(script, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    commands: list[tuple[tuple[str, ...], str | None]] = []
    pending: list[str] = []
    for token in lexer:
        if token in {";", "&&", "||"}:
            if pending:
                commands.append((tuple(pending), token))
                pending = []
        else:
            pending.append(token)
    if pending:
        commands.append((tuple(pending), None))
    return commands


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
    payloads = [argv[2] for argv in _shell_commands(script) if argv[:2] == ("printf", "%s") and len(argv) == 3]
    for suite, (report, command) in reports.items():
        payload = next((value for value in payloads if f"--suite {suite} " in value), "")
        if command + " || exit $?;" not in payload:
            errors.append(f"{suite}: suite status is not preserved")
        checks = [
            (checker_report, operator)
            for argv, operator in _simple_commands(payload)
            if (checker_report := _checker_report(argv, suite)) is not None
        ]
        if len(checks) != 2 or checks[0] != (
            "tests/fixtures/skip-allowlist-canary.xml",
            "&&",
        ):
            errors.append(f"{suite}: canary checker/guard is missing")
        if len(checks) != 2 or checks[1][0] != report:
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
    reports = {
        "pytest": "$PFB_SKIP_REPORT_DIR/pytest.xml",
        "phpunit": "$PFB_SKIP_REPORT_DIR/phpunit.xml",
        "shellspec": "$PFB_SKIP_REPORT_DIR/shellspec/results_junit.xml",
    }
    for suite, report in reports.items():
        prefix = f"scripts/check_skip_allowlist.py --suite {suite} --allowlist tests/skip-allowlist.txt "
        mutated = script.replace(
            prefix + "tests/fixtures/skip-allowlist-canary.xml",
            prefix + f'"{report}"',
            1,
        )
        assert f"{suite}: canary checker/guard is missing" in _local_runner_canary_errors(mutated)
