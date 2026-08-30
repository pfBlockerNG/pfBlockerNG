"""Tests for scripts/check_skip_allowlist.py (issue #2359).

PROBLEM PINNED
--------------
#2356 found nine PHPUnit cases that had silently skipped in CI for a year; the
only signal was the wording of a summary line ("OK, but some tests were
skipped!"), which gates nothing. This script fails a suite's report when it
skips a test not on ``tests/skip-allowlist.txt``, so a NEW silent skip is
caught at the commit that causes it, for all three suites (pytest, PHPUnit,
shellspec) sharing one allowlist file (ids are suite-prefixed).

Every case here builds a JUnit report by hand rather than shelling out to a
real suite -- this file pins the CONTRACT (id derivation per suite, exit
codes, allowlist parsing, hostile input); the real reports are exercised
separately by the CI wiring (the "Skip allowlist" step in each job) and by
this task's verification runs (never reasoned through, per testing.md).

Covers BOTH branches per dimension: every allowlisted-and-observed case is
paired with an unlisted-skip sibling, so a green proves the gate discriminates
rather than always passing (or always failing).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_skip_allowlist.py"
_spec = importlib.util.spec_from_file_location("check_skip_allowlist", _TOOL)
assert _spec is not None and _spec.loader is not None
csa = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = csa
_spec.loader.exec_module(csa)


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #


def _junit(testcases_xml: str, *, nested: bool = False) -> str:
    """A minimal JUnit report wrapping the given <testcase>...</testcase> XML."""
    inner = f'<testsuite name="inner" tests="1">{testcases_xml}</testsuite>' if nested else testcases_xml
    body = f'<testsuites><testsuite name="t" tests="1">{inner}</testsuite></testsuites>\n'
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + body


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _allowlist(tmp_path: Path, lines: list[str]) -> Path:
    return _write(tmp_path, "allow.txt", "\n".join(lines) + "\n")


def _report(tmp_path: Path, name: str, testcases_xml: str, *, nested: bool = False) -> Path:
    return _write(tmp_path, name, _junit(testcases_xml, nested=nested))


# --------------------------------------------------------------------------- #
# Suite id normalisation — each suite's OWN probed JUnit shape (brief #2359).
# --------------------------------------------------------------------------- #


def test_pytest_id_is_suite_colon_dotted_classname_double_colon_name(tmp_path: Path) -> None:
    tc = (
        '<testcase classname="tests.test_build_pkg_portable" '
        'name="test_output_macos_os_alias_is_allowed[/tmp-/private/tmp]" time="0.01">'
        "<skipped/></testcase>"
    )
    report = _report(tmp_path, "r.xml", tc)
    skips = csa.parse_report(report, "pytest")
    assert skips == [
        (
            "pytest:tests.test_build_pkg_portable::test_output_macos_os_alias_is_allowed[/tmp-/private/tmp]",
            None,
        )
    ]


def test_phpunit_id_uses_classname_not_class(tmp_path: Path) -> None:
    tc = (
        '<testcase name="test_octet_stream_archive_recovered_to_zip" '
        'class="OctetStreamRecoveryWiringTest" classname="OctetStreamRecoveryWiringTest" time="0">'
        "<skipped/></testcase>"
    )
    report = _report(tmp_path, "r.xml", tc)
    skips = csa.parse_report(report, "phpunit")
    assert skips == [("phpunit:OctetStreamRecoveryWiringTest::test_octet_stream_archive_recovered_to_zip", None)]


def test_shellspec_id_keeps_the_spaced_spec_description_as_name(tmp_path: Path) -> None:
    # <skip/>, not <skipped/>: that is the element shellspec's own JUnit generator writes.
    tc = (
        '<testcase time="0" classname="tests/shell/pfblockerng_adr26_locale_spec.sh" '
        'name="sorts z before a-umlaut under C, and the other way round under de_DE.UTF-8">'
        "<skip/></testcase>"
    )
    report = _report(tmp_path, "r.xml", tc)
    skips = csa.parse_report(report, "shellspec")
    assert skips == [
        (
            "shellspec:tests/shell/pfblockerng_adr26_locale_spec.sh::sorts z before a-umlaut "
            "under C, and the other way round under de_DE.UTF-8",
            None,
        )
    ]


# --------------------------------------------------------------------------- #
# Verdict — allowlisted vs unlisted, single and multiple.
# --------------------------------------------------------------------------- #


def test_all_skips_allowlisted_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tc = '<testcase classname="C" name="a"><skipped message="why"/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    allow = _allowlist(tmp_path, ["pytest:C::a  # tracked reason"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 0
    assert capsys.readouterr().err == ""


def test_one_unlisted_skip_exits_1_and_prints_id_and_reason(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tc = '<testcase classname="C" name="a"><skipped message="new drift"/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    allow = _allowlist(tmp_path, ["# nothing allowlisted yet"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "pytest:C::a" in err
    assert "new drift" in err


def test_several_unlisted_skips_all_printed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tcs = (
        '<testcase classname="C" name="a"><skipped message="one"/></testcase>'
        '<testcase classname="C" name="b"><skipped message="two"/></testcase>'
        '<testcase classname="C" name="c"><skipped message="three"/></testcase>'
    )
    report = _report(tmp_path, "r.xml", tcs)
    allow = _allowlist(tmp_path, ["# empty"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    err = capsys.readouterr().err
    for name, reason in (("a", "one"), ("b", "two"), ("c", "three")):
        assert f"pytest:C::{name}" in err
        assert reason in err


# --------------------------------------------------------------------------- #
# Input failure — exit 2, never 0 (a vanished input must not read as clean).
# --------------------------------------------------------------------------- #


def test_missing_report_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    allow = _allowlist(tmp_path, ["# empty"])
    missing = tmp_path / "nope.xml"
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(missing)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_empty_report_file_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """An empty report says so, rather than being reported as malformed XML: the two mean
    different things to whoever reads the failed job — a suite that wrote nothing versus a
    report that was truncated. The fixture is NOT named empty.xml, so the word can only
    reach the message from the diagnosis and not from the path."""
    allow = _allowlist(tmp_path, ["# empty"])
    report = _write(tmp_path, "r.xml", "")
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "empty" in err
    assert "well-formed" not in err


def test_unparsable_report_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    allow = _allowlist(tmp_path, ["# empty"])
    report = _write(tmp_path, "garbled.xml", "<testsuites><testsuite><unterminated")
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 2
    assert "not well-formed" in capsys.readouterr().err.lower()


def test_missing_allowlist_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    missing_allow = tmp_path / "nope.txt"
    rc = csa.main(["--suite", "pytest", "--allowlist", str(missing_allow), str(report)])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Allowlist parsing.
# --------------------------------------------------------------------------- #


def test_allowlist_comment_and_blank_lines_are_ignored(tmp_path: Path) -> None:
    allow = _allowlist(
        tmp_path,
        [
            "# a full-line comment",
            "",
            "   ",
            "pytest:C::a  # tracked reason",
        ],
    )
    assert csa.parse_allowlist(allow) == {"pytest:C::a": "tracked reason"}


def test_allowlist_trailing_whitespace_on_the_line_is_tolerated(tmp_path: Path) -> None:
    allow = _write(tmp_path, "allow.txt", "pytest:C::a  # tracked reason   \n")
    assert csa.parse_allowlist(allow) == {"pytest:C::a": "tracked reason"}


def test_allowlist_that_is_not_utf8_exits_2(tmp_path: Path) -> None:
    """Undecodable bytes are an unusable allowlist, which is exit 2 like a missing one --
    the checker never reports a clean run because it could not read its own input."""
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = tmp_path / "allow.txt"
    allow.write_bytes(b"pytest:C::a  # reason \xff\xfe\n")
    assert csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)]) == 2


def test_shellspec_skip_element_is_observed(tmp_path: Path) -> None:
    """shellspec 0.28.1 writes `<skip message="..."/>`, not `<skipped>` -- probed against
    the real generator. Matching only `<skipped>` made the shellspec leg of the gate blind:
    it reported a clean run for a report that recorded skips, which is the exact failure
    this gate exists to catch."""
    report = _write(
        tmp_path,
        "ss.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<testsuites><testsuite name="shellspec">\n'
        '<testcase time="0" classname="tests/shell/x_spec.sh" name="x is skipped">\n'
        '<skip message="needs docker" />\n'
        "</testcase></testsuite></testsuites>\n",
    )
    assert csa.parse_report(report, "shellspec") == [("shellspec:tests/shell/x_spec.sh::x is skipped", "needs docker")]


def test_canary_fixture_carries_both_skip_element_shapes() -> None:
    """The CI red canary runs with --suite shellspec too, so it has to trip a parser that
    reads shellspec's `<skip>` as well as the `<skipped>` pytest and PHPUnit write."""
    canary = (Path(__file__).resolve().parent.parent / "tests/fixtures/skip-allowlist-canary.xml").read_text(
        encoding="utf-8"
    )
    assert "<skipped" in canary
    assert "<skip " in canary


def test_allowlist_id_may_contain_a_hash(tmp_path: Path) -> None:
    """A pytest parametrised id can carry a '#', so the reason is separated by TWO OR MORE
    spaces before the '#' rather than by any '#' on the line. A bare split would truncate
    the id, and the skip it names could then never be recorded."""
    allow = _write(tmp_path, "allow.txt", "pytest:C::test_x[a#b]  # tracked reason\n")
    assert csa.parse_allowlist(allow) == {"pytest:C::test_x[a#b]": "tracked reason"}


def test_allowlist_id_may_contain_a_spaced_hash(tmp_path: Path) -> None:
    """PHPUnit names an unnamed data-set case `<method> with data set #0`, so a real id can
    carry a SPACE-preceded '#'. Splitting on the first one truncates that id into something
    no run produces, and the skip it names could then never be recorded — the gate would
    fail on it forever, whatever the allowlist said."""
    allow = _write(
        tmp_path,
        "allow.txt",
        "phpunit:ProbeTest::testFoo with data set #0  # provider case skips off-appliance\n",
    )
    assert csa.parse_allowlist(allow) == {
        "phpunit:ProbeTest::testFoo with data set #0": "provider case skips off-appliance"
    }


def test_allowlist_id_may_contain_a_spaced_hash_from_a_parameter(tmp_path: Path) -> None:
    """A pytest parameter value can contain " # " -- pytest renders it into the id
    verbatim. The separator is therefore TWO-OR-MORE spaces before the '#', the convention
    every entry in the file already uses, so no id shape any suite generates is
    unrecordable."""
    allow = _write(tmp_path, "allow.txt", "pytest:C::test_x[see # this]  # parametrised skip\n")
    assert csa.parse_allowlist(allow) == {"pytest:C::test_x[see # this]": "parametrised skip"}


def test_allowlist_id_may_contain_the_separator_shape_itself(tmp_path: Path) -> None:
    """A pytest parameter value can contain two spaces and a '#' — the separator shape —
    and pytest renders it into the id verbatim. The split therefore takes the RIGHTMOST
    separator: the id is the suite's to generate and cannot be constrained, while the
    reason is ours to write."""
    allow = _write(tmp_path, "allow.txt", "pytest:C::test_x[foo  # bar]  # parametrised skip\n")
    assert csa.parse_allowlist(allow) == {"pytest:C::test_x[foo  # bar]": "parametrised skip"}


def test_allowlist_single_space_before_the_hash_is_a_parse_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """One space cannot be told apart from a '#' inside an id, so it is refused rather than
    guessed -- and the message says what the separator has to be."""
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = _write(tmp_path, "allow.txt", "pytest:C::a # tracked reason\n")
    assert csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)]) == 2
    assert "two spaces" in capsys.readouterr().err


def test_allowlist_reason_may_contain_a_hash(tmp_path: Path) -> None:
    """The reason is free text and often carries an issue reference."""
    allow = _write(tmp_path, "allow.txt", "pytest:C::a  # see #2359 for the cause\n")
    assert csa.parse_allowlist(allow) == {"pytest:C::a": "see #2359 for the cause"}


def test_allowlist_crlf_line_endings_parse_the_same_as_lf(tmp_path: Path) -> None:
    allow = tmp_path / "allow.txt"
    allow.write_bytes(b"pytest:C::a  # tracked reason\r\npytest:C::b  # other\r\n")
    assert csa.parse_allowlist(allow) == {"pytest:C::a": "tracked reason", "pytest:C::b": "other"}


def test_allowlist_duplicate_entry_does_not_raise(tmp_path: Path) -> None:
    allow = _allowlist(
        tmp_path,
        ["pytest:C::a  # first reason", "pytest:C::a  # restated reason"],
    )
    reasons = csa.parse_allowlist(allow)
    assert "pytest:C::a" in reasons


def test_allowlist_entry_with_no_reason_exits_2(tmp_path: Path) -> None:
    allow = _allowlist(tmp_path, ["pytest:C::a"])
    with pytest.raises(csa.AllowlistError):
        csa.parse_allowlist(allow)


def test_allowlist_entry_with_no_reason_via_cli_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = _allowlist(tmp_path, ["pytest:C::a"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 2
    assert "reason" in capsys.readouterr().err.lower()


def test_allowlist_comment_only_file_parses_to_empty_and_gate_still_fires(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allow = _allowlist(tmp_path, ["# nothing here yet", "# still nothing"])
    assert csa.parse_allowlist(allow) == {}
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    assert "pytest:C::a" in capsys.readouterr().err


def test_allowlist_line_that_is_only_a_hash_is_a_comment_not_an_error(tmp_path: Path) -> None:
    allow = _allowlist(tmp_path, ["#", "pytest:C::a  # tracked reason"])
    assert csa.parse_allowlist(allow) == {"pytest:C::a": "tracked reason"}


# --------------------------------------------------------------------------- #
# Skip-reason surfacing.
# --------------------------------------------------------------------------- #


def test_skipped_message_attribute_is_the_reason(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a"><skipped message="host file(1) classification"/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a", "host file(1) classification")]


def test_skipped_element_text_is_the_reason_when_no_message_attribute(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a"><skipped>reason as element text</skipped></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a", "reason as element text")]


def test_bare_skipped_element_has_no_reason(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a", None)]


def test_unlisted_skip_with_no_reason_prints_placeholder_not_blank(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = _allowlist(tmp_path, ["# empty"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "pytest:C::a" in err
    assert "no reason given" in err.lower()


# --------------------------------------------------------------------------- #
# XML shape.
# --------------------------------------------------------------------------- #


def test_nested_testsuite_elements_are_still_scanned(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc, nested=True)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a", None)]


def test_testcase_with_no_skipped_child_is_not_counted(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a" time="0.01"></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == []


def test_failure_child_is_not_counted_as_a_skip(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a"><failure message="boom">trace</failure></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == []


def test_failure_and_skip_siblings_only_the_skip_counts(tmp_path: Path) -> None:
    tcs = (
        '<testcase classname="C" name="a"><failure message="boom">trace</failure></testcase>'
        '<testcase classname="C" name="b"><skipped/></testcase>'
    )
    report = _report(tmp_path, "r.xml", tcs)
    assert csa.parse_report(report, "pytest") == [("pytest:C::b", None)]


def test_duplicate_testcase_ids_are_rejected_before_allowlist_matching(tmp_path: Path) -> None:
    tcs = (
        '<testcase classname="test" name="same name"></testcase>'
        '<testcase classname="test" name="same name"><skipped/></testcase>'
    )
    report = _report(tmp_path, "r.xml", tcs)
    with pytest.raises(csa.ReportError, match="duplicate testcase id"):
        csa.parse_report(report, "webassets-bundle")


def test_non_node_reports_keep_their_reporter_defined_duplicate_semantics(tmp_path: Path) -> None:
    tcs = (
        '<testcase classname="C" name="same name"></testcase>'
        '<testcase classname="C" name="same name"><skip message="second occurrence"/></testcase>'
    )
    report = _report(tmp_path, "r.xml", tcs)
    assert csa.parse_report(report, "shellspec") == [("shellspec:C::same name", "second occurrence")]


# --------------------------------------------------------------------------- #
# Allowlist vs observed.
# --------------------------------------------------------------------------- #


def test_listed_and_observed_is_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = _allowlist(tmp_path, ["pytest:C::a  # tracked"])
    assert csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)]) == 0


def test_listed_but_not_observed_is_informational_and_still_exits_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A PHP-build-gated case skips on one PHP version and not the other (brief
    # #2359) -- an allowlisted id absent from THIS run's report must not fail it.
    report = _report(tmp_path, "r.xml", '<testcase classname="C" name="a"><skipped/></testcase>')
    allow = _allowlist(tmp_path, ["pytest:C::a  # tracked", "pytest:C::gone  # only skips on the other leg"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pytest:C::gone" in out


# --------------------------------------------------------------------------- #
# CI wiring — the report flag lands on the command, the gate consumes that path.
# --------------------------------------------------------------------------- #


def test_workflow_wires_report_flag_and_gate_step_per_job() -> None:
    import yaml

    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/test.yml").read_text())
    jobs = workflow["jobs"]

    cases = {
        "test": ("Run tests", "pytest", "--junitxml="),
        "php-unit": ("Run PHPUnit (with coverage)", "phpunit", "--log-junit "),
        "shell-tests": ("Run shellspec", "shellspec", None),  # shellspec: --reportdir, not a bare flag=path
    }
    for job_name, (run_step_name, suite, flag_prefix) in cases.items():
        steps = jobs[job_name]["steps"]
        run_step = next((s for s in steps if s.get("name") == run_step_name), None)
        gate_step = next((s for s in steps if s.get("name") == "Skip allowlist"), None)
        assert run_step is not None, f"{job_name}: no step named {run_step_name!r}"
        assert gate_step is not None, f"{job_name}: no step named 'Skip allowlist'"
        assert f"--suite {suite}" in gate_step["run"]
        assert "check_skip_allowlist.py" in gate_step["run"]
        assert "tests/skip-allowlist.txt" in gate_step["run"]
        assert "skip-allowlist-canary.xml" in gate_step["run"], "gate step must prove its own red path"
        if flag_prefix:
            assert flag_prefix in run_step["run"]
        else:
            assert "-o junit" in run_step["run"] and "--reportdir" in run_step["run"]


def test_all_tests_passed_still_gates_on_the_three_report_producing_jobs() -> None:
    import yaml

    workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/test.yml").read_text())
    needs = workflow["jobs"]["all-tests-passed"]["needs"]
    for job_name in ("test", "php-unit", "shell-tests"):
        assert job_name in needs


# --------------------------------------------------------------------------- #
# Hostile input.
# --------------------------------------------------------------------------- #


def test_xml_entity_in_test_name_is_unescaped_in_the_id(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a &amp; b &lt;tag&gt;"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a & b <tag>", None)]


def test_non_ascii_unicode_name_round_trips(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="tést_中文_\U0001f600"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::tést_中文_\U0001f600", None)]


def test_name_containing_double_colon_itself_is_kept_verbatim(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a::b::c"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::a::b::c", None)]


def test_name_containing_a_newline_does_not_crash(tmp_path: Path) -> None:
    tc = '<testcase classname="C" name="a&#10;b"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    skips = csa.parse_report(report, "pytest")
    assert skips == [("pytest:C::a\nb", None)]


def test_empty_classname_yields_empty_classname_segment(tmp_path: Path) -> None:
    tc = '<testcase classname="" name="a"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:::a", None)]


def test_missing_name_attribute_defaults_to_empty(tmp_path: Path) -> None:
    tc = '<testcase classname="C"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    assert csa.parse_report(report, "pytest") == [("pytest:C::", None)]


def test_id_differing_only_by_trailing_whitespace_from_allowlist_entry_is_unlisted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No fuzzy matching: a genuinely different observed id (here, one with a
    # trailing space baked into the reported `name`) must not be silently
    # absorbed by a similar-looking allowlist entry.
    tc = '<testcase classname="C" name="a "><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    allow = _allowlist(tmp_path, ["pytest:C::a  # tracked reason"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    assert "pytest:C::a " in capsys.readouterr().err


def test_allowlist_line_that_is_only_a_hash_alone_in_file(tmp_path: Path) -> None:
    allow = _allowlist(tmp_path, ["#"])
    assert csa.parse_allowlist(allow) == {}


def test_allowlist_entry_for_a_different_suite_prefix_does_not_satisfy_this_suite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tc = '<testcase classname="C" name="a"><skipped/></testcase>'
    report = _report(tmp_path, "r.xml", tc)
    allow = _allowlist(tmp_path, ["phpunit:C::a  # tracked for a different suite"])
    rc = csa.main(["--suite", "pytest", "--allowlist", str(allow), str(report)])
    assert rc == 1
    assert "pytest:C::a" in capsys.readouterr().err


def test_shellspec_real_report_control_byte_defect_is_sanitized_not_unparsable(tmp_path: Path) -> None:
    # shellspec 0.28.1's own JUnit writer embeds a raw XML-1.0-illegal control
    # byte verbatim when a spec description carries one (probed in the image:
    # tests/shell/agent_run_gates_git_spec.sh's C-quoted-path fixtures use a
    # literal 0x01 byte) -- that byte has no legal XML representation, so a
    # strict parse of shellspec's REAL report always raises. This must be
    # healed before parsing, not reported as "unparsable" (report_error).
    raw = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="t" tests="1">'
        '<testcase classname="tests/shell/agent_run_gates_git_spec.sh" '
        "name=\"a file named 'has\x01control'\"><skipped/></testcase>"
        "</testsuite></testsuites>\n"
    ).encode("utf-8")
    report = tmp_path / "r.xml"
    report.write_bytes(raw)
    skips = csa.parse_report(report, "shellspec")
    assert len(skips) == 1
    assert skips[0][0].startswith("shellspec:tests/shell/agent_run_gates_git_spec.sh::a file named 'has")


def test_genuinely_malformed_xml_is_still_unparsable_after_sanitizing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The control-byte heal above must not widen into "any broken XML passes":
    # truncated/mismatched tags stay a hard parse error.
    allow = _allowlist(tmp_path, ["# empty"])
    report = _write(tmp_path, "garbled.xml", "<testsuites><testsuite><testcase")
    rc = csa.main(["--suite", "shellspec", "--allowlist", str(allow), str(report)])
    assert rc == 2
    assert "not well-formed" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------- #
# Canary fixture — usable for every --suite value (the CI red canary needs this).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("suite", ["pytest", "phpunit", "shellspec"])
def test_canary_fixture_is_never_on_the_real_allowlist(suite: str, capsys: pytest.CaptureFixture[str]) -> None:
    root = Path(__file__).resolve().parents[1]
    canary = root / "tests/fixtures/skip-allowlist-canary.xml"
    real_allowlist = root / "tests/skip-allowlist.txt"
    rc = csa.main(["--suite", suite, "--allowlist", str(real_allowlist), str(canary)])
    assert rc == 1, f"canary must never be satisfied by the real allowlist for --suite {suite}"


# --------------------------------------------------------------------------- #
# Real allowlist file — every entry carries a reason (the file cannot rot).
# --------------------------------------------------------------------------- #


# Suite prefixes the allowlist may legitimately carry, one per --suite value the gates pass:
# run-gates.sh uses pytest/phpunit/shellspec; the live workflows use ui/smoke.
_ALLOWLIST_SUITES = ("pytest", "phpunit", "shellspec", "ui", "smoke")


def test_real_allowlist_file_parses_cleanly() -> None:
    root = Path(__file__).resolve().parents[1]
    allow = root / "tests/skip-allowlist.txt"
    entries = csa.parse_allowlist(allow)
    assert entries, "tests/skip-allowlist.txt must seed at least the known PHPUnit/pytest skips"
    for entry_id in entries:
        assert entry_id.split(":", 1)[0] in _ALLOWLIST_SUITES, entry_id


def test_default_smoke_skips_are_allowlisted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = Path(__file__).resolve().parents[1]
    testcases = "".join(
        f'<testcase classname="{classname}" name="{name}"><skipped message="expected"/></testcase>'
        for classname, name in (
            ("tests.smoke.test_smoke_714_asn_geoip", "test_714_c1_asn_table_logs_not_stray_file"),
            ("tests.smoke.test_smoke_714_asn_geoip", "test_714_c8_geoip_single_ip_preserved"),
            ("tests.smoke.test_smoke_boot", "test_control_name_resolves"),
            ("tests.smoke.test_smoke_helpers", "test_reset_returns_to_baseline"),
            ("tests.smoke.test_smoke_matrix", "test_false_green_guard_vm"),
        )
    )
    report = _report(tmp_path, "smoke.xml", testcases)
    rc = csa.main(
        [
            "--suite",
            "smoke",
            "--allowlist",
            str(root / "tests/skip-allowlist.txt"),
            str(report),
        ]
    )
    assert rc == 0, capsys.readouterr().err
