"""Tests for scripts/check_coverage_pairing.py.

Per CLAUDE.md's test-coverage rule, every "does NOT fire" / `== []` assertion is
paired with a sibling case that DOES fire, so a green run proves the classifier
DISCRIMINATES (src<->tests, www<->ui-tests) rather than always/never firing.
"""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path
from typing import Any

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_coverage_pairing.py"
_spec = importlib.util.spec_from_file_location("check_coverage_pairing", _TOOL)
assert _spec is not None and _spec.loader is not None
ccp: Any = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ccp
_spec.loader.exec_module(ccp)


def test_src_only_no_tests_fires_rule1() -> None:
    # Scenario: a PR touches src/ but ships no tests/ change at all -> rule 1 fires.
    violations = ccp.evaluate(["src/usr/local/pkg/pfblockerng/pfblockerng.inc"])
    assert len(violations) == 1, f"expected exactly 1 violation (rule 1); got {violations}"
    assert "tests/**" in violations[0], f"rule-1 message must name tests/**; got {violations[0]!r}"


def test_src_with_paired_test_passes() -> None:
    # Discriminating sibling of the above: adding the paired test clears rule 1.
    violations = ccp.evaluate(["src/usr/local/pkg/pfblockerng/pfblockerng.inc", "tests/test_x.py"])
    assert violations == [], f"src+tests pair must pass; got {violations}"


def test_www_only_fires_both_rules() -> None:
    # Scenario: a PR touches www/ but ships no tests/ at all -> BOTH rule 1 (no
    # tests/**) and rule 2 (no tests/smoke/ui/**) fire.
    violations = ccp.evaluate(["src/usr/local/www/pfblockerng_dnsbl.php"])
    assert len(violations) == 2, f"expected both rule 1 and rule 2 to fire; got {violations}"


def test_www_with_non_ui_test_still_fires_rule2() -> None:
    # A non-UI test satisfies rule 1 (generic src<->tests) but NOT rule 2's
    # stricter Tier-A UI requirement -- this is the precise Tier-A distinction.
    violations = ccp.evaluate(["src/usr/local/www/pfblockerng_dnsbl.php", "tests/php/FooTest.php"])
    assert len(violations) == 1, f"expected only rule 2 to still fire; got {violations}"
    assert "tests/smoke/ui/**" in violations[0], f"must name tests/smoke/ui/**; got {violations[0]!r}"


def test_www_with_ui_test_passes() -> None:
    # Discriminating sibling: a paired Tier-A UI test clears rule 2 (and rule 1,
    # since tests/smoke/ui/** is also under tests/**).
    violations = ccp.evaluate(["src/usr/local/www/pfblockerng_dnsbl.php", "tests/smoke/ui/test_render_x.py"])
    assert violations == [], f"www+ui-test pair must pass; got {violations}"


def test_warn_only_flag_downgrades_to_pass() -> None:
    # Before-state: the same src-only set FAILS (exit 1) without --warn-only.
    path = "src/usr/local/pkg/pfblockerng/pfblockerng.inc"
    assert ccp.main([path]) == 1, "without the label, a violation must fail the gate"
    # --warn-only (the no-test-needed label's CI-side effect) downgrades to pass.
    # Without --pr-body-file it keeps its pure downgrade semantics (no
    # justification requirement) — the CI job always passes both together.
    assert ccp.main(["--warn-only", path]) == 0, "--warn-only must downgrade a violation to pass"


# ---- no-test-needed justification (--pr-body-file, issue #921 via #934) ----

_SRC_ONLY = "src/usr/local/pkg/pfblockerng/pfblockerng.inc"


def _main_with_body(tmp_path: Any, body: str) -> int:
    # Scenario shared by the justification tests: a rule-1 violation + the
    # no-test-needed label (--warn-only) + the PR body handed over as the CI
    # job does. The body's justification line alone decides warn-vs-fail.
    f = tmp_path / "pr_body.txt"
    f.write_text(body, encoding="utf-8")
    return ccp.main(["--warn-only", "--pr-body-file", str(f), _SRC_ONLY])


def test_justified_body_keeps_the_warn_downgrade(tmp_path: Any) -> None:
    # A deliberate `no-test-needed: <why>` line preserves the label's downgrade;
    # CRLF bodies (GitHub API) and case variants are equally valid.
    assert _main_with_body(tmp_path, "Reasons.\nno-test-needed: comment-only change") == 0
    assert _main_with_body(tmp_path, "Reasons.\r\nNo-Test-Needed: docs move\r\n") == 0


def test_unjustified_body_fails_hard_despite_label(tmp_path: Any) -> None:
    # The label without a justification line FAILS the gate (issue #921's
    # "applied deliberately" constraint) — stricter than no label at all being
    # merely violation-driven.
    assert _main_with_body(tmp_path, "ordinary body that never mentions the token") == 1
    assert _main_with_body(tmp_path, "") == 1, "an empty PR body is not a justification"
    assert _main_with_body(tmp_path, "no-test-needed:   \n") == 1, "a blank <why> is not a justification"


def test_mentions_of_the_token_are_not_justification(tmp_path: Any) -> None:
    # The false-positive class found in PR #936's review: the check is
    # line-anchored, so prose ABOUT the feature, a blockquote, or an indented
    # line never counts — only a line the author started with the token does.
    prose = "the PR body must now contain a `no-test-needed: <why>` line"
    assert _main_with_body(tmp_path, prose) == 1, "a mid-sentence mention must not justify"
    assert _main_with_body(tmp_path, "> no-test-needed: quoted, not real") == 1, "a blockquote must not justify"
    assert _main_with_body(tmp_path, "  no-test-needed: indented") == 1, "an indented line must not justify"


def test_pr_body_file_flag_requires_a_value() -> None:
    assert ccp.main(["--warn-only", "--pr-body-file"]) == 2, "a dangling --pr-body-file must error, not crash"


def test_pr_body_file_hostile_cli_shapes(tmp_path: Any) -> None:
    # Hostile CLI rows from PR #936's fix-delta review (all unreachable via the
    # CI wiring, pinned so a refactor cannot regress them into reachability):
    justified = tmp_path / "b.txt"
    justified.write_text("no-test-needed: why", encoding="utf-8")
    # A missing body file is a clean rc-2 error, never a traceback.
    assert ccp.main(["--warn-only", "--pr-body-file", str(tmp_path / "absent.txt"), _SRC_ONLY]) == 2
    # A duplicated flag is stripped ENTIRELY (last value wins) — its value must
    # be consumed as a (here: missing) file, never leak into the path list where
    # a `tests/...`-shaped string would silently satisfy rule 1.
    assert (
        ccp.main(["--warn-only", "--pr-body-file", str(justified), "--pr-body-file", "tests/leaked.py", _SRC_ONLY]) == 2
    ), "a repeated --pr-body-file must not leak its value into the changed-path list"
    # A UTF-8 BOM at byte 0 must not hide a justification line (utf-8-sig read).
    bom = tmp_path / "bom.txt"
    bom.write_text("\ufeffno-test-needed: bom-leading body", encoding="utf-8")
    assert ccp.main(["--warn-only", "--pr-body-file", str(bom), _SRC_ONLY]) == 0


def test_docs_only_diff_is_neutral() -> None:
    # A .md under src/ is still neutral (docs-under-src does not count as src code).
    violations = ccp.evaluate(
        [
            "README.md",
            "docs/misc/architecture-notes.md",
            "src/usr/local/pkg/pfblockerng/CHANGELOG.md",
        ]
    )
    assert violations == [], f"docs-only diff must never fire either rule; got {violations}"


# ---- Hostile-input rows ---------------------------------------------------


def test_empty_diff_passes() -> None:
    assert ccp.evaluate([]) == []


def test_delete_or_rename_only_src_path_still_counts_as_change() -> None:
    # No special-casing of delete/rename-only paths: a bare path string still
    # counts (the diff carries no change-type info to this classifier anyway).
    violations = ccp.evaluate(["src/usr/local/pkg/pfblockerng/removed.inc"])
    assert violations != [], "a lone changed src path (even delete/rename-only) must still fire"


def test_www_legacy_is_not_treated_as_www() -> None:
    # Boundary guard: "www-legacy" must not match the "src/usr/local/www/"
    # trailing-slash boundary -- it is generic src, not the www/Tier-A surface.
    # Paired with a plain (non-UI) test it must fully pass (rule 2 never fires).
    violations = ccp.evaluate(["src/usr/local/www-legacy/x.php", "tests/test_x.py"])
    assert violations == [], f"www-legacy + a plain test must pass (not treated as www); got {violations}"
    # Discriminating sibling: alone (no test at all) it still fires rule 1 as
    # generic src -- proving it IS classified as src, just not as www.
    alone = ccp.evaluate(["src/usr/local/www-legacy/x.php"])
    assert len(alone) == 1, f"www-legacy alone must fire generic rule 1 only; got {alone}"
    assert "tests/smoke/ui/**" not in alone[0], "www-legacy must not trigger the www/Tier-A rule"


def test_tests_helper_under_src_is_src_not_test() -> None:
    # "tests_helper.inc" living under src/ is src code, not a test -- it must
    # still require a paired tests/** change.
    violations = ccp.evaluate(["src/usr/local/pkg/pfblockerng/tests_helper.inc"])
    assert violations != [], "src/.../tests_helper.inc must still require a paired test"


def test_sibling_othertests_dir_does_not_satisfy_test_requirement() -> None:
    # A path under a sibling "othertests/" directory (not "tests/") must NOT
    # satisfy the test requirement.
    violations = ccp.evaluate(["src/x.inc", "othertests/x.py"])
    assert violations != [], "othertests/ is not tests/ and must not satisfy rule 1"


def test_main_reads_stdin_when_no_positional_paths(monkeypatch: Any) -> None:
    # The workflow pipes `git diff --name-only` output via stdin (no positional
    # args). Blank lines must be tolerated/skipped.
    monkeypatch.setattr("sys.stdin", io.StringIO("src/x.inc\n\n"))
    assert ccp.main([]) == 1, "stdin-fed src-only path (blank line skipped) must fail the gate"


def test_positional_args_are_whitespace_normalized() -> None:
    # A positional path is stripped the same as a stdin line, so a padded arg is
    # classified (not silently dropped into no category). Before-state: without
    # the strip, the padded path matched no classifier and the gate passed.
    assert ccp.main(["  src/x.inc  "]) == 1, "a padded src path must still fire the gate"
    # Discriminating sibling: a padded docs path is still neutral (stays a pass).
    assert ccp.main([" README.md "]) == 0, "a padded docs path must stay neutral"


def test_uppercase_md_extension_is_neutral() -> None:
    # _is_docs matches `.md` case-insensitively, so an uppercase `.MD` under src/
    # is still docs-neutral -- paired with a firing sibling to prove discrimination.
    assert ccp.evaluate(["src/usr/local/pkg/pfblockerng/NOTES.MD"]) == [], "an uppercase .MD is docs, neutral"
    assert ccp.evaluate(["src/usr/local/pkg/pfblockerng/notes.inc"]) != [], "a .inc sibling is src code, fires"
