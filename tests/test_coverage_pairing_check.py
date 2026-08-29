"""Tests for scripts/check_coverage_pairing.py.

Per CLAUDE.md's test-coverage rule, every "does NOT fire" / `== []` assertion is
paired with a sibling case that DOES fire, so a green run proves the classifier
DISCRIMINATES (src<->tests, www<->ui-tests) rather than always/never firing.
"""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import subprocess
import sys
import textwrap
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


def test_violation_message_says_rerun_after_labeling() -> None:
    # issue #969: the remedy must work as written — labels/body are re-read live,
    # so the hint tells the author a plain re-run suffices after labeling.
    violations = ccp.evaluate(["src/usr/local/pkg/pfblockerng/pfblockerng.inc"])
    assert "re-run this check" in violations[0], f"hint must say re-run works; got {violations[0]!r}"


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


# ---- Upstream data snapshots (issue #2132) --------------------------------

# Spelled out rather than imported from the tool: the exempt set is a policy
# decision, so the test states it independently and a silent widening of the
# tool's own set cannot rewrite the expectation it is checked against.
_EXEMPT_DATA_PATHS = (
    "src/usr/local/pkg/pfblockerng/dnsbl_psl",
    "src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt",
    "src/usr/local/www/pfblockerng/vendor/codemirror/MANIFEST.sha256",
)


def test_upstream_data_snapshot_refresh_is_neutral() -> None:
    # A diff whose whole content is a regenerated upstream snapshot has nothing
    # hand-authored to pair a test with, so the gate stays silent (issue #2132).
    for path in _EXEMPT_DATA_PATHS:
        assert ccp.evaluate([path]) == [], f"{path} is upstream data, must never fire a rule"


def test_exempt_set_matches_the_documented_policy_set() -> None:
    # The tool's set and the policy set above are the same set: an addition made
    # in the tool alone (widening the exemption unreviewed) fails here.
    assert ccp._DATA_ONLY == frozenset(_EXEMPT_DATA_PATHS), (
        f"tool exemption set drifted from the documented policy set; got {sorted(ccp._DATA_ONLY)}"
    )


def test_data_snapshot_neutrality_does_not_excuse_a_real_src_change() -> None:
    # Discriminating sibling: neutral means "ignored", never "satisfies". A real
    # src file riding along in the same diff still demands its paired test.
    both = ["src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt", "src/usr/local/pkg/pfblockerng/pfblockerng.inc"]
    violations = ccp.evaluate(both)
    assert len(violations) == 1, f"a real src file alongside data must still fire rule 1; got {violations}"
    assert "tests/**" in violations[0], f"rule-1 message must name tests/**; got {violations[0]!r}"


def test_every_exempt_path_still_exists_in_the_tree() -> None:
    # A rename or deletion upstream of the exemption would leave a dead entry
    # silently exempting nothing while the renamed file goes back to being
    # gated with no one noticing. Pin each entry to a real tracked file.
    repo = Path(__file__).resolve().parent.parent
    # splitlines(), not split(): git emits one path per line and a path may
    # legitimately contain spaces.
    tracked = set(
        subprocess.run(["git", "ls-files"], cwd=repo, capture_output=True, text=True, check=True).stdout.splitlines()
    )
    dead = [p for p in _EXEMPT_DATA_PATHS if p not in tracked]
    assert dead == [], f"exempt paths no longer tracked (renamed/deleted?): {dead}"


def test_exempt_www_asset_clears_the_tier_a_rule_too() -> None:
    # The manifest lives under src/usr/local/www/, so its neutrality must reach
    # the stricter www<->ui rule too, not just rule 1.
    manifest = "src/usr/local/www/pfblockerng/vendor/codemirror/MANIFEST.sha256"
    assert ccp.evaluate([manifest]) == [], "the vendored digest manifest must clear BOTH rules"
    # Discriminating sibling: a really-shipped asset in the same vendor
    # directory still fires both rules -- the exemption is path-exact, not a
    # blanket pass for everything under vendor/.
    sibling = ccp.evaluate(["src/usr/local/www/pfblockerng/vendor/codemirror/cm-hooks.min.js"])
    assert len(sibling) == 2, f"a real vendored asset must still fire both rules; got {sibling}"


def test_data_exemption_is_exact_path_not_a_prefix() -> None:
    # Hostile row: the exemption matches whole paths only. A neighbour whose name
    # merely EXTENDS an exempt path is ordinary src code and stays gated -- a
    # prefix/startswith implementation would silently exempt it.
    assert ccp.evaluate(["src/usr/local/pkg/pfblockerng/dnsbl_tld_overrides"]) != [], (
        "a path that only extends an exempt name is still src code"
    )
    assert ccp.evaluate(["src/usr/local/pkg/pfblockerng/pfb_py_hsts.txt.in"]) != [], (
        "a generator template beside an exempt snapshot is still src code"
    )


def test_behaviour_bearing_data_files_stay_gated() -> None:
    # The exemption is deliberately narrow: files under src/ that LOOK like data
    # but change what the appliance does are NOT exempt (issue #2132's
    # out-of-scope list). Unbound config decides what the resolver answers; the
    # feed/ASN catalogs decide what the UI offers; a *_global_usage file carries
    # a blacklist provider's download URL and the category allowlist the
    # Blacklist page validates against, so editing one is a behaviour change.
    for path in (
        "src/usr/local/pkg/pfblockerng/pfb_dnsbl.safesearch.conf",
        "src/usr/local/pkg/pfblockerng/pfb_dnsbl.doh.conf",
        "src/usr/local/www/pfblockerng/pfblockerng_feeds.json",
        "src/usr/local/www/pfblockerng/pfblockerng_asn.txt",
        "src/usr/local/pkg/pfblockerng/ut1_global_usage",
        "src/usr/local/pkg/pfblockerng/shallalist_global_usage",
    ):
        assert ccp.evaluate([path]) != [], f"{path} is behaviour, not data -- it must stay gated"


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


# ---- Release-plane pairing and frozen-RED proof (issue #2415) ------------

_RELEASE_SCRIPT = "scripts/dispatch-pkg-publication.sh"
_RELEASE_TEST = "tests/test_coverage_pairing_check.py"


def _frozen_red_body(test_path: str, digest: str, tail: str = "FAILED test_release_plane") -> str:
    return (
        "| Frozen RED test | `git hash-object` | RED run tail |\n"
        "| --- | --- | --- |\n"
        f"| `{test_path}` | `{digest}` | `{tail}` |\n"
    )


def _working_tree_hash(path: str) -> str:
    repo = Path(__file__).resolve().parent.parent
    return subprocess.check_output(["git", "hash-object", "--", path], cwd=repo, text=True).strip()


def test_release_plane_change_without_shipped_test_fails() -> None:
    violations = ccp.evaluate([_RELEASE_SCRIPT])
    assert len(violations) == 1, f"release script without a test must fail once; got {violations}"
    assert "release-plane" in violations[0], f"violation must name the gated plane; got {violations[0]!r}"


def test_release_plane_recorded_red_hash_must_match_shipped_test(tmp_path: Any, capsys: Any) -> None:
    body = tmp_path / "pr-body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, "0" * 40), encoding="utf-8")

    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1
    assert _RELEASE_TEST in capsys.readouterr().out


def test_every_release_plane_path_class_is_gated() -> None:
    for path in (
        "scripts/dispatch-pkg-publication.sh",
        "scripts/agent/run-gates.sh",
        "scripts/release-notes-prompt.txt",
        ".github/workflows/nightly.yml",
        ".github/actions/read-version-matrix/action.yml",
        ".github/actionlint.yaml",
    ):
        assert ccp.evaluate([path]) != [], f"{path} is release-plane behaviour and must require a shipped test"


def test_release_plane_change_with_shipped_test_clears_pairing() -> None:
    assert ccp.evaluate([_RELEASE_SCRIPT, _RELEASE_TEST]) == []
    assert ccp.evaluate([".github/workflows/test.yml", "tests/smoke/test_stub_shapes.py"]) == []


def test_release_plane_neutral_classes_stay_neutral() -> None:
    for path in (
        "scripts/README.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/agents/adversarial-reviewer.agent.md",
        ".github/copilot-instructions.md",
        ".agents/policy/testing.md",
        ".claude/hooks/session-start.sh",
        "legacy/archive/tool.py",
        "docs/release.md",
    ):
        assert ccp.evaluate([path]) == [], f"{path} is neutral and must not trigger release-plane pairing"
    assert ccp.evaluate([".github/actionlint.yaml"]) != [], "a gated sibling proves the classifier discriminates"
    assert ccp.evaluate([_RELEASE_SCRIPT, "tests/README.md"]) != [], "neutral docs must not satisfy pairing"


def test_smoke_tests_and_helpers_are_test_side_not_release_plane_triggers() -> None:
    for path in (
        "tests/smoke/test_repo_install.py",
        "tests/smoke/helpers.py",
        "tests/smoke/fixtures/repo/canonical.conf",
        "tests/smoke/boot_vm.sh",
    ):
        assert ccp.evaluate([path]) == [], f"{path} is test-side and must not trigger a production pairing rule"
        assert ccp.evaluate([_RELEASE_SCRIPT, path]) == [], f"{path} must satisfy the shipped-test side"


def test_release_plane_requires_frozen_red_record_when_body_is_available(tmp_path: Any, capsys: Any) -> None:
    body = tmp_path / "pr-body.md"
    body.write_text("## Tests\nA test changed, but no frozen-RED record is present.\n", encoding="utf-8")

    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1
    assert "Frozen RED test" in capsys.readouterr().out


def test_matching_frozen_red_record_passes(tmp_path: Any) -> None:
    body = tmp_path / "pr-body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, _working_tree_hash(_RELEASE_TEST)), encoding="utf-8")

    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 0


def test_frozen_red_hash_must_be_lowercase(tmp_path: Any, capsys: Any) -> None:
    body = tmp_path / "pr-body.md"
    digest = _working_tree_hash(_RELEASE_TEST)
    body.write_text(_frozen_red_body(_RELEASE_TEST, digest.upper()), encoding="utf-8")

    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1
    output = capsys.readouterr().out
    assert _RELEASE_TEST in output
    assert "Git object ID" in output


def test_frozen_red_record_must_name_a_changed_test_and_carry_a_tail(tmp_path: Any, capsys: Any) -> None:
    body = tmp_path / "pr-body.md"
    body.write_text(
        _frozen_red_body(
            "tests/test_check_skip_allowlist.py", _working_tree_hash("tests/test_check_skip_allowlist.py")
        ),
        encoding="utf-8",
    )
    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1
    assert "not changed by this PR" in capsys.readouterr().out

    body.write_text(_frozen_red_body(_RELEASE_TEST, _working_tree_hash(_RELEASE_TEST), tail=""), encoding="utf-8")
    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1
    assert "RED run tail" in capsys.readouterr().out


def test_comment_only_release_change_uses_existing_no_test_needed_escape(tmp_path: Any) -> None:
    body = tmp_path / "pr-body.md"
    body.write_text("no-test-needed: comment-only change\n", encoding="utf-8")

    assert ccp.main(["--warn-only", "--pr-body-file", str(body), _RELEASE_SCRIPT]) == 0


def _coverage_run_block() -> str:
    workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/test.yml").read_text(encoding="utf-8")
    lines = workflow.splitlines()
    step = next(i for i, line in enumerate(lines) if line.strip().startswith("- name: Enforce "))
    run = next(i for i in range(step + 1, len(lines)) if lines[i].strip() == "run: |")
    body: list[str] = []
    for line in lines[run + 1 :]:
        if line and len(line) - len(line.lstrip()) <= len(lines[run]) - len(lines[run].lstrip()):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def test_ci_wiring_executes_ordered_red_canaries_and_real_status_stream(tmp_path: Path) -> None:
    block = _coverage_run_block()
    commands = [line.strip() for line in block.splitlines() if "scripts/check_coverage_pairing.py" in line]
    assert block.splitlines()[0] == "set -euo pipefail"
    assert len(commands) == 3, commands
    assert all("| tee " in command for command in commands)
    assert all("--name-status-z" in command for command in commands)
    assert commands[0].startswith('if printf "M\\0scripts/canary.py\\0"')
    assert "frozen-red-canary-body.txt" in commands[1]
    assert commands[2].endswith('< changed.txt | tee -a "$GITHUB_STEP_SUMMARY"')

    (tmp_path / "scripts").mkdir()
    (tmp_path / "tests").mkdir()
    shutil.copy2(_TOOL, tmp_path / "scripts/check_coverage_pairing.py")
    shutil.copy2(Path(__file__), tmp_path / _RELEASE_TEST)
    digest = subprocess.check_output(
        ["git", "hash-object", "--", _RELEASE_TEST],
        cwd=tmp_path,
        text=True,
    ).strip()
    body = tmp_path / "live-body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, digest), encoding="utf-8")
    (tmp_path / "changed.txt").write_bytes(b"M\0.github/workflows/test.yml\0M\0tests/test_coverage_pairing_check.py\0")
    stub = tmp_path / "bin"
    stub.mkdir()
    gh = stub / "gh"
    gh.write_text(
        '#!/bin/sh\ncase "$*" in\n'
        "*issues/*/labels*) exit 0 ;;\n"
        '*pulls/*) cat "$PR_BODY_FIXTURE" ;;\n'
        "*) exit 1 ;;\nesac\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stub}:{os.environ['PATH']}",
        "GITHUB_REPOSITORY": "owner/repo",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "GH_TOKEN": "token",
        "PR_BODY_FIXTURE": str(body),
        "PR_NUM": "1",
    }
    proc = subprocess.run(
        ["bash", "-c", block],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    missing = proc.stdout.index("release-plane<->tests coverage pairing violated")
    mismatch = proc.stdout.index("Frozen RED hash mismatch")
    success = proc.stdout.index("Coverage pairing OK")
    assert missing < mismatch < success


def test_run_gates_plan_includes_coverage_pairing() -> None:
    repo = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        ["sh", "scripts/agent/run-gates.sh", "--diff", "HEAD", "--plan"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines().count("python3 scripts/check_coverage_pairing.py --name-status-z") == 1, proc.stdout


def _run_status_stream(data: bytes, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_TOOL), "--name-status-z", *args],
        cwd=cwd or Path(__file__).resolve().parent.parent,
        input=data,
        capture_output=True,
        check=False,
    )


def test_status_stream_retains_deleted_release_paths_but_not_deleted_tests() -> None:
    deleted_release = _run_status_stream(b"D\0scripts/removed.py\0")
    assert deleted_release.returncode == 1, deleted_release.stdout

    deleted_test = _run_status_stream(b"M\0scripts/dispatch-pkg-publication.sh\0D\0tests/test_removed.py\0")
    assert deleted_test.returncode == 1, deleted_test.stdout


def test_status_stream_retains_release_side_of_rename_to_neutral() -> None:
    renamed = _run_status_stream(b"R100\0scripts/dispatch-pkg-publication.sh\0scripts/README.md\0")
    assert renamed.returncode == 1, renamed.stdout


def test_status_stream_added_or_modified_test_satisfies_pairing() -> None:
    for status in (b"A", b"M"):
        proc = _run_status_stream(b"M\0scripts/dispatch-pkg-publication.sh\0" + status + b"\0tests/test_release.py\0")
        assert proc.returncode == 0, proc.stdout


def test_status_stream_uses_final_live_test_state_without_losing_triggers() -> None:
    deleted_after_add = _run_status_stream(
        b"M\0scripts/dispatch-pkg-publication.sh\0A\0tests/test_release.py\0D\0tests/test_release.py\0"
    )
    assert deleted_after_add.returncode == 1, deleted_after_add.stdout

    renamed_away = _run_status_stream(
        b"M\0scripts/dispatch-pkg-publication.sh\0A\0tests/test_release.py\0R100\0tests/test_release.py\0docs/release-test.md\0"
    )
    assert renamed_away.returncode == 1, renamed_away.stdout

    recreated = _run_status_stream(
        b"M\0scripts/dispatch-pkg-publication.sh\0A\0tests/test_release.py\0D\0tests/test_release.py\0A\0tests/test_release.py\0"
    )
    assert recreated.returncode == 0, recreated.stdout


def test_nul_paths_are_not_stripped_or_decoded_lossily(tmp_path: Path) -> None:
    body = tmp_path / "body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, _working_tree_hash(_RELEASE_TEST)), encoding="utf-8")
    for impostor in (
        b"tests/test_coverage_pairing_check.py ",
        b"tests/test_coverage_pairing_check.py\t",
    ):
        proc = _run_status_stream(
            b"M\0scripts/dispatch-pkg-publication.sh\0M\0" + impostor + b"\0",
            "--pr-body-file",
            str(body),
        )
        assert proc.returncode == 1, proc.stdout
        assert b"not changed by this PR" in proc.stdout

    for unrepresentable in (b"tests/test_bad\nname.py", b"tests/test_\xff.py"):
        proc = _run_status_stream(b"M\0scripts/dispatch-pkg-publication.sh\0M\0" + unrepresentable + b"\0")
        assert proc.returncode == 2, proc.stdout
        assert b"cannot be represented in Markdown" in proc.stdout


def test_frozen_red_table_must_be_one_visible_unindented_delimited_table(tmp_path: Path) -> None:
    digest = _working_tree_hash(_RELEASE_TEST)
    table = _frozen_red_body(_RELEASE_TEST, digest)
    invalid_bodies = (
        f"```\n{table}```\n",
        f"<!--\n{table}-->\n",
        textwrap.indent(table, "  "),
        table.replace("| --- | --- | --- |\n", ""),
        f"{table}\n{table}",
        f"````text\n```\n{table}```\n````\n",
        f"~~~~text\n~~~\n{table}~~~\n~~~~\n",
        f"````\n````not-a-close\n{table}````\n",
        f"```text\n```\u00a0\n{table}```\n",
        f"```text\n```\f{table}```\n",
        f"```text\n```\u0085{table}```\n",
        f"```text\n```\u2028{table}```\n",
    )
    for body_text in invalid_bodies:
        body = tmp_path / "body.md"
        body.write_text(body_text, encoding="utf-8")
        assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 1

    body = tmp_path / "visible.md"
    body.write_text(f"```text\nnot evidence\n```\n\n{table}", encoding="utf-8")
    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 0

    for newline in ("\n", "\r", "\r\n"):
        body.write_text(
            f"```text{newline}not evidence{newline}``` \t{newline}{newline}{table}",
            encoding="utf-8",
        )
        assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST]) == 0


def test_every_changed_test_side_file_requires_its_own_frozen_row(tmp_path: Path, capsys: Any) -> None:
    second = "tests/test_check_skip_allowlist.py"
    body = tmp_path / "body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, _working_tree_hash(_RELEASE_TEST)), encoding="utf-8")
    assert ccp.main(["--pr-body-file", str(body), _RELEASE_SCRIPT, _RELEASE_TEST, second]) == 1
    assert second in capsys.readouterr().out


def test_name_status_mode_requires_a_row_for_every_live_test(tmp_path: Path) -> None:
    second = b"tests/test_check_skip_allowlist.py"
    body = tmp_path / "body.md"
    body.write_text(_frozen_red_body(_RELEASE_TEST, _working_tree_hash(_RELEASE_TEST)), encoding="utf-8")
    proc = _run_status_stream(
        b"M\0scripts/dispatch-pkg-publication.sh\0M\0tests/test_coverage_pairing_check.py\0M\0" + second + b"\0",
        "--pr-body-file",
        str(body),
    )
    assert proc.returncode == 1, proc.stdout
    assert second in proc.stdout


def test_frozen_hash_uses_repository_native_git_object_format(tmp_path: Path, monkeypatch: Any) -> None:
    repo = tmp_path / "sha256"
    repo.mkdir()
    init = subprocess.run(
        ["git", "init", "-q", "--object-format=sha256"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert init.returncode == 0, init.stderr
    (repo / "tests").mkdir()
    (repo / "target").write_text("target\n", encoding="utf-8")
    (repo / "tests/native-link.py").symlink_to("../target")
    digest = subprocess.check_output(
        ["git", "hash-object", "--", "tests/native-link.py"],
        cwd=repo,
        text=True,
    ).strip()
    assert len(digest) == 64
    body = repo / "body.md"
    body.write_text(_frozen_red_body("tests/native-link.py", digest), encoding="utf-8")
    monkeypatch.chdir(repo)
    assert ccp.main(["--pr-body-file", str(body), "scripts/release.py", "tests/native-link.py"]) == 0
