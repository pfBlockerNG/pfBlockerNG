"""Tests for scripts/check_context_budget.py.

Every violation class is paired with its nearest clean sibling (the checker
must fire on the violating shape and stay quiet on the compliant one):
budgets per surface class, boundary at the exact budget,
routing-table extraction/resolution, both header shapes, capsule extraction,
and the conditional --staged/--diff trigger through the CLI against scratch
git repos. One test pins the live repository tree itself within budget.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests._workflow_steps import extract_before, extract_between
from tests.gitenv import scrubbed_git_env

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_context_budget.py"
_spec = importlib.util.spec_from_file_location("check_context_budget", _TOOL)
assert _spec is not None and _spec.loader is not None
ccb = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ccb
_spec.loader.exec_module(ccb)

_REPO_ROOT = Path(__file__).resolve().parent.parent

_HEADER = "Scope: test file. Load when: testing.\n"

_BOOTSTRAP = """# Bootstrap

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| policy work | `.agents/policy/alpha.md` |
| context work | `beta.md` |
| languages | `lang-<php\\|python\\|shell>.md` per touched language |

## After

Prose mentioning `outside.md` that is not a routing row.
"""

_HOSTILE_BOOTSTRAP = """# Bootstrap

## Routing table — read on trigger, not up front

| Task touches | Read first |
| ------------ | ---------- |
| policy work | `.agents/policy/alpha.md` |
| empty group | `<>.md` |
| empty alts both | `<|>.md` |
| empty alt middle | `<a||b>.md` |
| unclosed group | `lang-<php|python.md` |
| two groups | `a<b|c>d<e|f>g.md` |
| no alternation | `lang-<php>.md` |
"""

_PARITY_AGENTS = """# Doc

Never assume — read the source of truth, investigate the live state, and confirm a
genuine fork before building.

Delegation shape: substantial coding work is planned by the **top tier**, implemented
by small-tier agents.
"""


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scratch_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, "AGENTS.md", _BOOTSTRAP)
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    _write(root, ".agents/context/beta.md", f"# Beta\n\n{_HEADER}")
    # _BOOTSTRAP carries a `lang-<php\|python\|shell>.md` template row — every
    # expanded alternative must resolve for this fixture to stay header-clean.
    _write(root, ".agents/context/lang-php.md", f"# PHP\n\n{_HEADER}")
    _write(root, ".agents/context/lang-python.md", f"# Python\n\n{_HEADER}")
    _write(root, ".agents/context/lang-shell.md", f"# Shell\n\n{_HEADER}")
    subprocess.run(["git", "init", "-q", root], check=True, env=scrubbed_git_env())
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    return root


def _tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True, env=scrubbed_git_env()
    ).stdout
    return [line for line in out.split("\n") if line]


# --- budget_for: one assertion per surface class -------------------------------


@pytest.mark.parametrize(
    ("rel", "budget"),
    [
        ("AGENTS.md", 10_240),
        ("CLAUDE.md", 8_192),
        ("GROK.md", 8_192),
        (".agents/policy/new-policy.md", 12_288),
        (".agents/context/new-context.md", 12_288),
        (".agents/policy/landing.md", 26_000),
        (".agents/policy/agent-roles.md", 19_000),
        (".agents/policy/delegation.md", 18_000),
        ("tests/smoke/CLAUDE.md", 400),
        ("tests/smoke/GROK.md", 400),
        ("src/usr/local/AGENTS.md", 400),
        # Nested stubs under .agents/ are dir stubs, not routed policy files —
        # the stub branch must win over the policy/context prefix.
        (".agents/context/sub/AGENTS.md", 400),
        (".agents/policy/sub/CLAUDE.md", 400),
        ("src/usr/local/pkg/pfblockerng/pfblockerng.inc", None),
        ("docs/misc/architecture-notes.md", None),
        (".claude/rules/smoke.md", 400),
        (".claude/rules/sub/deep.md", 400),
    ],
)
def test_budget_for_surface_classes(rel: str, budget: int | None) -> None:
    assert ccb.budget_for(rel) == budget


def test_size_over_budget_fires_and_at_budget_passes(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".agents/policy/fat.md", "x" * 12_289)
    _write(root, ".agents/policy/exact.md", "x" * 12_288)
    violations = ccb.check_sizes(root, [".agents/policy/fat.md", ".agents/policy/exact.md"])
    assert violations == [".agents/policy/fat.md: 12289 bytes > budget 12288"]


def test_nested_stub_over_budget_fires_root_files_use_own_budget(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "www/CLAUDE.md", "x" * 401)
    _write(root, "AGENTS.md", "x" * 401)  # root bootstrap: 401 B is far under 10,240
    violations = ccb.check_sizes(root, ["www/CLAUDE.md", "AGENTS.md"])
    assert violations == ["www/CLAUDE.md: 401 bytes > budget 400"]


def test_size_of_missing_tracked_file_fails_closed(tmp_path: Path) -> None:
    # Tracked-but-deleted (deletion unstaged) must yield a violation, not a traceback.
    violations = ccb.check_sizes(tmp_path, [".agents/policy/gone.md"])
    assert len(violations) == 1 and violations[0].startswith(".agents/policy/gone.md: unreadable")


def test_rules_budget_over_fires_and_at_budget_passes(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".claude/rules/x.md", "x" * 401)
    _write(root, ".claude/rules/y.md", "x" * 400)
    violations = ccb.check_sizes(root, [".claude/rules/x.md", ".claude/rules/y.md"])
    assert violations == [".claude/rules/x.md: 401 bytes > budget 400"]


# --- the append-only CodeRabbit ledger keeps its one-line format (#2829) -------


def _ledger_entry(nbytes: int, sha: str = "deadbeef", pr: int = 1) -> str:
    """One ASCII ledger entry of exactly nbytes bytes, padded in the clause."""
    stem = f"- `{sha}`  a title  (#{pr}) — "
    return stem + "y" * (nbytes - len(stem.encode("utf-8")))


def test_ledger_entry_at_cap_passes(tmp_path: Path) -> None:
    _write(tmp_path, ccb.LEDGER, _ledger_entry(ccb.LEDGER_ENTRY_MAX) + "\n")
    assert ccb.check_ledger_entries(tmp_path) == []


def test_ledger_entry_one_byte_over_cap_fires(tmp_path: Path) -> None:
    over = ccb.LEDGER_ENTRY_MAX + 1
    _write(tmp_path, ccb.LEDGER, _ledger_entry(over) + "\n")
    assert ccb.check_ledger_entries(tmp_path) == [f"{ccb.LEDGER}:1: entry is {over} bytes > cap {ccb.LEDGER_ENTRY_MAX}"]


def test_ledger_narrative_entry_fires(tmp_path: Path) -> None:
    # The #2829 regression shape: a ~1,900-byte review narrative appended in
    # place of the documented one-liner. Twelve of those ate the file's budget,
    # and the narrative they carry already lives in that PR's audit comments.
    _write(tmp_path, ccb.LEDGER, _ledger_entry(1_900) + "\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "1900 bytes > cap" in violations[0], violations


@pytest.mark.parametrize(
    "line",
    [
        "- `deadbeef`  a title with no PR number",
        "- a title  (#1)",  # no SHA
        "- `deadbeef` a title  (#1)",  # single space, not the documented two
        "- `deadbeef`  a title  (#1) - clause",  # hyphen, not the em-dash clause marker
    ],
)
def test_ledger_malformed_entry_fires(tmp_path: Path, line: str) -> None:
    _write(tmp_path, ccb.LEDGER, line + "\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "does not match" in violations[0], violations


def test_ledger_duplicate_sha_fires(tmp_path: Path) -> None:
    # One line per merged SHA: a re-appended entry is a double-count, and the
    # ledger carried exactly that (`de69f67b` twice) until #2829.
    entry = _ledger_entry(60)
    _write(tmp_path, ccb.LEDGER, f"{entry}\n{entry}\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "listed twice" in violations[0], violations


def test_ledger_without_entries_fires_rather_than_passing_vacuously(tmp_path: Path) -> None:
    # Zero parsed entries means the format drifted (or the list was emptied) —
    # never a clean pass, same rule the routing-table extraction already follows.
    _write(tmp_path, ccb.LEDGER, "# CodeRabbit missed reviews\n\nNothing here.\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "no entries" in violations[0], violations


def test_ledger_entry_without_a_clause_passes(tmp_path: Path) -> None:
    # The clause is optional by contract (#2829: "plus at most one clause"), so
    # the bare documented shape is valid and stays valid.
    _write(tmp_path, ccb.LEDGER, "- `deadbeef`  a title  (#1)\n")
    assert ccb.check_ledger_entries(tmp_path) == []


@pytest.mark.parametrize(
    "wrapper",
    [
        "  ",  # an indented bullet is still a list item
        "\t",
        "\ufeff",  # invisible
        "\u00a0",  # a space that is not a space
        "\u3000",
        "* ",  # every other Markdown list marker
        "+ ",
        "1. ",
        "1)\t",
        "<!-- ",  # invisible again
        "# ",  # and the shapes marker enumeration keeps missing
        "> ",
        ": ",
        "\u2022 ",
    ],
)
def test_ledger_narrative_hidden_above_the_list_still_fires(tmp_path: Path, wrapper: str) -> None:
    # Enumerating markers is a losing game — `#`, `>`, `:` and `•` all render an
    # entry-looking line, and the next reviewer finds a fifteenth shape. The
    # header answers to its own byte cap instead, so a narrative parked above
    # the list is caught whatever it wears.
    hidden = f"{wrapper}{_ledger_entry(1_900, sha='c0ffee12')}"
    _write(tmp_path, ccb.LEDGER, f"{hidden}\n\n- `deadbeef`  a title  (#1)\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "header is" in violations[0] and "> cap" in violations[0], violations


def test_ledger_header_at_cap_passes_and_one_byte_over_fires(tmp_path: Path) -> None:
    entry = "- `deadbeef`  a title  (#1)\n"
    header = "# CodeRabbit missed reviews\n\n"
    at_cap = header + "x" * (ccb.LEDGER_HEADER_MAX - len(header.encode("utf-8")) - 1) + "\n"
    _write(tmp_path, ccb.LEDGER, at_cap + entry)
    assert ccb.check_ledger_entries(tmp_path) == []
    _write(tmp_path, ccb.LEDGER, at_cap[:-1] + "x\n" + entry)
    violations = ccb.check_ledger_entries(tmp_path)
    assert violations == [f"{ccb.LEDGER}: header is {ccb.LEDGER_HEADER_MAX + 1} bytes > cap {ccb.LEDGER_HEADER_MAX}"], (
        violations
    )


def test_ledger_header_cap_counts_the_bytes_the_file_ships_not_normalized_ones(tmp_path: Path) -> None:
    # CRLF is two bytes. Counting a normalized "\n" per line lets a 1,800-byte
    # header measure 1,200 and pass the cap it just broke.
    _write(tmp_path, ccb.LEDGER, "x\r\n" * 600 + "- `deadbeef`  a title  (#1)\r\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert violations == [f"{ccb.LEDGER}: header is 1800 bytes > cap {ccb.LEDGER_HEADER_MAX}"], violations


@pytest.mark.parametrize(
    "prose",
    [
        "1. Read the PR, then record the miss.",
        "+ expected output",
        "<!-- markdownlint-disable MD013 -->",
        "> the review story stays on the PR",
        "---",  # a thematic break is not the list opening
        "-- a dashed aside, still prose",
    ],
)
def test_ledger_ordinary_header_prose_passes(tmp_path: Path, prose: str) -> None:
    # Header prose is prose: a numbered instruction, a code sample line, a lint
    # directive, a quote or a rule must not be mistaken for a smuggled entry.
    # The list opens at `-` FOLLOWED BY A SPACE; a bare dash run does not open it.
    _write(tmp_path, ccb.LEDGER, f"# CodeRabbit missed reviews\n\n{prose}\n\n- `deadbeef`  a title  (#1)\n")
    assert ccb.check_ledger_entries(tmp_path) == []


def test_ledger_live_header_passes_within_its_cap(tmp_path: Path) -> None:
    # The LIVE header, not a paraphrase: it must stay inside the cap the gate
    # enforces, so a header edit that would trip the gate fails here first.
    live_header = (_REPO_ROOT / ccb.LEDGER).read_text(encoding="utf-8").split("\n- ", 1)[0]
    _write(tmp_path, ccb.LEDGER, f"{live_header}\n- `deadbeef`  a title  (#1)\n")
    assert ccb.check_ledger_entries(tmp_path) == []


def test_ledger_prose_after_the_first_entry_fires(tmp_path: Path) -> None:
    # A narrative continuation line carries no bullet at all; once the list has
    # started, every non-blank line answers to the entry rule.
    _write(tmp_path, ccb.LEDGER, "- `deadbeef`  a title  (#1)\n\nand then the review story continued\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "does not match" in violations[0], violations


def test_ledger_absent_from_a_root_without_the_policy_is_not_a_violation(tmp_path: Path) -> None:
    # Scratch roots (and any tree that never carried the ledger) stay clean.
    assert ccb.check_ledger_entries(tmp_path) == []


def test_ledger_missing_beside_the_policy_that_requires_it_fires(tmp_path: Path) -> None:
    # A staged or committed deletion drops the file out of `git ls-files`, so
    # check_sizes never sees it: this gate is the one that must fail closed.
    _write(tmp_path, ccb.LEDGER_OWNER, "# CodeRabbit\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "missing" in violations[0], violations


def test_ledger_replaced_by_a_directory_fires(tmp_path: Path) -> None:
    (tmp_path / ccb.LEDGER).mkdir(parents=True)
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "unreadable" in violations[0], violations


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions — denial cannot be simulated")
def test_ledger_unreadable_fires(tmp_path: Path) -> None:
    path = _write(tmp_path, ccb.LEDGER, "- `deadbeef`  a title  (#1)\n")
    path.chmod(0o000)
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "unreadable" in violations[0], violations


def test_ledger_with_invalid_utf8_fires_instead_of_crashing(tmp_path: Path) -> None:
    # A traceback out of the CLI discards every other violation already found.
    path = tmp_path / ccb.LEDGER
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"- `deadbeef`  a title  (#1)\n\xff\n")
    violations = ccb.check_ledger_entries(tmp_path)
    assert len(violations) == 1 and "unreadable" in violations[0], violations


def test_run_checks_surfaces_ledger_violations(tmp_path: Path) -> None:
    # Wiring pin: the rule is only a gate while run_checks calls it, and every
    # unit test above stays green when the call is dropped.
    root = _scratch_repo(tmp_path)
    _write(root, ccb.LEDGER, _ledger_entry(ccb.LEDGER_ENTRY_MAX + 1) + "\n")
    violations = ccb.run_checks(root, _tracked(root))
    assert any("> cap" in v for v in violations), violations


# --- routing-table extraction and resolution -----------------------------------


def test_routing_targets_extracts_table_rows_only() -> None:
    # A well-formed `lang-<php\|python\|shell>.md` template row expands into one
    # concrete token per alternative (markdown-escaped pipes stripped), never skips.
    tokens, skipped = ccb.routing_targets(_BOOTSTRAP)
    assert tokens == [".agents/policy/alpha.md", "beta.md", "lang-php.md", "lang-python.md", "lang-shell.md"]
    assert skipped == []


def test_routing_targets_hostile_templates_skip_without_crash() -> None:
    tokens, skipped = ccb.routing_targets(_HOSTILE_BOOTSTRAP)
    assert tokens == [".agents/policy/alpha.md"]
    assert skipped == ["<>.md", "<|>.md", "<a||b>.md", "lang-<php|python.md", "a<b|c>d<e|f>g.md", "lang-<php>.md"]


def test_resolve_target_bare_token_searches_policy_context_docs(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.resolve_target(root, "beta.md") == ".agents/context/beta.md"
    assert ccb.resolve_target(root, ".agents/policy/alpha.md") == ".agents/policy/alpha.md"
    assert ccb.resolve_target(root, "missing.md") is None


def test_check_headers_clean_tree_passes(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.check_headers(root) == []


def test_check_headers_flags_unresolvable_target(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    (root / ".agents/context/beta.md").unlink()
    assert ccb.check_headers(root) == ["AGENTS.md: routing target `beta.md` does not resolve to a file"]


def test_check_headers_flags_missing_header(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/context/beta.md", "# Beta\n\nNo routing header here.\n")
    violations = ccb.check_headers(root)
    assert violations == [".agents/context/beta.md: routed file lacks a Scope: + Load-when: header (first 12 lines)"]


def test_check_headers_flags_renamed_routing_table_heading(tmp_path: Path) -> None:
    # Zero extracted targets must be a violation, not a vacuous pass — otherwise
    # renaming the "## Routing table" heading disarms the whole header gate.
    root = _scratch_repo(tmp_path)
    _write(root, "AGENTS.md", _BOOTSTRAP.replace("## Routing table", "## Where to read"))
    _write(root, ".agents/context/beta.md", "# Beta\n\nNo routing header here.\n")
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: no routing-table targets extracted — heading renamed or table removed?"]


def test_check_headers_expanded_template_flags_missing_alternative(tmp_path: Path) -> None:
    # _scratch_repo ships all three lang-*.md alternatives (header-clean by
    # default); a missing alternative is an unresolved-target violation — each
    # expanded alternative resolves and header-checks independently.
    root = _scratch_repo(tmp_path)
    (root / ".agents/context/lang-shell.md").unlink()
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: routing target `lang-shell.md` does not resolve to a file"]


def test_check_headers_expanded_template_all_alternatives_present_clean(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    assert ccb.check_headers(root) == []


def test_check_headers_hostile_templates_skip_silently_no_crash(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _HOSTILE_BOOTSTRAP)
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    assert ccb.check_headers(root) == []


def test_check_headers_reports_spaced_template_token(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    bootstrap = _BOOTSTRAP.replace("lang-<php\\|python\\|shell>.md", "lang-<php | python>.md")
    _write(root, "AGENTS.md", bootstrap)
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: malformed routing target `lang-<php | python>.md` skipped"]


def test_check_headers_reports_spaced_template_token_with_trailing_text(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    bootstrap = _BOOTSTRAP.replace("lang-<php\\|python\\|shell>.md", "lang-<php | python>.md trailing")
    _write(root, "AGENTS.md", bootstrap)
    violations = ccb.check_headers(root)
    assert violations == ["AGENTS.md: malformed routing target `lang-<php | python>.md trailing` skipped"]


# --- both header shapes accepted; window enforced ------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "Scope: things. Load when: touching things.",
        "- **Scope:** things over multiple words.\n- **Load-when:** touching things.",
    ],
)
def test_has_context_header_accepts_both_house_shapes(header: str) -> None:
    assert ccb.has_context_header(f"# Title\n\n{header}\n")


@pytest.mark.parametrize(
    "text",
    [
        "# Title\n\nLoad when: no scope line.\n",
        "# Title\n\nScope: no load-when line.\n",
        "# Title\n" + "\n" * 12 + "Scope: too late. Load when: beyond the window.\n",
    ],
)
def test_has_context_header_rejects_missing_or_late_fields(text: str) -> None:
    assert not ccb.has_context_header(text)


# --- capsule extraction and budget ---------------------------------------------


def _settings(capsule: str) -> str:
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": capsule}})
    return json.dumps(
        {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": f"echo '{payload}'"}]}],
                "PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}],
            }
        }
    )


def _settings_ups(capsule: str) -> str:
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": capsule}})
    return json.dumps(
        {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"echo '{payload}'"}]}]}}
    )


def _settings_command(command: str, event: str = "SessionStart") -> str:
    return json.dumps({"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}]}})


def test_extract_capsules_returns_event_text_and_measures_bytes() -> None:
    # extract_capsules returns the capsule TEXT per event; byte length is
    # derived by the caller where it matters.
    capsules, errors = ccb.extract_capsules(_settings("abc"))
    assert capsules == [("SessionStart", "abc")] and errors == []
    assert len(capsules[0][1].encode("utf-8")) == 3


def test_check_capsules_flags_over_budget_only(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, ".claude/settings.json", _settings("x" * 1_801))
    assert ccb.check_capsules(root) == [".claude/settings.json: SessionStart capsule 1801 bytes > budget 1800"]
    _write(root, ".claude/settings.json", _settings("x" * 1_800))
    assert ccb.check_capsules(root) == []


def test_extract_capsules_reports_unextractable_payload() -> None:
    settings = json.dumps(
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "emit-additionalContext.sh 'oops"}]}]}}
    )
    capsules, errors = ccb.extract_capsules(settings)
    assert capsules == []
    assert errors == [".claude/settings.json: SessionStart capsule payload is not extractable JSON"]


def test_extract_capsules_rejects_shell_broken_apostrophe() -> None:
    capsules, errors = ccb.extract_capsules(_settings("repo's"))
    assert capsules == []
    assert errors == [".claude/settings.json: SessionStart capsule payload is not extractable JSON"]


def test_extract_capsules_rejects_appended_command_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "MARKER"
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "abc"}})
    settings = _settings_command(f"echo '{payload}'; touch {marker}")
    capsules, errors = ccb.extract_capsules(settings)
    assert capsules == []
    assert errors == [".claude/settings.json: SessionStart capsule payload is not extractable JSON"]
    assert not marker.exists(), f"capsule validation executed side effect: {marker}"


def test_extract_capsules_keeps_single_quoted_shell_metacharacters_literal(tmp_path: Path) -> None:
    marker = tmp_path / "MARKER"
    capsule = f"literal $(touch {marker})"
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": capsule}})
    capsules, errors = ccb.extract_capsules(_settings_command(f"echo '{payload}'"))
    assert capsules == [("SessionStart", capsule)]
    assert errors == []
    assert not marker.exists(), f"single-quoted capsule text expanded: {marker}"


@pytest.mark.parametrize("shape", ["double-quoted", "printf", "extra-arg", "multiple-commands"])
def test_extract_capsules_rejects_noncanonical_commands(shape: str) -> None:
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "abc"}})
    command = {
        "double-quoted": f'echo "{payload}"',
        "printf": f"printf '%s' '{payload}'",
        "extra-arg": f"echo '{payload}' ''",
        "multiple-commands": f"echo '{payload}'; true",
    }[shape]
    capsules, errors = ccb.extract_capsules(_settings_command(command))
    assert capsules == []
    assert errors == [".claude/settings.json: SessionStart capsule payload is not extractable JSON"]


@pytest.mark.parametrize(
    "settings_text",
    [
        "{not json",  # parse error
        '{"hooks": ["not", "a", "dict"]}',  # valid JSON, hooks is a list
        '["top-level list"]',  # valid JSON, wrong top-level shape
        '{"hooks": {"SessionStart": "not-entries"}}',  # entries not a list of dicts
    ],
)
def test_extract_capsules_malformed_settings_fails_closed(settings_text: str) -> None:
    capsules, errors = ccb.extract_capsules(settings_text)
    assert capsules == []
    assert errors == [".claude/settings.json: not a parseable hooks structure — capsule budgets unverifiable"]


def test_run_checks_reports_size_violations_despite_malformed_settings(tmp_path: Path) -> None:
    # A capsule-check failure must not swallow violations the other checks found.
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    _write(root, ".claude/settings.json", '{"hooks": ["not", "a", "dict"]}')
    violations = ccb.run_checks(root, [".agents/policy/alpha.md", ".claude/settings.json"])
    assert any("> budget 12288" in v for v in violations)
    assert any("not a parseable hooks structure" in v for v in violations)


def test_extract_capsules_rejects_over_cap_command_before_tokenization() -> None:
    # issue #1504: shlex is nonlinear on huge quoted strings (~25 s at 1 MB), so a
    # command beyond the derived ceiling (decoded 1,800 B budget × worst-case JSON
    # escaping + envelope) must be rejected on byte length alone, never tokenized.
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "X" * 11_000}})
    capsules, errors = ccb.extract_capsules(_settings_command(f"echo '{payload}'"))
    assert capsules == []
    assert len(errors) == 1 and "SessionStart" in errors[0] and "cap" in errors[0], errors


def _canonical_command_padded_to(nbytes: int) -> str:
    """A canonical `echo '<JSON>'` capsule command of exactly nbytes UTF-8 bytes."""
    empty = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ""}})
    pad = nbytes - len(f"echo '{empty}'".encode())
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "X" * pad}})
    command = f"echo '{payload}'"
    assert len(command.encode("utf-8")) == nbytes
    return command


def test_extract_capsules_command_at_cap_is_tokenized() -> None:
    # The boundary itself passes the cap: an at-ceiling command still reaches
    # tokenization and extraction (its payload then answers to the 1,800 B budget).
    capsules, errors = ccb.extract_capsules(_settings_command(_canonical_command_padded_to(ccb.COMMAND_BYTES_MAX)))
    assert errors == []
    assert len(capsules) == 1 and capsules[0][0] == "SessionStart"
    assert len(capsules[0][1].encode("utf-8")) > 1_800  # the cap never replaces the budget


def test_extract_capsules_command_one_byte_over_cap_rejected() -> None:
    over = ccb.COMMAND_BYTES_MAX + 1
    capsules, errors = ccb.extract_capsules(_settings_command(_canonical_command_padded_to(over)))
    assert capsules == []
    assert errors == [f".claude/settings.json: SessionStart capsule command {over} bytes > cap {ccb.COMMAND_BYTES_MAX}"]


def test_extract_capsules_unencodable_command_fails_closed() -> None:
    # A lone/unpaired UTF-16 surrogate is valid inside a JSON \uXXXX escape but
    # cannot be UTF-8 encoded; the byte-cap check's .encode("utf-8") must not
    # crash out to the file-level catch and discard every other capsule's result.
    capsules, errors = ccb.extract_capsules(_settings_command("echo additionalContext \ud800"))
    assert capsules == []
    assert len(errors) == 1 and "SessionStart" in errors[0] and "unencodable" in errors[0], errors


def test_indirect_over_cap_command_fails_closed(tmp_path: Path) -> None:
    # A non-capsule command over the cap is never tokenized for script refs either.
    root = _indirect_root(tmp_path, "true " + "x" * 11_000)
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and "cannot rule out a capsule" in violations[0], violations


def test_indirect_unencodable_command_fails_closed_without_masking_others(tmp_path: Path) -> None:
    # A lone/unpaired surrogate in ONE hook command must not crash
    # check_indirect_producers's per-file try and silently drop every OTHER
    # hook's already-found violation in the same settings file.
    root = tmp_path
    _write(root, "scripts/real_emit.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    settings_text = (
        '{"hooks": {'
        '"SessionStart": [{"hooks": [{"type": "command", "command": "sh scripts/real_emit.sh \\ud800"}]}],'
        '"PreToolUse": [{"hooks": [{"type": "command", "command": "sh scripts/real_emit.sh"}]}]'
        "}}"
    )
    _write(root, ".claude/settings.json", settings_text)
    violations = ccb.check_indirect_producers(root)
    assert any("unencodable" in v for v in violations), violations
    assert any("PreToolUse" in v and "scripts/real_emit.sh" in v for v in violations), violations


# --- indirect capsule producers (#1501) ------------------------------------------


def _indirect_root(tmp_path: Path, command: str, event: str = "SessionStart") -> Path:
    _write(tmp_path, ".claude/settings.json", _settings_command(command, event))
    return tmp_path


def test_indirect_helper_without_capsule_output_clean(tmp_path: Path) -> None:
    # Nearest clean sibling of the bypass: same hook shape, helper emits no capsule.
    root = _indirect_root(tmp_path, 'sh "${CLAUDE_PROJECT_DIR:-.}/scripts/quiet.sh"')
    _write(root, "scripts/quiet.sh", "#!/bin/sh\nexit 0\n")
    assert ccb.check_indirect_producers(root) == []


def test_indirect_empty_helper_clean(tmp_path: Path) -> None:
    root = _indirect_root(tmp_path, "sh scripts/empty.sh")
    _write(root, "scripts/empty.sh", "")
    assert ccb.check_indirect_producers(root) == []


def test_indirect_missing_helper_fails_closed(tmp_path: Path) -> None:
    root = _indirect_root(tmp_path, "sh scripts/ghost.sh")
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and "`scripts/ghost.sh` not found" in violations[0], violations


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions — denial cannot be simulated")
def test_indirect_unreadable_helper_fails_closed(tmp_path: Path) -> None:
    root = _indirect_root(tmp_path, "sh scripts/locked.sh")
    helper = _write(root, "scripts/locked.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    helper.chmod(0)
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and "unreadable" in violations[0], violations


@pytest.mark.parametrize(
    ("command", "marker"),
    [
        ('sh "scripts/broken.sh', "unparseable quoting"),
        ('sh "$HOME/x.sh"', "unresolvable script"),
        ("sh /tmp/x.sh", "unresolvable script"),
        ("sh scripts/../x.sh", "unresolvable script"),
    ],
)
def test_indirect_unresolvable_command_shapes_fail_closed(tmp_path: Path, command: str, marker: str) -> None:
    root = _indirect_root(tmp_path, command)
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and marker in violations[0], violations


def test_indirect_helper_outside_checked_roots_fails_closed(tmp_path: Path) -> None:
    # A helper outside scripts//.claude/hooks/ dodges the trigger surfaces: editing
    # it would never re-run this gate, so its location alone is a violation.
    root = _indirect_root(tmp_path, "sh tests/helper.sh")
    _write(root, "tests/helper.sh", "#!/bin/sh\nexit 0\n")
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and "outside the checked roots" in violations[0], violations


@pytest.mark.parametrize(
    "command",
    [
        "sh scripts/x.sh;sh scripts/quiet.sh",
        "sh scripts/x.sh>/tmp/out.log",
        "sh scripts/x.sh|cat",
        "sh scripts/x.sh&&true",
    ],
)
def test_indirect_metachar_glued_helper_still_detected(tmp_path: Path, command: str) -> None:
    # Shell operators glued to the path (no whitespace) must not make an emitting
    # helper invisible: `scripts/x.sh;sh` is a ref plus an operator, not a non-ref token.
    root = _indirect_root(tmp_path, command)
    _write(root, "scripts/x.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    _write(root, "scripts/quiet.sh", "#!/bin/sh\nexit 0\n")
    violations = ccb.check_indirect_producers(root)
    assert any("scripts/x.sh" in v for v in violations), violations


def test_indirect_uppercase_extension_helper_still_detected(tmp_path: Path) -> None:
    root = _indirect_root(tmp_path, "sh scripts/LOUD.SH")
    _write(root, "scripts/LOUD.SH", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    violations = ccb.check_indirect_producers(root)
    assert any("scripts/LOUD.SH" in v for v in violations), violations


def test_indirect_quoted_compound_script_ref_still_detected(tmp_path: Path) -> None:
    # `sh -c '...'` (an ordinary shell idiom) collapses its whole quoted body to
    # ONE shlex token after quote removal — a script ref embedded inside that
    # merged token must not go invisible to _script_refs.
    # The ref sits OUTSIDE the helper dirs on purpose: _HELPER_PATH_RE is helper-dir
    # scoped and structurally cannot reach it, so only the compound-fragment
    # recursion surfaces it — keeping this a live mutant for the recursion rather
    # than a shadow of the extension-agnostic path scan.
    root = _indirect_root(tmp_path, "sh -c 'python3 tools/emit.py --flag'")
    _write(root, "tools/emit.py", "print('additionalContext')\n")
    violations = ccb.check_indirect_producers(root)
    assert any("tools/emit.py" in v and "outside the checked roots" in v for v in violations), violations


def test_indirect_delegating_helper_without_literal_still_detected(tmp_path: Path) -> None:
    # A helper that delegates emission to another module
    # (`exec "$PY" -m "pkg.hooks.$1"`) carries no "additionalContext" literal
    # itself — the substring-only check would otherwise miss it entirely and
    # never require registration (#1501).
    root = _indirect_root(tmp_path, "sh scripts/delegate.sh")
    _write(root, "scripts/delegate.sh", '#!/bin/sh\nexec "$PY" -m "pkg.hooks.$1"\n')
    violations = ccb.check_indirect_producers(root)
    assert any("scripts/delegate.sh" in v for v in violations), violations


@pytest.mark.parametrize("name", ["emit-context", "emit+context", "emit@context"])
def test_indirect_extensionless_helper_still_detected(tmp_path: Path, name: str) -> None:
    # A committed helper with no .sh/.py extension — including a name with valid
    # unquoted path characters such as + or @ — must still be resolved and checked;
    # the suffix-gated tokenizer drops it entirely, so the path scan must cover the
    # full unquoted filename, not a truncated prefix (#1501).
    root = _indirect_root(tmp_path, f"sh scripts/{name}")
    _write(root, f"scripts/{name}", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    violations = ccb.check_indirect_producers(root)
    assert any(f"scripts/{name}" in v for v in violations), violations


@pytest.mark.parametrize("glue", ["$()", "``"])
def test_indirect_glued_substitution_helper_still_detected(tmp_path: Path, glue: str) -> None:
    # An empty command substitution glued with no whitespace right after a
    # .sh/.py helper (`x.sh$()`, `x.sh` + backticks) is a shell no-op that still
    # runs the file, yet it strips the recognizable suffix off every surviving
    # shlex token, so the reference goes invisible (#1501).
    root = _indirect_root(tmp_path, f"sh scripts/emit.sh{glue}")
    _write(root, "scripts/emit.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    violations = ccb.check_indirect_producers(root)
    assert any("scripts/emit.sh" in v for v in violations), violations


def test_indirect_registered_dynamic_producer_clean(tmp_path: Path) -> None:
    root = _indirect_root(tmp_path, 'sh "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/session-branch-sync.sh"')
    _write(root, ".claude/hooks/session-branch-sync.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    assert ccb.check_indirect_producers(root) == []


def test_indirect_registered_script_at_other_event_fails_closed(tmp_path: Path) -> None:
    # Registration is per (event, script) pair: rewiring a registered producer to a
    # different event is a new, unreviewed capsule surface.
    command = 'sh "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/session-branch-sync.sh"'
    root = _indirect_root(tmp_path, command, event="UserPromptSubmit")
    _write(root, ".claude/hooks/session-branch-sync.sh", "#!/bin/sh\nprintf '%s' 'additionalContext payload'\n")
    violations = ccb.check_indirect_producers(root)
    assert len(violations) == 1 and "cannot validate" in violations[0], violations


def test_indirect_no_script_reference_command_clean(tmp_path: Path) -> None:
    command = (
        "command -v zstd >/dev/null 2>&1 || python3 -c 'import zstandard' 2>/dev/null"
        " || pip3 install -q zstandard >/dev/null 2>&1 || true"
    )
    root = _indirect_root(tmp_path, command)
    assert ccb.check_indirect_producers(root) == []


def test_indirect_wrong_shape_settings_defers_to_capsule_check(tmp_path: Path) -> None:
    # check_capsules already fails closed on the whole file; no duplicate violation here.
    _write(tmp_path, ".claude/settings.json", '{"hooks": ["not", "a", "dict"]}')
    assert ccb.check_indirect_producers(tmp_path) == []


def test_run_checks_flags_helper_script_capsule_bypass(tmp_path: Path) -> None:
    # issue #1501: the hook command carries no `additionalContext` literal, but the
    # repo helper script it invokes emits a valid oversized capsule Claude consumes —
    # the checker must flag the indirect producer, never skip the hook silently.
    root = _scratch_repo(tmp_path)
    payload = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "X" * 5_000}})
    _write(root, "scripts/emit-context.sh", f"#!/bin/sh\nprintf '%s\\n' '{payload}'\n")
    _write(root, ".claude/settings.json", _settings_command('sh "${CLAUDE_PROJECT_DIR:-.}/scripts/emit-context.sh"'))
    violations = ccb.run_checks(root, _tracked(root))
    assert any("scripts/emit-context.sh" in v for v in violations), violations


# --- UserPromptSubmit capsule <-> AGENTS.md parity ------------------------------


def test_check_parity_all_verbatim_segments_clean(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    capsule = (
        "DISCIPLINE: read the source of truth, investigate the live state, and confirm a "
        "genuine fork before building. · planned by the top tier, implemented by small-tier agents."
    )
    _write(root, ".claude/settings.json", _settings_ups(capsule))
    assert ccb.check_parity(root) == []


def test_check_parity_alien_segment_flags_violation(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("DISCIPLINE: totally alien text absent from agents md"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "totally alien text absent from agents md" in violations[0]


def test_check_parity_no_user_prompt_submit_capsule_clean(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings("abc"))  # SessionStart capsule only
    assert ccb.check_parity(root) == []


def test_check_parity_capsule_without_colon_shape_flags_violation(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("no colon separator here at all"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "UserPromptSubmit" in violations[0]


def test_check_parity_segments_split_only_on_middle_dot_not_colon(tmp_path: Path) -> None:
    # "alpha" and "beta" each appear standalone in AGENTS.md, but "alpha: beta" as a
    # contiguous phrase does not — proves the per-segment text is never re-split (or
    # re-partitioned) on ":", only the outer remainder is ever split, and only on " · ".
    root = tmp_path
    _write(root, "AGENTS.md", "# Doc\n\nalpha appears standalone here.\n\nbeta appears standalone here too.\n")
    _write(root, ".claude/settings.json", _settings_ups("Label: alpha: beta"))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "alpha: beta" in violations[0]


def test_check_parity_overlong_label_flags_violation(tmp_path: Path) -> None:
    # Everything before the first ": " is unchecked prose — without a bound it can
    # smuggle arbitrary directives past the parity gate up to the capsule budget.
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    label = "An alien preamble smuggled ahead of the first colon-space " + "x" * 40
    _write(root, ".claude/settings.json", _settings_ups(label + ": genuine fork before building."))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "label" in violations[0]


def test_check_parity_label_at_bound_passes(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("D" * 80 + ": genuine fork before building."))
    assert ccb.check_parity(root) == []


def test_check_parity_empty_segment_flags_violation(tmp_path: Path) -> None:
    # An empty string is a substring of everything — a trailing " · " (or a
    # segments-free "Label: " capsule) must not pass as vacuously verbatim.
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("DISCIPLINE: genuine fork before building. ·  "))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "empty" in violations[0]


def test_check_parity_label_only_capsule_flags_violation(tmp_path: Path) -> None:
    root = tmp_path
    _write(root, "AGENTS.md", _PARITY_AGENTS)
    _write(root, ".claude/settings.json", _settings_ups("DISCIPLINE: "))
    violations = ccb.check_parity(root)
    assert len(violations) == 1
    assert "empty" in violations[0]


def test_check_parity_live_repository_user_prompt_submit_clean() -> None:
    # Pins the live UserPromptSubmit capsule content against the live AGENTS.md.
    assert ccb.check_parity(_REPO_ROOT) == []


# --- conditional trigger -------------------------------------------------------


@pytest.mark.parametrize(
    "rel",
    [
        "AGENTS.md",
        "CLAUDE.md",
        "GROK.md",
        ".github/copilot-instructions.md",
        ".claude/settings.json",
        "scripts/check_context_budget.py",
        ".agents/policy/alpha.md",
        ".agents/context/beta.md",
        "docs/misc/architecture-notes.md",
        "tests/smoke/CLAUDE.md",
        ".claude/rules/smoke.md",
        ".grok/rules/harness.md",
        ".claude/hooks/session-branch-sync.sh",
    ],
)
def test_touches_context_surface_true(rel: str) -> None:
    assert ccb.touches_context_surface(["src/other.inc", rel])


def test_touches_context_surface_false_on_unrelated() -> None:
    assert not ccb.touches_context_surface(["src/usr/local/www/x.php", "docs/history/incidents.md"])


# --- CLI against scratch repos -------------------------------------------------


def _git_commit(root: str | Path, message: str) -> None:
    """Commit everything staged in a scratch repo under a synthetic identity.

    One definition rather than four copies, and the single place the config-scope scrub
    has to be right for this file (issue #1967).
    """
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", message],
        check=True,
        env=scrubbed_git_env(),
    )


def _run_cli(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_TOOL), *args, "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_staged_skips_when_no_context_surface_staged(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    _git_commit(root, "base")
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    _write(root, "src/thing.inc", "<?php\n")
    subprocess.run(["git", "-C", root, "add", "src/thing.inc"], check=True, env=scrubbed_git_env())
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "skipped" in proc.stdout


def test_cli_staged_runs_and_fails_on_staged_over_budget_policy(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    _git_commit(root, "base")
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_staged_checks_index_content_not_working_tree(tmp_path: Path) -> None:
    # Staged over-budget + worktree fixed back under budget: the commit would
    # still ship the violation, so --staged must fail (index is the snapshot).
    root = _scratch_repo(tmp_path)
    _git_commit(root, "base")
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    _write(root, ".agents/policy/alpha.md", f"# Alpha\n\n{_HEADER}")
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_staged_ignores_unstaged_working_tree_violation(tmp_path: Path) -> None:
    # Staged content clean + worktree bloated: the commit ships the clean index,
    # so --staged must pass instead of false-failing on the dirty worktree.
    root = _scratch_repo(tmp_path)
    _git_commit(root, "base")
    _write(root, ".agents/policy/alpha.md", f"# Alpha (tweaked)\n\n{_HEADER}")
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    proc = _run_cli(root, "--staged")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_diff_fires_on_over_budget_commit_vs_base(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run([*git, "commit", "-qm", "base"], check=True, env=scrubbed_git_env())
    _write(root, ".agents/policy/alpha.md", "# Alpha\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    subprocess.run([*git, "commit", "-qm", "bloat"], check=True, env=scrubbed_git_env())
    proc = _run_cli(root, "--diff", "HEAD~1")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ".agents/policy/alpha.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_all_flags_non_ascii_named_policy_file(tmp_path: Path) -> None:
    # Under default core.quotePath, ls-files C-quotes non-ASCII names and the
    # quoted string would match no budget — the checker must still see the file.
    root = _scratch_repo(tmp_path)
    _write(root, ".agents/policy/pölicy.md", "# P\n\n" + _HEADER + "x" * 20_000)
    subprocess.run(["git", "-C", root, "add", "-A"], check=True, env=scrubbed_git_env())
    proc = _run_cli(root, "--all")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # NFC/NFD filename normalization differs per OS — match the ASCII tail only.
    assert "licy.md" in proc.stdout and "> budget 12288" in proc.stdout


def test_cli_all_clean_scratch_repo_exits_zero(tmp_path: Path) -> None:
    root = _scratch_repo(tmp_path)
    proc = _run_cli(root, "--all")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_cli_all_missing_git_exits_two(tmp_path: Path) -> None:
    proc = _run_cli(tmp_path / "not-a-repo", "--all")
    assert proc.returncode == 2


# --- CI wiring ------------------------------------------------------------------


def test_ci_workflow_paths_match_checker_triggers() -> None:
    # The gate rides its own path-filtered workflow (test.yml's global
    # `paths-ignore: '**/*.md'` would skip an md-only change — the exact class
    # this gate polices). Both trigger blocks must mirror the checker's surfaces.
    text = (_REPO_ROOT / ".github/workflows/context-budget.yml").read_text(encoding="utf-8")
    expected = (
        set(ccb._TRIGGER_FILES)
        | {f"{d}**" for d in ccb._TRIGGER_DIRS}
        # the basename trigger (nested dir stubs anywhere) as workflow globs:
        | {"**/AGENTS.md", "**/CLAUDE.md", "**/GROK.md"}
    )
    # Compare each trigger block INDEPENDENTLY: the two hand-duplicated paths
    # lists drift exactly one-block-at-a-time, and a whole-file set comparison
    # cannot see an entry dropped from only one of them.
    assert "push:" in text, "md-only pushes straight to devel are the dominant re-accretion vector"
    push_block = extract_before(text, "pull_request:")
    pr_block = extract_between(text, "pull_request:", "permissions:")
    for name, block in (("push", push_block), ("pull_request", pr_block)):
        listed = re.findall(r"^\s+- '([^']+)'\s*$", block, re.MULTILINE)
        assert len(listed) == len(expected), f"{name} paths list has duplicates or gaps: {sorted(listed)}"
        assert set(listed) == expected, f"{name} paths {sorted(listed)} != checker triggers {sorted(expected)}"


def test_ci_workflow_arms_the_red_canary() -> None:
    # This gate only ever runs green, so nothing else would notice a checker that
    # stopped firing — and its failure mode surfaces at commit time, not in CI
    # (#2829). The canary deliberately breaks the tree and requires the matching
    # violation; deleting the step must fail here rather than go unnoticed.
    text = (_REPO_ROOT / ".github/workflows/context-budget.yml").read_text(encoding="utf-8")
    assert "Red canary" in text
    assert f"bytes > budget {ccb.POLICY_BUDGET}" in text
    assert f"> cap {ccb.LEDGER_ENTRY_MAX}" in text


# --- the live tree stays within its own budgets --------------------------------


def test_live_repository_tree_is_clean() -> None:
    tracked = _tracked(_REPO_ROOT)
    assert ccb.run_checks(_REPO_ROOT, tracked) == []


# --- the live CodeRabbit ledger: recorded SHAs, recorded order, stated format ---

# Every SHA the ledger carried when #2829 compressed the narrative entries back
# to the documented one-liner, newest first (merge order, each position verified
# against that PR's `merged_at`). Compressing or rewording an entry may never
# drop one, and a new miss is PREPENDED, so this block stays the tail of the
# list and recording a miss needs no edit here.
_LEDGER_RECORDED = (
    ("85bb57e3", 2819, "download: sanity-scan an archive's extracted payload"),
    ("76b4ecc9", 2816, "download: stream the XLSX shared-strings part past the run tmpdir"),
    ("309b1902", 2806, "download: refuse an XLSX extraction that finds no address"),
    ("3aa51d4d", 2782, "pfblockerng: stage the two direct-write GeoIP extractions"),
    ("4fa68d01", 2790, "tests: align the worktree-intelligence pin with the tracked root graph"),
    ("3aab75a1", 2775, "install-pkg.sh: fail closed when pkg POST-INSTALL fails"),
    ("624e9a75", 2756, "install.sh: document fetch-to-file not fetch|sh"),
    ("f9a7e158", 2740, "pfblockerng: unlink leftover Blacklist orig/hash sidecars"),
    ("8bb7d925", 2742, "pfblockerng: fail closed on bzip2/zip Blacklist bodies"),
    ("dc1debe1", 2741, "ci: add scripted refresh for artifact-action majors"),
    ("7896e379", 2737, "pfblockerng: return from gzip Blacklist success arm"),
    ("b9cc813d", 2593, "smoke: bootstrap ports clone into an empty pre-created dir"),
    ("86792fc5", 2594, "download: reject tar-bearing feeds"),
    ("29c9111e", 2576, "install: fail closed when pkg reports a script failure"),
    ("01c6ebd6", 2536, "install.sh: refuse an empty CA hash directory"),
    ("1f348346b", 2523, "Consented pkg.conf PKG_ENV patch so GUI and CLI pkg operations work on Plus boxes"),
    ("f0dddeb6", 2520, "pfblockerng: carry the box's CA locations on the Software catalog reads"),
    ("b2df9957", 2515, "install: export SSL_CA_CERT_PATH for every pkg call"),
    ("1e735e38", 2485, "smoke: keep polling when the post-boot metadata job has not started"),
    ("de69f67b", 2482, "wait-checks.sh: resolve an abbreviated `--sha` at arm time"),
    ("aaf8019d", 2444, "pkg Pages: one install-`<ch>`.sh per channel that converges the box from any starting state"),
)


def _live_ledger_entries() -> list[tuple[str, int, str]]:
    text = (_REPO_ROOT / ccb.LEDGER).read_text(encoding="utf-8")
    parsed = []
    for line in text.splitlines():
        if not line.startswith("- "):
            continue
        match = ccb.LEDGER_ENTRY_RE.match(line)
        assert match is not None, f"unparseable ledger entry: {line}"
        parsed.append((match["sha"], int(match["pr"]), match["title"]))
    return parsed


def test_live_ledger_keeps_every_recorded_sha_title_and_pr_in_order() -> None:
    # The contract compression may not break: every SHA still listed, with its
    # title and PR number, newest first.
    assert _live_ledger_entries()[-len(_LEDGER_RECORDED) :] == list(_LEDGER_RECORDED)


def test_live_ledger_header_states_the_format_and_the_entry_cap() -> None:
    # The format drifted because the header stated it only in passing; the
    # header now carries the template and the cap the checker enforces.
    header = (_REPO_ROOT / ccb.LEDGER).read_text(encoding="utf-8").split("\n- ", 1)[0]
    assert "`SHA`  title  (#PR)" in header
    assert f"{ccb.LEDGER_ENTRY_MAX} bytes" in header
