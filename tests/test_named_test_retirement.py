from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_named_test_retirement.py"
HISTORY = "docs/history/retired-tests.md"

LANGUAGES = (
    {
        "id": "python",
        "path": "tests/test_python_guard.py",
        "old": "test_python_old",
        "new": "test_python_new",
        "before": "def test_python_old():\n    assert True\n",
        "body": "def test_python_old():\n    assert 1 == 1\n",
        "renamed": "def test_python_new():\n    assert True\n",
        "successor": "{marker}\n\n@pytest.mark.guard\ndef test_python_new():\n    assert True\n",
    },
    {
        "id": "phpunit",
        "path": "tests/php/NamedRetirementTest.php",
        "old": "testPhpOld",
        "new": "testPhpNew",
        "before": (
            "<?php\nfinal class NamedRetirementTest extends TestCase\n{\n"
            "    public function testPhpOld(): void\n    {\n        self::assertTrue(true);\n    }\n}\n"
        ),
        "body": (
            "<?php\nfinal class NamedRetirementTest extends TestCase\n{\n"
            "    public function testPhpOld(): void\n    {\n        self::assertSame(1, 1);\n    }\n}\n"
        ),
        "renamed": (
            "<?php\nfinal class NamedRetirementTest extends TestCase\n{\n"
            "    public function testPhpNew(): void\n    {\n        self::assertTrue(true);\n    }\n}\n"
        ),
        "successor": (
            "<?php\nfinal class NamedRetirementTest extends TestCase\n{\n"
            "    {marker}\n\n    #[DataProvider('rows')]\n"
            "    public function testPhpNew(): void\n    {\n        self::assertTrue(true);\n    }\n}\n"
        ),
    },
    {
        "id": "shellspec",
        "path": "tests/shell/named_retirement_spec.sh",
        "old": "shell old",
        "new": "shell new",
        "before": "Describe 'named retirement'\n  It 'shell old'\n    The status should be success\n  End\nEnd\n",
        "body": "Describe 'named retirement'\n  It 'shell old'\n    The output should equal ok\n  End\nEnd\n",
        "renamed": "Describe 'named retirement'\n  It 'shell new'\n    The status should be success\n  End\nEnd\n",
        "successor": (
            "Describe 'named retirement'\n  {marker}\n\n"
            "  It 'shell new' env:ports\n    The status should be success\n  End\nEnd\n"
        ),
    },
)

DECLARATIONS = (
    (
        "python-top-level",
        "tests/test_forms.py",
        "def test_top_level():\n    assert True\n",
        "test_top_level",
        "\n",
    ),
    (
        "python-class-method",
        "tests/test_forms.py",
        "class TestForms:\n    def test_indented_method(self):\n        assert True\n",
        "test_indented_method",
        "class TestForms:\n    pass\n",
    ),
    (
        "python-async",
        "tests/test_forms.py",
        "async def test_async_form():\n    return None\n",
        "test_async_form",
        "\n",
    ),
    (
        "phpunit-camel",
        "tests/php/FormsTest.php",
        "<?php\nclass FormsTest {\n    public function testCamelForm(): void {}\n}\n",
        "testCamelForm",
        "<?php\nclass FormsTest {}\n",
    ),
    (
        "phpunit-snake",
        "tests/php/FormsTest.php",
        "<?php\nclass FormsTest {\n    public function test_snake_form(): void {}\n}\n",
        "test_snake_form",
        "<?php\nclass FormsTest {}\n",
    ),
    (
        "phpunit-attribute",
        "tests/php/FormsTest.php",
        "<?php\nclass FormsTest {\n    #[DataProvider('rows')]\n    public function testAttributed(): void {}\n}\n",
        "testAttributed",
        "<?php\nclass FormsTest {}\n",
    ),
    (
        "shellspec-single",
        "tests/shell/forms_spec.sh",
        "Describe 'forms'\n  It 'single quoted title'\n  End\nEnd\n",
        "single quoted title",
        "Describe 'forms'\nEnd\n",
    ),
    (
        "shellspec-double-dollar",
        "tests/shell/forms_spec.sh",
        "Describe 'forms'\n  It \"double quoted $1\"\n  End\nEnd\n",
        "double quoted $1",
        "Describe 'forms'\nEnd\n",
    ),
    (
        "shellspec-tags",
        "tests/shell/forms_spec.sh",
        "Describe 'forms'\n  It 'tagged title' env:ports focus:network\n  End\nEnd\n",
        "tagged title",
        "Describe 'forms'\nEnd\n",
    ),
)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        check=check,
    )


def _write(repo: Path, rel: str | bytes, content: str | bytes) -> None:
    raw_rel = os.fsencode(rel) if isinstance(rel, str) else rel
    target = os.path.join(os.fsencode(repo), raw_rel)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as stream:
        stream.write(content.encode() if isinstance(content, str) else content)


def _remove(repo: Path, rel: str | bytes) -> None:
    raw_rel = os.fsencode(rel) if isinstance(rel, str) else rel
    os.unlink(os.path.join(os.fsencode(repo), raw_rel))


def _rename(repo: Path, old: str, new: str) -> None:
    destination = repo / new
    destination.parent.mkdir(parents=True, exist_ok=True)
    (repo / old).rename(destination)


def _commit(repo: Path, message: str = "fixture change") -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD").stdout.decode().strip()


def _repo(tmp_path: Path, files: Mapping[str | bytes, str | bytes]) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "Named retirement tests")
    _git(repo, "config", "commit.gpgsign", "false")
    for rel, content in files.items():
        _write(repo, rel, content)
    return repo, _commit(repo, "baseline")


def _checker(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *args],
        cwd=repo,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        check=False,
    )


def _diff(repo: Path, base: str) -> subprocess.CompletedProcess[bytes]:
    return _checker(repo, "--diff", base)


def _staged(repo: Path) -> subprocess.CompletedProcess[bytes]:
    return _checker(repo, "--staged")


def _output(proc: subprocess.CompletedProcess[bytes]) -> str:
    return (proc.stdout + proc.stderr).decode("utf-8", errors="backslashreplace")


def _assert_rc(proc: subprocess.CompletedProcess[bytes], expected: int) -> str:
    output = _output(proc)
    assert proc.returncode == expected, f"expected rc={expected}, got rc={proc.returncode}\n{output}"
    return output


def _identity(case: dict[str, str]) -> str:
    return f"{case['path']}::{case['old']}"


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _tombstone(identity: str, reason: str = "superseded by stronger coverage", *, when: str | None = None) -> str:
    record = {"date": when or _today().isoformat(), "test": identity, "reason": reason}
    return "- " + json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"


@pytest.mark.parametrize(
    ("_form", "path", "before", "name", "after"), DECLARATIONS, ids=[row[0] for row in DECLARATIONS]
)
def test_every_named_declaration_form_retires_exact_identifier(
    tmp_path: Path, _form: str, path: str, before: str, name: str, after: str
) -> None:
    repo, base = _repo(tmp_path, {path: before})
    _write(repo, path, after)
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert f"{path}::{name}" in output, output


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_deleting_named_test_blocks_for_each_language(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    _write(repo, case["path"], "\n")
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert _identity(case) in output, output


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_renaming_named_test_blocks_old_identity_for_each_language(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    _write(repo, case["path"], case["renamed"])
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert _identity(case) in output, output


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_canonical_successor_passes_for_each_language(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    marker = f"# successor: {_identity(case)}"
    _write(repo, case["path"], case["successor"].replace("{marker}", marker))
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_new_tombstone_passes_for_each_language(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    _write(repo, case["path"], "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone(_identity(case)))
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_body_only_edit_is_neutral_for_each_language(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    _write(repo, case["path"], case["body"])
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


@pytest.mark.parametrize("case", LANGUAGES, ids=[case["id"] for case in LANGUAGES])
def test_pure_file_rename_preserving_language_and_names_is_neutral(tmp_path: Path, case: dict[str, str]) -> None:
    repo, base = _repo(tmp_path, {case["path"]: case["before"]})
    old = Path(case["path"])
    new = str(old.with_name("renamed " + old.name))
    _rename(repo, case["path"], new)
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_whole_file_delete_reports_every_retired_name(tmp_path: Path) -> None:
    path = "tests/test_whole_file.py"
    repo, base = _repo(
        tmp_path,
        {path: "def test_first():\n    assert True\n\ndef test_second():\n    assert True\n"},
    )
    _remove(repo, path)
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert f"{path}::test_first" in output and f"{path}::test_second" in output, output


def test_low_similarity_move_seen_as_delete_add_still_reports_retirement(tmp_path: Path) -> None:
    old = "tests/test_low_similarity_old.py"
    new = "tests/test_low_similarity_new.py"
    before = "def test_low_similarity_old():\n    assert True\n" + "\n".join(f"# old-{n}" for n in range(80)) + "\n"
    after = (
        "def test_low_similarity_new():\n    assert True\n"
        + "\n".join(f"# new-{n}-different" for n in range(80))
        + "\n"
    )
    repo, base = _repo(tmp_path, {old: before})
    _remove(repo, old)
    _write(repo, new, after)
    _commit(repo)

    status = _git(repo, "diff", "--name-status", "-z", "--find-renames", f"{base}...HEAD").stdout
    assert status == f"A\0{new}\0D\0{old}\0".encode() or status == f"D\0{old}\0A\0{new}\0".encode(), status
    output = _assert_rc(_diff(repo, base), 1)
    assert f"{old}::test_low_similarity_old" in output, output


def test_successor_may_live_in_another_file(tmp_path: Path) -> None:
    old = "tests/test_cross_file_old.py"
    new = "tests/test_cross_file_new.py"
    repo, base = _repo(tmp_path, {old: "def test_old_cross_file():\n    assert True\n"})
    _remove(repo, old)
    _write(
        repo,
        new,
        f"# successor: {old}::test_old_cross_file\n\ndef test_new_cross_file():\n    assert True\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_multiple_independent_retirements_each_need_a_discharge(tmp_path: Path) -> None:
    files = {case["path"]: case["before"] for case in LANGUAGES}
    repo, base = _repo(tmp_path, files)
    for case in LANGUAGES:
        _write(repo, case["path"], "\n")
    _commit(repo, "retire all")

    output = _assert_rc(_diff(repo, base), 1)
    assert all(_identity(case) in output for case in LANGUAGES), output

    python, php, shell = LANGUAGES
    _write(
        repo,
        python["path"],
        python["successor"].replace("{marker}", f"# successor: {_identity(python)}"),
    )
    _write(
        repo,
        HISTORY,
        "# Retired tests\n\n" + _tombstone(_identity(php)) + _tombstone(_identity(shell)),
    )
    _commit(repo, "discharge all")
    _assert_rc(_diff(repo, base), 0)


def test_unique_bare_successor_name_is_accepted(tmp_path: Path) -> None:
    path = "tests/test_unique_bare.py"
    repo, base = _repo(tmp_path, {path: "def test_unique_old():\n    assert True\n"})
    _write(repo, path, "# successor: test_unique_old\n\ndef test_unique_new():\n    assert True\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_unique_bare_tombstone_name_is_accepted(tmp_path: Path) -> None:
    path = "tests/test_unique_bare_tombstone.py"
    repo, base = _repo(tmp_path, {path: "def test_unique_tombstone_old():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone("test_unique_tombstone_old"))
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


@pytest.mark.parametrize(
    "marker",
    (
        "# successor:",
        "# successor : test_marker_old",
        "# successor:test_marker_old",
        "# Successor: test_marker_old",
        "// successor: test_marker_old",
        "## successor: test_marker_old",
    ),
)
def test_empty_or_malformed_successor_attempt_is_rejected(tmp_path: Path, marker: str) -> None:
    path = "tests/test_marker_shape.py"
    repo, base = _repo(tmp_path, {path: "def test_marker_old():\n    assert True\n"})
    _write(repo, path, f"{marker}\n\ndef test_marker_new():\n    assert True\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_duplicate_successor_marker_value_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_duplicate_marker.py"
    identity = f"{path}::test_duplicate_old"
    repo, base = _repo(tmp_path, {path: "def test_duplicate_old():\n    assert True\n"})
    _write(
        repo,
        path,
        f"# successor: {identity}\ndef test_new_one():\n    assert True\n\n"
        f"# successor: {identity}\ndef test_new_two():\n    assert True\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


@pytest.mark.parametrize(
    "forgery",
    (
        'TEXT = "# successor: test_forged_old"',
        'print("# successor: test_forged_old")',
        "This prose says # successor: test_forged_old",
    ),
)
def test_marker_forged_in_string_or_prose_is_not_accepted(tmp_path: Path, forgery: str) -> None:
    path = "tests/test_forged_marker.py"
    repo, base = _repo(tmp_path, {path: "def test_forged_old():\n    assert True\n"})
    _write(repo, path, f"{forgery}\n\ndef test_forged_new():\n    assert True\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


@pytest.mark.parametrize(
    ("path", "before", "after"),
    (
        (
            "tests/php/ForgedMarkerTest.php",
            "<?php\nclass ForgedMarkerTest { public function testForgedPhpOld(): void {} }\n",
            "<?php\nclass ForgedMarkerTest {\n"
            '    public string $text = "# successor: testForgedPhpOld";\n'
            "    public function testForgedPhpNew(): void {}\n}\n",
        ),
        (
            "tests/shell/forged_marker_spec.sh",
            "Describe 'forged'\n  It 'forged shell old'\n  End\nEnd\n",
            "Describe '# successor: forged shell old'\n  It 'forged shell new'\n  End\nEnd\n",
        ),
    ),
    ids=("phpunit-string", "shellspec-quoted-prose"),
)
def test_marker_forged_in_each_language_quote_syntax_is_not_accepted(
    tmp_path: Path, path: str, before: str, after: str
) -> None:
    repo, base = _repo(tmp_path, {path: before})
    _write(repo, path, after)
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_marker_attached_to_unchanged_test_is_rejected(tmp_path: Path) -> None:
    old = "tests/test_retired_elsewhere.py"
    unchanged = "tests/test_unchanged_target.py"
    repo, base = _repo(
        tmp_path,
        {
            old: "def test_retired_elsewhere():\n    assert True\n",
            unchanged: "def test_existing_target():\n    assert True\n",
        },
    )
    _write(repo, old, "\n")
    _write(
        repo,
        unchanged,
        f"# successor: {old}::test_retired_elsewhere\ndef test_existing_target():\n    assert True\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_marker_without_matching_retirement_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_no_retirement.py"
    repo, base = _repo(tmp_path, {path: "def test_existing():\n    assert True\n"})
    _write(
        repo,
        path,
        "def test_existing():\n    assert True\n\n# successor: test_missing\ndef test_added():\n    assert True\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_ambiguous_bare_name_cannot_select_duplicate_identities(tmp_path: Path) -> None:
    first = "tests/test_duplicate_first.py"
    second = "tests/test_duplicate_second.py"
    successor = "tests/test_duplicate_successor.py"
    repo, base = _repo(
        tmp_path,
        {
            first: "def test_same_bare_name():\n    assert True\n",
            second: "def test_same_bare_name():\n    assert True\n",
        },
    )
    _remove(repo, first)
    _remove(repo, second)
    _write(repo, successor, "# successor: test_same_bare_name\ndef test_replacement():\n    assert True\n")
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert f"{first}::test_same_bare_name" in output and f"{second}::test_same_bare_name" in output, output


def test_one_marker_cannot_discharge_duplicate_occurrences(tmp_path: Path) -> None:
    path = "tests/test_duplicate_occurrences.py"
    repo, base = _repo(
        tmp_path,
        {path: "def test_repeated():\n    assert True\n\ndef test_repeated():\n    assert False\n"},
    )
    _write(repo, path, f"# successor: {path}::test_repeated\ndef test_replacement():\n    assert True\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_marker_must_be_immediately_associated_with_new_named_test(tmp_path: Path) -> None:
    path = "tests/test_marker_association.py"
    repo, base = _repo(tmp_path, {path: "def test_association_old():\n    assert True\n"})
    _write(
        repo,
        path,
        "# successor: test_association_old\nVALUE = 1\n\ndef test_association_new():\n    assert True\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_marker_attached_to_non_test_declaration_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_marker_non_test.py"
    repo, base = _repo(tmp_path, {path: "def test_non_test_old():\n    assert True\n"})
    _write(repo, path, "# successor: test_non_test_old\ndef helper():\n    return True\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_shellspec_metacharacters_and_both_quote_kinds_match_exactly(tmp_path: Path) -> None:
    path = "tests/shell/metachar_spec.sh"
    title = "literal [a-z]* $(echo nope) 'single' \"double\""
    source = "Describe 'hostile'\n  It \"literal [a-z]* $(echo nope) 'single' \\\"double\\\"\"\n  End\nEnd\n"
    repo, base = _repo(tmp_path, {path: source})
    _write(
        repo,
        path,
        f"Describe 'hostile'\n  # successor: {path}::{title}\n  It 'safe replacement'\n  End\nEnd\n",
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


@pytest.mark.parametrize(
    ("path", "before", "after"),
    (
        ("tests/test_comments.py", "# def test_commented():\nVALUE = 1\n", "VALUE = 2\n"),
        (
            "tests/php/CommentedTest.php",
            "<?php\n// public function testCommented(): void {}\n$value = 1;\n",
            "<?php\n$value = 2;\n",
        ),
        (
            "tests/shell/commented_spec.sh",
            "# It 'commented shell test'\nvalue=1\n",
            "value=2\n",
        ),
    ),
    ids=("python", "phpunit", "shellspec"),
)
def test_commented_declaration_and_prose_are_not_tests(tmp_path: Path, path: str, before: str, after: str) -> None:
    repo, base = _repo(tmp_path, {path: before})
    _write(repo, path, after)
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_checker_never_executes_repository_content(tmp_path: Path) -> None:
    path = "tests/test_never_execute.py"
    sentinel = tmp_path / "executed"
    before = "def test_never_execute():\n    assert True\n"
    after = (
        f"__import__('pathlib').Path({str(sentinel)!r}).write_text('executed')\n"
        "def test_never_execute():\n    assert 1 == 1\n"
    )
    repo, base = _repo(tmp_path, {path: before})
    _write(repo, path, after)
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)
    assert not sentinel.exists(), "checker executed changed Python test content"


def test_checker_ignores_its_self_referential_test_file(tmp_path: Path) -> None:
    repo, base = _repo(tmp_path, {"README": "baseline\n"})
    _write(
        repo,
        "tests/test_named_test_retirement.py",
        'MARKER = "# successor: test_fixture_old"\ndef test_checker_fixture():\n    assert True\n',
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_preexisting_tombstone_cannot_discharge_later_retirement(tmp_path: Path) -> None:
    path = "tests/test_preexisting_tombstone.py"
    identity = f"{path}::test_preexisting_old"
    repo, base = _repo(
        tmp_path,
        {
            path: "def test_preexisting_old():\n    assert True\n",
            HISTORY: "# Retired tests\n\n" + _tombstone(identity),
        },
    )
    _write(repo, path, "\n")
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert identity in output, output


def test_tombstone_without_matching_retirement_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_no_tombstone_retirement.py"
    repo, base = _repo(tmp_path, {path: "def test_still_present():\n    assert True\n"})
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone("test_never_existed"))
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_ambiguous_bare_tombstone_cannot_select_duplicate_identities(tmp_path: Path) -> None:
    first = "tests/test_tombstone_duplicate_first.py"
    second = "tests/test_tombstone_duplicate_second.py"
    repo, base = _repo(
        tmp_path,
        {
            first: "def test_same_tombstone_name():\n    assert True\n",
            second: "def test_same_tombstone_name():\n    assert True\n",
        },
    )
    _remove(repo, first)
    _remove(repo, second)
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone("test_same_tombstone_name"))
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert f"{first}::test_same_tombstone_name" in output
    assert f"{second}::test_same_tombstone_name" in output


@pytest.mark.parametrize(
    "record",
    (
        {"test": "tests/test_bad_date.py::test_bad_date", "reason": "missing date"},
        {"date": "not-a-date", "test": "tests/test_bad_date.py::test_bad_date", "reason": "bad date"},
        {"date": "2026-02-30", "test": "tests/test_bad_date.py::test_bad_date", "reason": "impossible date"},
    ),
    ids=("missing", "syntax", "impossible"),
)
def test_missing_or_bad_tombstone_date_is_rejected(tmp_path: Path, record: dict[str, str]) -> None:
    path = "tests/test_bad_date.py"
    repo, base = _repo(tmp_path, {path: "def test_bad_date():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n- " + json.dumps(record, separators=(",", ":")) + "\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_future_tombstone_date_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_future_date.py"
    identity = f"{path}::test_future_date"
    repo, base = _repo(tmp_path, {path: "def test_future_date():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(
        repo,
        HISTORY,
        "# Retired tests\n\n" + _tombstone(identity, when=(_today() + timedelta(days=1)).isoformat()),
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


@pytest.mark.parametrize("reason", ("", "   "))
def test_blank_tombstone_reason_is_rejected(tmp_path: Path, reason: str) -> None:
    path = "tests/test_blank_reason.py"
    identity = f"{path}::test_blank_reason"
    repo, base = _repo(tmp_path, {path: "def test_blank_reason():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone(identity, reason))
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_malformed_tombstone_json_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_malformed_tombstone.py"
    repo, base = _repo(tmp_path, {path: "def test_malformed_tombstone():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(
        repo,
        HISTORY,
        '# Retired tests\n\n- {"date":"2026-08-30",'
        '"test":"tests/test_malformed_tombstone.py::test_malformed_tombstone"\n',
    )
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_duplicate_added_tombstone_is_rejected(tmp_path: Path) -> None:
    path = "tests/test_duplicate_tombstone.py"
    identity = f"{path}::test_duplicate_tombstone"
    row = _tombstone(identity)
    repo, base = _repo(tmp_path, {path: "def test_duplicate_tombstone():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + row + row)
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_hostile_identity_and_reason_round_trip_through_tombstone_json(tmp_path: Path) -> None:
    path = 'tests/odd "quoted" \\ café.py'
    name = "test_μ"
    identity = f"{path}::{name}"
    reason = 'replaced "safely" \\ no\tcommands $(touch nope)'
    repo, base = _repo(tmp_path, {path: f"def {name}():\n    assert True\n"})
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone(identity, reason))
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_one_tombstone_cannot_discharge_duplicate_occurrences(tmp_path: Path) -> None:
    path = "tests/test_duplicate_tombstone_occurrences.py"
    identity = f"{path}::test_repeated_tombstone"
    repo, base = _repo(
        tmp_path,
        {path: "def test_repeated_tombstone():\n    assert True\n\ndef test_repeated_tombstone():\n    assert False\n"},
    )
    _write(repo, path, "\n")
    _write(repo, HISTORY, "# Retired tests\n\n" + _tombstone(identity))
    _commit(repo)

    _assert_rc(_diff(repo, base), 1)


def test_preexisting_malformed_history_is_not_scanned_when_unchanged(tmp_path: Path) -> None:
    path = "tests/test_diff_scope.py"
    repo, base = _repo(
        tmp_path,
        {
            path: "def test_diff_scope():\n    assert True\n",
            HISTORY: "# Retired tests\n\n- malformed historical prose\n",
        },
    )
    _write(repo, path, "def test_diff_scope():\n    assert 1 == 1\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


HOSTILE_PATHS = (
    "tests/space bearing/test_old.py",
    "tests/tab\tbearing/test_old.py",
    "tests/newline\nbearing/test_old.py",
    "tests/-leading-dash.py",
    "tests/back\\slash/test_old.py",
    "tests/café/test_old.py",
)


@pytest.mark.parametrize("path", HOSTILE_PATHS, ids=("space", "tab", "newline", "dash", "backslash", "utf8"))
def test_nul_status_stream_preserves_hostile_deleted_paths(tmp_path: Path, path: str) -> None:
    repo, base = _repo(tmp_path, {path: "def test_hostile_path():\n    assert True\n"})
    _remove(repo, path)
    _commit(repo)

    output = _assert_rc(_diff(repo, base), 1)
    assert f"{path}::test_hostile_path" in output, output


@pytest.mark.parametrize("source", HOSTILE_PATHS, ids=("space", "tab", "newline", "dash", "backslash", "utf8"))
def test_hostile_rename_source_and_destination_remain_neutral(tmp_path: Path, source: str) -> None:
    suffix = Path(source).suffix
    destination = f"tests/renamed destination\t café{suffix}"
    repo, base = _repo(tmp_path, {source: "def test_hostile_rename():\n    assert True\n"})
    _rename(repo, source, destination)
    _commit(repo)

    _assert_rc(_diff(repo, base), 0)


def test_invalid_utf8_blob_is_deterministic_tool_error(tmp_path: Path) -> None:
    path = "tests/test_invalid_blob.py"
    repo, base = _repo(tmp_path, {path: b"def test_invalid_blob():\n    assert True\n# \xff\n"})
    _write(repo, path, b"def test_invalid_blob():\n    assert False\n# \xff\n")
    _commit(repo)

    _assert_rc(_diff(repo, base), 2)


def test_invalid_utf8_path_is_deterministic_tool_error(tmp_path: Path) -> None:
    path = b"tests/test-invalid-\xff.py"
    repo, _initial = _repo(tmp_path, {"README": "baseline\n"})
    env = scrubbed_git_env(drop_git_vars=True)
    blob = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=repo,
        env=env,
        input=b"def test_invalid_path():\n    assert True\n",
        capture_output=True,
        check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "-z", "--index-info"],
        cwd=repo,
        env=env,
        input=b"100644 blob " + blob + b"\t" + path + b"\0",
        capture_output=True,
        check=True,
    )
    _git(repo, "commit", "-qm", "invalid path baseline")
    base = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    assert path in _git(repo, "ls-tree", "-rz", "--name-only", "HEAD").stdout

    subprocess.run(
        ["git", "update-index", "-z", "--index-info"],
        cwd=repo,
        env=env,
        input=b"0 " + b"0" * 40 + b"\t" + path + b"\0",
        capture_output=True,
        check=True,
    )
    _git(repo, "commit", "-qm", "delete invalid path")

    _assert_rc(_diff(repo, base), 2)


def test_malformed_shellspec_quote_errors_only_when_changed(tmp_path: Path) -> None:
    malformed = "tests/shell/preexisting_malformed_spec.sh"
    changed = "tests/test_other_change.py"
    repo, base = _repo(
        tmp_path,
        {
            malformed: "Describe 'broken'\n  It 'unterminated\n  End\nEnd\n",
            changed: "def test_other_change():\n    assert True\n",
        },
    )
    _write(repo, changed, "def test_other_change():\n    assert 1 == 1\n")
    _commit(repo)
    _assert_rc(_diff(repo, base), 0)

    _write(repo, malformed, "Describe 'broken'\n  It 'still unterminated\n  End\nEnd\n")
    _commit(repo)
    _assert_rc(_diff(repo, base), 2)


@pytest.mark.parametrize("args", ((), ("--diff",), ("--diff", "refs/heads/does-not-exist")))
def test_usage_and_git_failures_exit_two(tmp_path: Path, args: tuple[str, ...]) -> None:
    repo, _base = _repo(tmp_path, {"tests/test_usage.py": "def test_usage():\n    assert True\n"})

    _assert_rc(_checker(repo, *args), 2)


def test_staged_retirement_blocks_and_staged_successor_passes(tmp_path: Path) -> None:
    path = "tests/test_staged.py"
    repo, _base = _repo(tmp_path, {path: "def test_staged_old():\n    assert True\n"})
    _write(repo, path, "\n")
    _git(repo, "add", "-A")
    output = _assert_rc(_staged(repo), 1)
    assert f"{path}::test_staged_old" in output, output

    _write(repo, path, "# successor: test_staged_old\ndef test_staged_new():\n    assert True\n")
    _git(repo, "add", "-A")
    _assert_rc(_staged(repo), 0)


def _job_block(workflow: str, job: str) -> str:
    marker = f"  {job}:\n"
    assert marker in workflow, f"missing workflow job {job!r}"
    tail = workflow.split(marker, 1)[1]
    lines = tail.splitlines()
    end = next(
        (
            index
            for index, line in enumerate(lines)
            if line
            and len(line) - len(line.lstrip()) == 2
            and line.rstrip().endswith(":")
            and not line.lstrip().startswith("#")
        ),
        len(lines),
    )
    return "\n".join(lines[:end])


def _run_block(job: str) -> str:
    lines = job.splitlines()
    checker_lines = [index for index, line in enumerate(lines) if "check_named_test_retirement.py" in line]
    assert checker_lines, "named-test-retirement job never invokes checker"
    target = checker_lines[-1]
    run = max(index for index in range(target + 1) if lines[index].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip())
    body: list[str] = []
    for line in lines[run + 1 :]:
        if line and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line[indent + 2 :] if line else "")
    return "\n".join(body)


def test_precommit_invokes_staged_checker_once_and_failure_is_blocking() -> None:
    hook = (ROOT / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    command = '"$py_bin" scripts/check_named_test_retirement.py --staged'

    assert hook.count("scripts/check_named_test_retirement.py") == 2, "expected exemption plus one invocation"
    assert "if exempted scripts/check_named_test_retirement.py; then" in hook
    assert command in hook
    line = next(line.strip() for line in hook.splitlines() if command in line)
    assert "|| failed 'named-test-retirement'" in line and "|| true" not in line, line


def test_ci_wiring_has_same_block_red_canary_live_pipeline_and_result_fold() -> None:
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    job = _job_block(workflow, "named-test-retirement")
    run = _run_block(job)
    checker_commands = [line.strip() for line in run.splitlines() if "check_named_test_retirement.py" in line]

    assert "if: github.event_name == 'pull_request'" in job
    assert "fetch-depth: 0" in job
    assert run.splitlines()[0] == "set -euo pipefail", run
    assert len(checker_commands) == 2, checker_commands
    assert checker_commands[0].startswith("if ") and "| tee " in checker_commands[0]
    assert "--diff" in checker_commands[0]
    assert not checker_commands[1].startswith("if ") and '| tee -a "$GITHUB_STEP_SUMMARY"' in checker_commands[1]
    assert '--diff "origin/$BASE"' in checker_commands[1]

    aggregate = _job_block(workflow, "all-tests-passed")
    needs = next(line for line in aggregate.splitlines() if line.strip().startswith("needs:"))
    assert "named-test-retirement" in needs
    assert "${{ needs.named-test-retirement.result }}" in aggregate
    assert "success|skipped" in aggregate


def test_ci_red_canary_pipeline_executes_real_checker_and_discriminates(tmp_path: Path) -> None:
    path = "tests/test_ci_canary.py"
    repo, base = _repo(tmp_path, {path: "def test_ci_canary_old():\n    assert True\n"})
    _write(repo, path, "\n")
    _commit(repo, "planted offence")
    summary = tmp_path / "summary"
    env = {**scrubbed_git_env(drop_git_vars=True), "BASE": base, "SUMMARY": str(summary)}
    command = (
        f'if {sys.executable!s} {CHECKER!s} --diff "$BASE" | tee "$SUMMARY"; then '
        "echo 'red canary unexpectedly passed' >&2; exit 99; fi"
    )
    proc = subprocess.run(
        ["bash", "-o", "pipefail", "-c", command], cwd=repo, env=env, capture_output=True, check=False
    )

    assert proc.returncode == 0, _output(proc)
    assert f"{path}::test_ci_canary_old" in summary.read_text(encoding="utf-8")

    _write(repo, path, "# successor: test_ci_canary_old\ndef test_ci_canary_new():\n    assert True\n")
    _commit(repo, "valid successor")
    _assert_rc(_diff(repo, base), 0)


def test_canonical_runner_plan_includes_checker_exactly_once_with_exported_base() -> None:
    proc = subprocess.run(
        ["sh", "scripts/agent/run-gates.sh", "--diff", "HEAD", "--plan"],
        cwd=ROOT,
        env=scrubbed_git_env(drop_git_vars=True),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    command = 'python3 scripts/check_named_test_retirement.py --diff "$PFB_GATE_BASE"'
    assert proc.stdout.splitlines().count(command) == 1, proc.stdout
    runner = (ROOT / "scripts" / "agent" / "run-gates.sh").read_text(encoding="utf-8")
    assert "PFB_GATE_BASE=$base" in runner and "export PFB_GATE_BASE" in runner
