"""Issue #3073: a path `nul_listing` hands back must name the file it came from.

`scripts/_git_paths.py` serves two routes out of one `git` invocation, and only
one of them is text. Diff TEXT is matched and printed, so it decodes lossily --
a stray non-UTF-8 byte in someone's file content must never abort a gate. Path
LISTINGS are opened by their consumers, so the same lossy decode is a defect:
U+FFFD names no file, and a scanner handed one either raises or -- the worse
outcome -- classifies the mangled name against no rule and reports a clean pass
over a file it never read (`check_agent_roles.py`, `check_context_budget.py`,
`tests/test_issue3066_php_grammar_parse.py`).

Byte-exactness here means `os.fsdecode`, not a hard-coded UTF-8 surrogateescape:
the two agree only while the filesystem encoding IS UTF-8, and under an ASCII one
(`LC_ALL=C` with UTF-8 mode off, which is what a hook or a locale-less CI shell
gets) a hard-coded UTF-8 decode turns a perfectly valid `café.php` into a `str`
that `open` cannot encode back.

Byte-exact paths carry lone surrogates, which a strict stdout cannot encode, so
the one consumer that PRINTS a listed path is pinned here too: a gate must report
the violation it found, not die reporting it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from _git_paths import nul_listing, unified_diff

from tests.gitenv import scrubbed_git_env

# A raw 0xFF is not valid UTF-8 in any position, so it is the shortest name that
# distinguishes a byte-exact decode from a lossy one.
_NON_UTF8_NAME = b"bad_\xff_name.php"
# Valid UTF-8, but not ASCII: the name that only `os.fsdecode` keeps openable
# when the filesystem encoding is not UTF-8.
_UTF8_NAME = "café.php".encode()
_SPACED_NAME = b"has space.php"
_BODY = b"<?php\n"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BUDGET_TOOL = _REPO_ROOT / "scripts" / "check_context_budget.py"


def _git(root: Path, *args: str) -> None:
    # scrubbed_git_env: a scratch repo must not inherit commit.gpgsign or a real
    # core.hooksPath from the developer's config (issue #1967), and must not be
    # redirected at the REAL repo by an inherited GIT_DIR when the suite runs
    # under a hook.
    subprocess.run(["git", "-C", str(root), *args], check=True, env=scrubbed_git_env(drop_git_vars=True))


def _seed_repo(root: Path, names: tuple[bytes, ...]) -> None:
    """A committed scratch repo holding one file per name in `names`."""
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True, env=scrubbed_git_env(drop_git_vars=True))
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")
    for name in names:
        (root / os.fsdecode(name)).write_bytes(_BODY)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "seed")


@pytest.mark.parametrize(
    ("label", "name"),
    [("non-UTF-8", _NON_UTF8_NAME), ("spaced", _SPACED_NAME), ("valid UTF-8", _UTF8_NAME)],
)
def test_listed_path_opens_the_file_it_names(tmp_path: Path, label: str, name: bytes) -> None:
    """Every listed path is openable -- the whole contract, one row per byte class."""
    _seed_repo(tmp_path, (_NON_UTF8_NAME, _SPACED_NAME, _UTF8_NAME))
    listed = nul_listing(tmp_path, "ls-files", "-z")

    wanted = os.fsdecode(name)
    assert wanted in listed, f"the {label} name must survive the listing: expected {wanted!r} among {listed!r}"
    assert (tmp_path / wanted).read_bytes() == _BODY, (
        f"the {label} path came back unopenable, so every consumer that reads what it lists is "
        f"scanning nothing: {wanted!r}"
    )


def test_listing_is_byte_identical_to_what_git_emitted(tmp_path: Path) -> None:
    """No path is silently re-encoded: fsencode of each listed path is git's own bytes."""
    _seed_repo(tmp_path, (_NON_UTF8_NAME, _SPACED_NAME, _UTF8_NAME))
    raw = subprocess.run(
        ["git", "-C", str(tmp_path), "ls-files", "-z"],
        capture_output=True,
        check=True,
        env=scrubbed_git_env(drop_git_vars=True),
    ).stdout
    expected = sorted(field for field in raw.split(b"\0") if field)

    listed = sorted(os.fsencode(path) for path in nul_listing(tmp_path, "ls-files", "-z"))
    assert listed == expected, f"listing is not byte-exact: expected {expected!r}, got {listed!r}"


def test_valid_utf8_name_opens_under_an_ascii_filesystem_encoding(tmp_path: Path) -> None:
    """Scenario: the decode follows the FILESYSTEM's encoding, not a hard-coded UTF-8.

    Given a tracked `café.php` and an interpreter whose filesystem encoding is
    ASCII (`LC_ALL=C`, UTF-8 mode off -- a git hook's environment), when the
    listing is decoded as UTF-8 the returned `str` holds U+00E9, which `open`
    cannot encode back onto an ASCII filesystem; decoded with `os.fsdecode` it
    holds the two escaped bytes git actually emitted and opens.
    """
    _seed_repo(tmp_path, (_UTF8_NAME,))
    probe = (
        "import sys;"
        "sys.path.insert(0, sys.argv[1]);"
        "from _git_paths import nul_listing;"
        "from pathlib import Path;"
        "root = Path(sys.argv[2]);"
        "listed = nul_listing(root, 'ls-files', '-z');"
        "sys.stdout.buffer.write(b'|'.join((root / p).read_bytes() for p in listed))"
    )
    env = {
        **scrubbed_git_env(drop_git_vars=True),
        # PEP 540 would otherwise force UTF-8 mode for the C locale and hide the
        # difference this case exists to catch.
        "PYTHONUTF8": "0",
        "PYTHONCOERCECLOCALE": "0",
        "LC_ALL": "C",
        "LANG": "C",
    }
    proc = subprocess.run(
        [sys.executable, "-c", probe, str(_REPO_ROOT / "scripts"), str(tmp_path)],
        capture_output=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, (
        "a valid UTF-8 tracked name must stay openable under an ASCII filesystem encoding; "
        f"the probe exited {proc.returncode}: {proc.stderr.decode('utf-8', 'replace')}"
    )
    assert proc.stdout == _BODY, f"expected the file's body back, got {proc.stdout!r}"


def test_staged_but_deleted_file_stays_in_the_listing(tmp_path: Path) -> None:
    """`ls-files` reports the INDEX, and so does this helper -- no worktree filter.

    Dropping a path whose file is missing from the worktree would be the same
    silent skip this issue is about, and it would be wrong on top: the staged
    mode of `check_context_budget.py` materialises the index into a temp root
    (`checkout-index --all`) and joins these paths against THAT, where the file
    is present. Callers own the missing-file case -- `check_sizes` already turns
    the `OSError` into a fail-closed violation rather than a skip.
    """
    _seed_repo(tmp_path, (_SPACED_NAME,))
    staged = tmp_path / "staged_then_removed.php"
    staged.write_bytes(_BODY)
    _git(tmp_path, "add", staged.name)
    staged.unlink()

    listed = nul_listing(tmp_path, "ls-files", "-z")
    assert staged.name in listed, (
        f"a staged file removed from the worktree must still be listed so the caller can decide; got {listed!r}"
    )


def test_diff_text_with_a_non_utf8_byte_decodes_lossily_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Diff TEXT keeps the lossy decode: it is matched and PRINTED, never opened.

    A byte-exact decode would put lone surrogates in the returned text, and the
    first gate that prints a violation line would die on `UnicodeEncodeError`
    instead of reporting -- the crash the lossy decode exists to prevent.
    """
    content = tmp_path / "content.txt"
    _seed_repo(tmp_path, (b"seed.php",))
    content.write_bytes(b"first\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "content")
    content.write_bytes(b"first\nlatin \xff byte\n")
    _git(tmp_path, "add", "-A")

    monkeypatch.chdir(tmp_path)
    diff = unified_diff(["--cached"])

    assert "latin \ufffd byte" in diff, f"the undecodable byte must be replaced, not dropped or raised on: {diff!r}"
    # The property the replacement buys: the text can reach a strict UTF-8 stream.
    assert diff.encode("utf-8"), "diff text must stay encodable so a gate can print the line it flagged"


def test_budget_gate_reports_a_violation_whose_path_is_not_valid_utf8(tmp_path: Path) -> None:
    """Scenario: the gate must REPORT the file it just became able to measure.

    Given an over-budget policy file whose tracked name holds a raw 0xFF, when
    `check_context_budget.py` runs on a strict-UTF-8 stdout (`PYTHONIOENCODING`,
    i.e. any real `*.UTF-8` locale), then it prints the size violation and exits
    1 -- it does not die with `UnicodeEncodeError` while printing the lone
    surrogate `os.fsdecode` correctly put in the path.
    """
    _seed_repo(tmp_path, (b"seed.php",))
    (tmp_path / ".agents" / "policy").mkdir(parents=True)
    (tmp_path / os.fsdecode(b".agents/policy/bad_\xff_rule.md")).write_bytes(b"x" * 40_000)
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "oversized")

    proc = subprocess.run(
        [sys.executable, str(_BUDGET_TOOL), "--all", "--root", str(tmp_path)],
        capture_output=True,
        check=False,
        env={**scrubbed_git_env(drop_git_vars=True), "PYTHONIOENCODING": "utf-8:strict"},
    )
    stdout = proc.stdout.decode("utf-8", "backslashreplace")
    stderr = proc.stderr.decode("utf-8", "backslashreplace")

    assert "UnicodeEncodeError" not in stderr, f"the gate died reporting instead of reporting: {stderr}"
    assert "40000 bytes > budget" in stdout, (
        f"the over-budget file must be named in the report; stdout={stdout!r} stderr={stderr!r}"
    )
    assert proc.returncode == 1, f"an over-budget file must fail the gate; exit={proc.returncode} stdout={stdout!r}"
