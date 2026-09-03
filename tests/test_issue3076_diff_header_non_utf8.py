"""Issue #3076: a non-UTF-8 filename must not skip the diff-header gates.

``_git_paths.unified_diff`` used to pin ``core.quotePath=false``, so git emitted a
high-bit byte in the ``+++ b/<path>`` header raw. The diff is decoded with
``errors="replace"`` (deliberately -- it is file CONTENT, only matched and
printed, and a byte-exact decode would put lone surrogates into every
violation line), which turned that raw byte into U+FFFD. ``check_version_literals``
then ran ``git show :<mangled path>``, which cannot resolve, and silently
skipped the file (clean pass over content it never scanned).
``check_comment_narration`` scans the diff body directly and never opens the
path, so it still flagged the violation -- only the printed path was wrong.

Both consumers route through the same ``_git_paths.unified_diff`` /
``diff_header_name`` pair, so the fix lives once, in ``_git_paths.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
VLIT = ROOT / "scripts" / "check_version_literals.py"
NARR = ROOT / "scripts" / "check_comment_narration.py"

# Concatenated so this file's own source is not itself a version-literal hit.
_PHP83 = "php8" + "3"
_LITERAL_LINE = f'$v = "{_PHP83}";'
_NARRATION_LINE = "// wired in Phase 4"

# A raw 0xFF is not valid UTF-8 in any position -- the shortest name that
# distinguishes a byte-exact recovery from a lossy one.
_BAD_NAME = os.fsdecode(b"src/bad_\xff.php")


def _git(repo: Path, *args: str) -> None:
    # scrubbed_git_env: a scratch repo must not inherit commit.gpgsign or a real
    # core.hooksPath from the developer's config (issue #1967), nor be redirected
    # at the real repo by an inherited GIT_DIR when the suite runs under a hook.
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env=scrubbed_git_env(drop_git_vars=True),
    )


def _scratch(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "devel")
    (repo / "src").mkdir()
    (repo / "src" / "seed.php").write_text("<?php\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "seed")
    return repo


def _run(script: Path, repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    # scrubbed_git_env: the invoked checker shells out to `git diff`/`git show`
    # itself, so it needs the same hook-safety scrub `_git()` gets -- an
    # inherited GIT_DIR would point it at the REAL repository, not `repo`.
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=repo,
        capture_output=True,
        env=scrubbed_git_env(drop_git_vars=True),
        check=False,
    )


def test_version_literals_reports_ascii_and_non_utf8_names_identically(tmp_path: Path) -> None:
    """Same violating content staged under an ASCII and a non-UTF-8 name -- both must be caught."""
    repo = _scratch(tmp_path)
    (repo / "src" / "plain.php").write_text(_LITERAL_LINE + "\n", encoding="utf-8")
    (repo / _BAD_NAME).write_bytes((_LITERAL_LINE + "\n").encode())
    _git(repo, "add", "-A")
    res = _run(VLIT, repo, "--staged")
    assert res.returncode == 1, res.stderr
    assert res.stderr.count(_LITERAL_LINE.encode()) == 2, res.stderr
    assert b"bad_" in res.stderr, f"non-UTF-8-named file's violation missing: {res.stderr!r}"
    assert b"\xef\xbf\xbd" not in res.stderr, f"U+FFFD replacement char leaked: {res.stderr!r}"


def test_version_literals_does_not_clean_pass_when_only_the_bad_name_violates(tmp_path: Path) -> None:
    """The exact issue #3076 reproduction: violation ONLY in the non-UTF-8-named file."""
    repo = _scratch(tmp_path)
    (repo / "src" / "plain.php").write_text("<?php\n// benign\n", encoding="utf-8")
    (repo / _BAD_NAME).write_bytes((_LITERAL_LINE + "\n").encode())
    _git(repo, "add", "-A")
    res = _run(VLIT, repo, "--staged")
    assert res.returncode == 1, f"clean pass over unscanned non-UTF-8-named content: {res.stderr!r}"
    assert _LITERAL_LINE.encode() in res.stderr, res.stderr


def test_comment_narration_reports_the_real_non_utf8_path(tmp_path: Path) -> None:
    """The reported path must be the real recovered name, not a U+FFFD-mangled one.

    stderr's ``backslashreplace`` error handler renders the unrepresentable
    byte as literal ``\\udcff`` text -- unlike U+FFFD, that rendering is
    bijective with the source byte (0xFF), so the real name is recoverable
    from the report; a mangled U+FFFD name is not.
    """
    repo = _scratch(tmp_path)
    (repo / _BAD_NAME).write_bytes((_NARRATION_LINE + "\n").encode())
    _git(repo, "add", "-A")
    res = _run(NARR, repo, "--staged")
    assert res.returncode == 1, res.stderr
    assert b"bad_\\udcff.php" in res.stderr, f"expected the real byte-exact name, got: {res.stderr!r}"
    assert b"\xef\xbf\xbd" not in res.stderr, f"U+FFFD replacement char leaked: {res.stderr!r}"


def test_user_quotepath_false_cannot_skip_the_non_utf8_file(tmp_path: Path) -> None:
    """A repo-local ``core.quotePath=false`` must not defeat the pin (module's own threat model)."""
    repo = _scratch(tmp_path)
    _git(repo, "config", "core.quotePath", "false")
    (repo / _BAD_NAME).write_bytes((_LITERAL_LINE + "\n").encode())
    _git(repo, "add", "-A")
    res = _run(VLIT, repo, "--staged")
    assert res.returncode == 1, f"user config bypassed the gate: {res.stderr!r}"
    assert _LITERAL_LINE.encode() in res.stderr, res.stderr


def test_valid_utf8_name_opens_under_an_ascii_filesystem_encoding(tmp_path: Path) -> None:
    """The header-recovered path follows the FILESYSTEM's encoding, not hard-coded UTF-8.

    Given a staged ``café.php`` (valid UTF-8, non-ASCII -- and, under the new
    ``core.quotePath=true`` pin, C-quoted in the header just like the invalid
    byte above) and an interpreter whose filesystem encoding is ASCII
    (``LC_ALL=C``, UTF-8 mode off -- a git hook's environment), ``git show
    <ref>:<path>`` needs the SAME encoding ``subprocess`` uses to build its
    argv. A hard-coded UTF-8 decode holds U+00E9, which does not `fsencode`
    back onto an ASCII filesystem and crashes the gate outright; recovered with
    ``os.fsdecode`` it holds the two escaped bytes git actually emitted and
    round-trips.
    """
    repo = _scratch(tmp_path)
    (repo / "src" / "café.php").write_bytes((_LITERAL_LINE + "\n").encode())
    _git(repo, "add", "-A")
    env = {
        **scrubbed_git_env(drop_git_vars=True),
        # PEP 540 would otherwise force UTF-8 mode for the C locale and hide
        # the difference this case exists to catch.
        "PYTHONUTF8": "0",
        "PYTHONCOERCECLOCALE": "0",
        "LC_ALL": "C",
        "LANG": "C",
    }
    res = subprocess.run([sys.executable, str(VLIT), "--staged"], cwd=repo, capture_output=True, env=env, check=False)
    assert b"Traceback" not in res.stderr, f"gate crashed instead of reporting: {res.stderr!r}"
    assert res.returncode == 1, res.stderr
    assert _LITERAL_LINE.encode() in res.stderr, res.stderr
