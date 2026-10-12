"""Published install commands: the landing page's pipe, plus a fail-closed variant.

Interactive installs use the pipe from pkg.pfblockerng.com (issue #3470). A POSIX
pipeline's status is the last command, so ``fetch | sh`` exits 0 when fetch delivers
zero bytes (issue #2754); an operator still sees fetch's error and no ``==> Done``.

Unattended callers need the exit status, so the README and ``install.sh --help``
also document mktemp + fetch-to-file + non-empty gate + ``sh``, then cleanup that
preserves the fetch/sh status, so an empty or failed fetch cannot report success.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
README = ROOT / "README.md"

# Exact published commands (README uses the public host; usage() templates it).
_FETCH_TO_FILE = (
    't=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && '
    'fetch -T 60 -o "$t" https://pkg.pfblockerng.com/install.sh && '
    '[ -s "$t" ] && '
    '/bin/sh "$t" --channel'
)
_STATUS_CLEANUP = '; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)'
_PIPE_FORM = "fetch -qo - https://pkg.pfblockerng.com/install.sh | sh -s -- --channel"
_ANY_CHANNEL = "<stable|testing|edge|nightly>"


def _recipe(channel: str) -> str:
    return f"{_FETCH_TO_FILE} {channel}{_STATUS_CLEANUP}"


def _readme_sh_fences() -> list[str]:
    rest = README.read_text(encoding="utf-8")
    fences: list[str] = []
    while "```sh" in rest:
        rest = rest.split("```sh", 1)[1]
        block, rest = rest.split("```", 1)
        fences.append(block.strip())
    return fences


def _readme_automation_fence() -> str:
    """Return the README's fetch-to-file fence.

    The executable pins run THIS text, not a parallel copy of the recipe, so a
    broken documented variant cannot stay green behind a hardcoded stub.
    """
    matches = [block for block in _readme_sh_fences() if block.startswith("t=$(mktemp ")]
    assert len(matches) == 1, matches
    return matches[0]


def _run_recipe(
    tmp_path: Path,
    *,
    body: bytes,
    fetch_rc: int,
) -> subprocess.CompletedProcess[str]:
    """Execute the README automation recipe with a stub ``fetch`` on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    body_file = tmp_path / "fetch-body"
    body_file.write_bytes(body)
    fetch = bindir / "fetch"
    # Handles both the leftover pipe (`fetch -qo - URL`) and fetch-to-file (`-o FILE`).
    fetch.write_text(
        "#!/bin/sh\n"
        "out=\n"
        "while [ $# -gt 0 ]; do\n"
        "  case $1 in\n"
        "    -o|-qo) out=$2; shift 2 ;;\n"
        "    -T) shift 2 ;;\n"
        "    -q) shift ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        f"rc={fetch_rc}\n"
        'if [ "$rc" -ne 0 ]; then\n'
        '  exit "$rc"\n'
        "fi\n"
        'if [ -z "$out" ] || [ "$out" = \'-\' ]; then\n'
        f'  cat "{body_file}"\n'
        "else\n"
        f'  cat "{body_file}" > "$out"\n'
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fetch.chmod(fetch.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    env["TMPDIR"] = str(tmp_path)
    return subprocess.run(
        ["dash", "-c", _readme_automation_fence()],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_readme_install_fences_are_the_landing_page_pipe() -> None:
    """Given the README install and channel-switch fences
    When a reader compares them with pkg.pfblockerng.com
    Then each is exactly the landing page's piped one-liner.
    """
    fences = _readme_sh_fences()
    assert f"{_PIPE_FORM} stable" in fences
    assert f"{_PIPE_FORM} edge" in fences


def test_readme_documents_the_fail_closed_automation_recipe() -> None:
    """Given the README
    When an unattended caller needs a meaningful exit status
    Then the fetch-to-file recipe is documented as its own fence.
    """
    assert _readme_automation_fence() == _recipe("stable")


def test_published_form_fails_closed_on_empty_fetch_body(tmp_path: Path) -> None:
    """Given a stub fetch that writes zero bytes and exits 0
    When the published one-liner runs
    Then the overall status is non-zero — empty body is not a successful install.
    """
    result = _run_recipe(tmp_path, body=b"", fetch_rc=0)
    assert result.returncode != 0, result.stderr


def test_published_form_fails_closed_when_fetch_fails(tmp_path: Path) -> None:
    """Given a stub fetch that exits non-zero
    When the published one-liner runs
    Then the overall status is non-zero and sh is not invoked on an empty file.
    """
    result = _run_recipe(tmp_path, body=b"exit 0\n", fetch_rc=1)
    assert result.returncode != 0, result.stderr


def test_published_form_runs_sh_on_nonempty_body(tmp_path: Path) -> None:
    """Given a stub fetch that writes a script exiting 42
    When the published one-liner runs
    Then that script is executed — the form still reaches sh on a real body.
    """
    result = _run_recipe(tmp_path, body=b"exit 42\n", fetch_rc=0)
    assert result.returncode == 42, result.stderr


def test_help_prints_both_published_forms_without_running_mktemp(tmp_path: Path) -> None:
    """Given ``install.sh --help``
    When an operator reads the published commands
    Then it prints the landing page's pipe and the literal fail-closed recipe;
    an expanded ``$(mktemp ...)`` would differ and leave a temp file behind.
    """
    env = os.environ.copy()
    env["TMPDIR"] = str(tmp_path)
    proc = subprocess.run(
        ["sh", str(INSTALL_SH), "--help"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("pfb-install"))
    assert proc.returncode == 0, proc.stderr
    assert "Usage:" in proc.stdout
    assert f"  {_PIPE_FORM} {_ANY_CHANNEL}\n" in proc.stdout
    assert f"  {_recipe(_ANY_CHANNEL)}\n" in proc.stdout
    assert leftovers == [], leftovers
