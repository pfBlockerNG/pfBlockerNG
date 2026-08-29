"""The published install one-liner must fail when fetch fails (issue #2754).

A POSIX pipeline's status is the last command. ``fetch | sh`` therefore exits 0
when fetch delivers zero bytes — ``sh`` on empty stdin is a success. Measured
on FreeBSD /bin/sh on a live pfSense clone: NXDOMAIN, HTTPS timeout, and
``sh </dev/null`` all returned 0 and left the package unchanged.

The documented form is mktemp + fetch-to-file + non-empty gate + ``sh``, then
cleanup that preserves the fetch/sh status, so an empty or failed fetch cannot
report success.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
README = ROOT / "README.md"

# Exact published recipe (README uses the public host; usage() templates it).
_FETCH_TO_FILE = (
    't=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && '
    'fetch -T 60 -o "$t" https://pkg.pfblockerng.com/install.sh && '
    '[ -s "$t" ] && '
    '/bin/sh "$t" --channel'
)
_STATUS_CLEANUP = '; e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)'
_PIPE_FORM = "fetch -qo - https://pkg.pfblockerng.com/install.sh | sh -s -- --channel"
# usage() prints the recipe via a single-quoted printf so set -u cannot
# expand $t. Pin that format string, not an unquoted heredoc body.
_USAGE_PRINTF = (
    'printf \'  t=$(mktemp "${TMPDIR:-/tmp}/pfb-install.XXXXXX") && '
    'fetch -T 60 -o "$t" https://%s/install.sh && '
    '[ -s "$t" ] && '
    '/bin/sh "$t" --channel <stable|testing|edge|nightly>; '
    'e=$?; [ -n "$t" ] && rm -f "$t"; (exit $e)\\n\' '
    '"${PFB_REPO_HOST}"'
)


def _recipe(channel: str) -> str:
    return f"{_FETCH_TO_FILE} {channel}{_STATUS_CLEANUP}"


def _readme_sh_fence(channel: str) -> str:
    """Return the README ``sh`` fence that installs ``channel``.

    The executable pins run THIS text, not a parallel copy of the recipe, so a
    documented pipe form cannot stay green behind a hardcoded fetch-to-file stub.
    """
    text = README.read_text(encoding="utf-8")
    fences: list[str] = []
    rest = text
    while "```sh" in rest:
        rest = rest.split("```sh", 1)[1]
        block, rest = rest.split("```", 1)
        fences.append(block.strip())
    matches = [block for block in fences if f"--channel {channel}" in block]
    assert matches, f"no README sh fence for --channel {channel}"
    return matches[0]


def _run_recipe(
    tmp_path: Path,
    *,
    body: bytes,
    fetch_rc: int,
    channel: str = "stable",
) -> subprocess.CompletedProcess[str]:
    """Execute the README recipe with a stub ``fetch`` on PATH."""
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
        ["dash", "-c", _readme_sh_fence(channel)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_readme_install_recipes_are_fetch_to_file_not_a_pipe() -> None:
    """Given the README install recipes
    When a reader copies them onto a firewall
    Then they gate on fetch's exit and a non-empty body, not on sh reading empty stdin.
    """
    text = README.read_text(encoding="utf-8")
    assert _PIPE_FORM not in text
    assert _recipe("stable") in text
    assert _recipe("edge") in text


def test_install_sh_usage_documents_fetch_to_file_not_a_pipe() -> None:
    """Given install.sh usage()
    When an operator reads the published one-liner
    Then it is mktemp + fetch-to-file + a non-empty gate, not the fail-open pipe.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    fn = text.split("usage() {", 1)[1].split("pfb_emit_embedded_hook", 1)[0]
    assert "fetch -qo - https://" not in fn
    assert " | sh -s -- --channel" not in fn
    assert _USAGE_PRINTF in fn


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


def test_help_prints_usage_without_running_the_documented_mktemp(tmp_path: Path) -> None:
    """The documented one-liner is printed via single-quoted printf.
    An unquoted heredoc body dies under ``set -u`` and would create a temp file.
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
    assert "https://pkg.pfblockerng.com/install.sh" in proc.stdout
    assert leftovers == [], leftovers
