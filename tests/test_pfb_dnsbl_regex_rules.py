"""pfb_dnsbl_regex_rules.py (issue #1765): single-source DNSBL regex admission
rules, shared by pfb_unbound.py and the save-time probe.

Covers what the PHP suite (tests/php/DnsblRegexEntryErrorTest.php, which drives
the probe through pfb_dnsbl_regex_validation_errors()) cannot reach directly:
standalone import-safety (the #1711 pythonmod-globals regression guard), the
probe's argv-absent default, and stdin line-ending edge cases. The five
diagnostic-message classes and the shape-vs-budget distinction are already
pinned in DnsblRegexEntryErrorTest -- not duplicated here.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng"
SCRIPT = PKG_DIR / "pfb_dnsbl_regex_rules.py"


def _anchored_pattern(length: int) -> str:
    """An anchored, structurally benign pattern of EXACTLY the requested length
    (mirror of DnsblRegexEntryErrorTest::anchoredPattern / test_adr07's twin)."""
    return "^" + "a" * (length - 2) + "$"


def run_probe(stdin_bytes: bytes, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin_bytes,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_import_is_standalone_with_no_pythonmod_globals() -> None:
    """issue #1711/#1765 regression guard: the module imports clean in a bare
    interpreter -- only the pkg dir on sys.path (cwd, mirroring Unbound's
    pythonmod chdir() + sys.path.append('.')), a stripped env, no unboundmodule
    stub. Fails the moment a pythonmod-injected name (log_info, RR_TYPE_*, ...)
    lands at module scope."""
    proc = subprocess.run(
        [sys.executable, "-c", "import pfb_dnsbl_regex_rules"],
        cwd=str(PKG_DIR),
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", "")},
        check=False,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == ""


def test_main_defaults_cap_off_when_argv_is_absent() -> None:
    """The nowdoc this module replaced used ``len(sys.argv) > 1 and sys.argv[1] ==
    "1"`` -- pin that the missing-argv case is cap OFF: a long-but-benign pattern
    is accepted with no argv[1] at all."""
    from pfb_dnsbl_regex_rules import REGEX_STATIC_LEN_CAP

    pattern = _anchored_pattern(REGEX_STATIC_LEN_CAP + 100)
    proc = run_probe((pattern + "\n").encode("utf-8"))
    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    assert proc.stderr == b""


def test_main_treats_crlf_terminated_lines_like_lf() -> None:
    """A regex-list body with CRLF line endings splits into the same lines (and
    reports the same line numbers) as an LF-only body."""
    body = b"^ads\x01$\r\n(a+)+\r\n^ok$\r\n"
    proc = run_probe(body)
    assert proc.returncode == 1
    stderr = proc.stderr.decode("utf-8")
    assert "line 1:" in stderr and "control character" in stderr
    assert "line 2:" in stderr and "catastrophic-backtracking shape" in stderr
    assert "line 3:" not in stderr


def test_main_does_not_hang_on_a_lone_cr_with_no_newline() -> None:
    """A regex-list body using bare CR (old-Mac style) line endings with no '\\n'
    anywhere is NOT split by ``sys.stdin`` (unlike CRLF, which still carries a
    real '\\n' for the line-terminator search) -- Python's text stdin only treats
    '\\n' as a line boundary here, so the whole blob is read as ONE line. Pin
    the safe outcome: no hang, and the embedded control byte (CR itself is
    0x0D, an ASCII control character) still trips the control-character
    diagnostic on that one line -- never a crash, never a silent pass."""
    body = b"^ads\x01$\r(a+)+\r^ok$\r"
    proc = run_probe(body)
    assert proc.returncode == 1
    stderr = proc.stderr.decode("utf-8")
    assert stderr.startswith("line 1:")
    assert stderr.count("line ") == 1, f"expected the whole blob read as one line, got: {stderr!r}"
    assert "control character" in stderr
