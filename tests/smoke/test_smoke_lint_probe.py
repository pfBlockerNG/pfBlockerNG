"""Pins the appliance-side diagnostic contracts the #1732 lint endpoint parses.

The server-side syntax-lint endpoint (issue #1732) shells out to the box's real
interpreters and parses their stderr into line-mapped CodeMirror diagnostics:

* ``/bin/sh -n /dev/stdin`` for shell hook scripts — content on stdin, never
  executed, never written to disk.  The ``/dev/stdin`` operand is load-bearing:
  FreeBSD sh prints NO line number at all when parsing bare stdin
  (``/bin/sh: Syntax error: <detail>``), but names the operand and the line
  when given a file path — and ``/dev/stdin`` is enough to trigger the
  file-shaped, line-numbered format (``/dev/stdin: <line>: Syntax error:
  <detail>``) while the content still arrives down the pipe.  (Linux dash,
  the ash sibling, line-numbers bare stdin too — FreeBSD does not.)
* ``compile(sys.stdin.read(), '<hook>', 'exec')`` under the package Python for
  Python hook scripts — the probe script prints its OWN ``line N: msg`` format,
  so only ``SyntaxError.lineno``/``.msg`` semantics are pinned here, not any
  traceback shape.

This test keeps those live-probed formats pinned on the real smoke image: if a
pfSense/FreeBSD update ever changes them under the endpoint's parser, this
fails loudly on the appliance instead of the lint gutter silently degrading to
file-level diagnostics.

``_SH_DIAG_RE`` mirrors the PHP-side extraction regex in
``pfb_lint_parse_sh_stderr()`` (pfblockerng_extra.inc) — keep the two in sync.
"""

from __future__ import annotations

import re
import shlex
import subprocess

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

# Mirrors the PHP parser's per-line extraction (pfb_lint_parse_sh_stderr):
# "/dev/stdin: <line>: Syntax error: <detail>" — operand name free-form, the
# line number and the literal "Syntax error:" marker are the load-bearing parts.
_SH_DIAG_RE = re.compile(r"(\d+): Syntax error: (.+)$")

# The exact stdin-fed compile probe the endpoint ships for lang=py (keep in
# sync with pfb_lint_py_diagnostics() in pfblockerng_extra.inc).
_PY_PROBE = (
    "import sys\n"
    "try:\n"
    "    compile(sys.stdin.read(), '<hook>', 'exec')\n"
    "except SyntaxError as error:\n"
    "    print('line {}: {}'.format(error.lineno or 1, error.msg), file=sys.stderr)\n"
    "    raise SystemExit(1)\n"
    "raise SystemExit(0)\n"
)


def _stdin_probe(vm: SmokeVM, command: str, content: str) -> subprocess.CompletedProcess[str]:
    """Feed ``content`` on stdin to ``command`` on the guest; echo the rc."""
    quoted = shlex.quote(content)
    return vm.ssh(f"printf %s {quoted} | {command}; echo rc=$?", timeout=30)


def _rc_of(result: subprocess.CompletedProcess[str]) -> int:
    match = re.search(r"rc=(\d+)", result.stdout)
    assert match, f"no rc marker in stdout: {result.stdout!r} stderr={result.stderr!r}"
    return int(match.group(1))


def test_sh_n_valid_script_is_silent_and_zero(smoke_vm: SmokeVM) -> None:
    result = _stdin_probe(smoke_vm, "/bin/sh -n /dev/stdin", "echo ok\n")
    assert _rc_of(result) == 0, f"sh -n rejected a valid script: stderr={result.stderr!r}"
    assert result.stderr.strip() == "", f"sh -n emitted noise on a valid script: {result.stderr!r}"


@pytest.mark.parametrize(
    ("content", "expected_line"),
    [
        # EOF-unexpected: the diagnostic points at the EOF line (2), not the if line.
        pytest.param("if true; then\n", 2, id="unterminated-if"),
        # FreeBSD sh reports the OPENING line for an unterminated quote (dash
        # reports the EOF line) — exactly why this pin exists.
        pytest.param('echo "unterminated\n', 1, id="unterminated-quote"),
        pytest.param("do\n", 1, id="stray-keyword"),
        # Error mid-file: line numbers must track the real source line, not reset.
        pytest.param("echo one\necho two\ndo\n", 3, id="line-number-tracks-source"),
    ],
)
def test_sh_n_syntax_error_format_is_line_mapped(smoke_vm: SmokeVM, content: str, expected_line: int) -> None:
    result = _stdin_probe(smoke_vm, "/bin/sh -n /dev/stdin", content)
    assert _rc_of(result) != 0, f"sh -n accepted a broken script: {content!r}"
    match = _SH_DIAG_RE.search(result.stderr)
    assert match, (
        "sh -n stderr did not match the endpoint's extraction regex "
        f"{_SH_DIAG_RE.pattern!r} — raw stderr: {result.stderr!r}"
    )
    assert int(match.group(1)) == expected_line, (
        f"sh -n reported line {match.group(1)}, expected {expected_line}; raw stderr: {result.stderr!r}"
    )


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> SmokeVM:
    """The smoke VM WITH the branch package installed.

    The session ``smoke_vm`` fixture only boots the deps-baked image —
    ``pfblockerng.inc`` (and the package dependency the python resolver reads)
    exists only after ``helpers.deploy()``. The sh rows need no package, so
    only the python-probe rows depend on this.
    """
    h.deploy(smoke_vm)
    return smoke_vm


_PY_PATH_OPEN = "<<<PFBPY>>>"
_PY_PATH_CLOSE = "<<<PFBPYEND>>>"


def _validated_python_paths(payload: str, out: str) -> tuple[str, str]:
    fields = payload.split("\n")
    assert len(fields) == 2, f"expected interpreter and wrapper paths: stdout={out!r}"
    resolved, wrapper = fields
    assert resolved, f"pfb_python_interpreter() returned an empty path: stdout={out!r}"
    assert wrapper, f"PFB_PYTHON_WRAPPER was empty: stdout={out!r}"
    return resolved, wrapper


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        pytest.param("\n/wrapper", "pfb_python_interpreter() returned an empty path", id="empty-interpreter"),
        pytest.param("/interpreter\n", "PFB_PYTHON_WRAPPER was empty", id="empty-wrapper"),
        pytest.param("/interpreter", "expected interpreter and wrapper paths", id="missing-wrapper"),
        pytest.param("/interpreter\n/wrapper\nextra", "expected interpreter and wrapper paths", id="extra-field"),
    ],
)
def test_python_path_fields_name_invalid_output(payload: str, message: str) -> None:
    with pytest.raises(AssertionError, match=re.escape(message)):
        _validated_python_paths(payload, f"{_PY_PATH_OPEN}{payload}{_PY_PATH_CLOSE}")


def _guest_python(vm: SmokeVM) -> str:
    """The package Python wrapper on the guest, cross-checked with PHP.

    ``pfb_python_interpreter()`` is the PHP readiness resolver; the wrapper is
    the SAME launcher the lint endpoint uses. Runs through
    ``helpers.php_eval`` (pfSsh.php, the fully-bootstrapped pfSense shell): a
    bare ``php -r`` require of ``pfblockerng.inc`` dies in pfSense's own error
    handler with exit 0, so the path is delimited the same way
    ``helpers.config_get`` delimits values past the pfSsh banner.
    """
    snippet = (
        'require_once("/usr/local/pkg/pfblockerng/pfblockerng.inc"); '
        f'echo "{_PY_PATH_OPEN}" . pfb_python_interpreter() . "\\n" . PFB_PYTHON_WRAPPER . "{_PY_PATH_CLOSE}";'
    )
    result = h.php_eval(vm, snippet, timeout=120)
    out = result.stdout
    start = out.find(_PY_PATH_OPEN)
    end = out.find(_PY_PATH_CLOSE)
    assert result.returncode == 0 and start != -1 and end != -1, (
        f"pfb_python_interpreter() resolution failed: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}"
    )
    resolved, wrapper = _validated_python_paths(out[start + len(_PY_PATH_OPEN) : end], out)
    wrapper_result = vm.ssh(
        f"printf %s {_PY_PATH_OPEN!r}; {shlex.quote(wrapper)} --print-interpreter; printf %s {_PY_PATH_CLOSE!r}",
        timeout=120,
    )
    wrapped_out = wrapper_result.stdout
    wrapped_start = wrapped_out.find(_PY_PATH_OPEN)
    wrapped_end = wrapped_out.find(_PY_PATH_CLOSE)
    assert wrapper_result.returncode == 0 and wrapped_start != -1 and wrapped_end != -1, (
        f"pfb_python.sh --print-interpreter failed: rc={wrapper_result.returncode} "
        f"stdout={wrapped_out!r} stderr={wrapper_result.stderr!r}"
    )
    wrapped = wrapped_out[wrapped_start + len(_PY_PATH_OPEN) : wrapped_end].strip()
    assert wrapped == resolved, f"PHP resolver {resolved!r} differs from wrapper {wrapped!r}"
    return wrapper


def test_py_compile_probe_valid_script_is_silent_and_zero(deployed_vm: SmokeVM) -> None:
    python = _guest_python(deployed_vm)
    result = _stdin_probe(deployed_vm, f"{python} -c {shlex.quote(_PY_PROBE)}", "print('ok')\n")
    assert _rc_of(result) == 0, f"compile probe rejected valid code: stderr={result.stderr!r}"
    assert result.stderr.strip() == "", f"compile probe emitted noise: {result.stderr!r}"


@pytest.mark.parametrize(
    ("content", "expected_line"),
    [
        pytest.param("def f(:\n", 1, id="first-line"),
        pytest.param("x = 1\ndef f(:\n", 2, id="line-number-tracks-source"),
    ],
)
def test_py_compile_probe_reports_lineno_and_msg(deployed_vm: SmokeVM, content: str, expected_line: int) -> None:
    python = _guest_python(deployed_vm)
    result = _stdin_probe(deployed_vm, f"{python} -c {shlex.quote(_PY_PROBE)}", content)
    assert _rc_of(result) == 1, (
        f"compile probe rc != 1 on a syntax error: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    match = re.search(r"^line (\d+): (.+)$", result.stderr.strip(), re.MULTILINE)
    assert match, f"compile probe stderr not in 'line N: msg' form: {result.stderr!r}"
    assert int(match.group(1)) == expected_line, f"raw stderr: {result.stderr!r}"
    assert match.group(2).strip(), "SyntaxError.msg was empty"
