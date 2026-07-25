"""``_require_hook_shim`` must fail, never skip, when the alias-rename hook is missing (#1658).

pfBlockerNG ships a required ``pre_write_config`` hook shim
(``tests/smoke/test_smoke_alias_rename.py::HOOK_SHIM``). The build CI runs
(``-devel``/``-nightly``) always package it -- its absence on a deployed build
is a packaging regression, not a reason to skip the whole alias-rename module
quietly. Pinned off-VM with the ``_FakeVM`` pattern (precedent:
``tests/test_smoke_unbound_ready.py``, ``tests/test_guest_file_contains.py``).
"""

from __future__ import annotations

import ast
import inspect
import re
from dataclasses import dataclass, field

import pytest

from tests.smoke import test_smoke_alias_rename as tsar


@dataclass
class _FakeResult:
    """Stand-in for ``subprocess.CompletedProcess[str]`` (the shape ``SmokeVM.ssh`` returns)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    """Fake ``vm.ssh(*remote, timeout=...)`` -- records calls, replays one scripted result."""

    result: _FakeResult
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        return self.result


def test_absent_hook_fails_not_skips() -> None:
    """rc 1 (clean ``test -f`` miss) -- the helper fails the run and names HOOK_SHIM."""
    vm = _FakeVM(result=_FakeResult(returncode=1))
    with pytest.raises(pytest.fail.Exception, match=re.escape(tsar.HOOK_SHIM)):
        tsar._require_hook_shim(vm)  # type: ignore[arg-type]


def test_present_hook_returns_normally() -> None:
    """rc 0 -- the helper returns; no failure, no skip."""
    vm = _FakeVM(result=_FakeResult(returncode=0))
    tsar._require_hook_shim(vm)  # type: ignore[arg-type]  # must not raise


def test_probe_transport_failure_fails_distinctly() -> None:
    """rc 255 (ssh transport fault, e.g. connection refused) is neither "present" nor the
    clean "absent" case -- it must still fail, with its own rc-bearing message, so a broken
    probe is never misread as a packaging regression."""
    vm = _FakeVM(result=_FakeResult(returncode=255, stderr="ssh: connect refused"))
    with pytest.raises(pytest.fail.Exception, match="rc=255"):
        tsar._require_hook_shim(vm)  # type: ignore[arg-type]


def test_the_only_skip_left_is_the_missing_package_one() -> None:
    """Row 4 regression guard: the module keeps exactly ONE ``pytest.skip`` call, the
    no-package-to-deploy fixture guard, and its message is that guard's.

    Read the AST rather than the source text, so a comment that merely mentions
    ``pytest.skip(`` cannot fail this and, more importantly, a deleted skip whose wording
    survives as a comment cannot satisfy it: the message has to sit INSIDE the one
    surviving call, not merely somewhere in the file.
    """
    calls = [
        node
        for node in ast.walk(ast.parse(inspect.getsource(tsar)))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "skip"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
    ]
    assert len(calls) == 1, f"exactly one pytest.skip call must remain, found {len(calls)}"
    reason = calls[0].args[0] if calls[0].args else None
    assert isinstance(reason, ast.Constant) and "SMOKE_PKG not set" in str(reason.value), (
        "the surviving skip must be the no-package-to-deploy guard"
    )
