"""Tests for scripts/check_appliance_python.py.

Per CLAUDE.md's test-coverage rule, every flagged case is paired with the correct
form that must stay clean, so a green proves the check DISCRIMINATES (the appliance
interpreter path is rejected) rather than always firing or never firing.

The bad path is assembled at runtime ("/usr/local/bin/" + "python...") so this test
file does not match its own check when the check scans ``tests/``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_appliance_python.py"
_spec = importlib.util.spec_from_file_location("check_appliance_python", _TOOL)
assert _spec is not None and _spec.loader is not None
cap = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cap
_spec.loader.exec_module(cap)

# The forbidden appliance interpreter path, assembled so it is not a literal substring here.
_APPLIANCE_PY = "/usr/local/bin/" + "python3"


def _find(tmp_path: Path, content: str) -> list[Any]:
    f = tmp_path / "sample.py"
    f.write_text(content, encoding="utf-8")
    return cap.find_violations([f])


def test_flags_appliance_python_minus_c(tmp_path: Path) -> None:
    # A smoke test shelling a Python snippet to the pfSense VM is the footgun.
    line = f'    vm.ssh(f"{_APPLIANCE_PY} -c {{snippet}}")\n'
    violations = _find(tmp_path, line)
    assert len(violations) == 1, f"expected the appliance python path to be flagged; got {violations}"
    assert violations[0][1] == 1


def test_flags_any_suffix(tmp_path: Path) -> None:
    # python / python3 / python3.11 under the appliance bindir are all the same footgun.
    for suffix in ("python", "python3", "python3.11"):
        line = f'    vm.ssh("/usr/local/bin/{suffix} /tmp/x.py")\n'
        assert _find(tmp_path, line), f"/usr/local/bin/{suffix} should be flagged"


def test_clean_php_is_not_flagged(tmp_path: Path) -> None:
    # The correct form: drive the box via PHP / the package's own ledger API.
    clean = (
        "    snippet = \"require_once('...extra.inc');pfb_due_ledger_write_entry(...);\"\n"
        "    result = h.php_eval(vm, snippet)\n"
    )
    assert _find(tmp_path, clean) == [], "PHP via php_eval must stay clean"


def test_bare_python3_is_not_flagged(tmp_path: Path) -> None:
    # Bare `python3` names the dev-host / client-VM interpreter (e.g. the civm tcp probe,
    # or scripts/ bench tooling on the dev box) — out of scope, must NOT be flagged.
    bare = '    client_vm.ssh("python3 /tmp/tcp_rst_probe.py 2.0")\n'
    assert _find(tmp_path, bare) == [], "bare python3 (dev/client) must not be flagged"


def test_unbound_embedded_loader_not_flagged(tmp_path: Path) -> None:
    # pfb_unbound.py runs in Unbound's embedded loader (python-script:), not spawned via
    # the appliance python path — so referencing the module file is fine.
    loader = '    conf = "python-script: /usr/local/pkg/pfblockerng/pfb_unbound.py"\n'
    assert _find(tmp_path, loader) == [], "the embedded-loader module path must not be flagged"


def test_main_exit_codes(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(f'vm.ssh("{_APPLIANCE_PY} -c x")\n', encoding="utf-8")
    good = tmp_path / "good.py"
    good.write_text('h.php_eval(vm, "echo 1;")\n', encoding="utf-8")
    assert cap.main([str(good)]) == 0
    assert cap.main([str(bad)]) == 1
