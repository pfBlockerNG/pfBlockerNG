"""Tests for scripts/check_appliance_python.py.

Per AGENTS.md's test-coverage rule, every flagged case is paired with the correct
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

import pytest

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "check_appliance_python.py"
_spec = importlib.util.spec_from_file_location("check_appliance_python", _TOOL)
assert _spec is not None and _spec.loader is not None
cap = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cap
_spec.loader.exec_module(cap)

# The forbidden appliance interpreter path, assembled so it is not a literal substring here.
_APPLIANCE_PY = "/usr/local/bin/" + "python3"


def _find(tmp_path: Path, content: str, relative_path: str = "sample.py") -> list[Any]:
    f = tmp_path / relative_path
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return cap.find_violations([f])


def test_flags_appliance_python_minus_c(tmp_path: Path) -> None:
    # A smoke test shelling a Python snippet to the pfSense VM is the footgun.
    line = f'    vm.ssh(f"{_APPLIANCE_PY} -c {{snippet}}")\n'
    violations = _find(tmp_path, line)
    assert len(violations) == 1, f"expected the appliance python path to be flagged; got {violations}"
    assert violations[0][1] == 1


def test_flags_any_literal_interpreter_path(tmp_path: Path) -> None:
    for suffix in ("python", "python3", "python3.11", "python311", "python3x"):
        line = f'    vm.ssh("/usr/local/bin/{suffix} /tmp/x.py")\n'
        assert _find(tmp_path, line), f"/usr/local/bin/{suffix} should be flagged"


def test_dependency_derived_interpreter_construction_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    prefix = "/usr/local/bin/" + "python"
    line = f"    $interpreter = '{prefix}' . $version; // appliance-python-ok: dependency-derived\n"
    relative_path = "src/usr/local/pkg/pfblockerng/pfblockerng.inc"
    assert _find(tmp_path, line, relative_path), "only the shell wrapper may construct the interpreter path"


def test_resolver_path_with_dot_segments_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    prefix = "/usr/local/bin/" + "python"
    line = f"    $interpreter = '{prefix}' . $version; // appliance-python-ok: dependency-derived\n"
    real = tmp_path / "src/usr/local/pkg/pfblockerng/pfblockerng.inc"
    real.parent.mkdir(parents=True, exist_ok=True)
    real.write_text(line, encoding="utf-8")
    # "other" must exist so the OS can traverse the literal path.
    (tmp_path / "src/usr/local/pkg/other").mkdir(parents=True, exist_ok=True)
    non_normalized = tmp_path / "src/usr/local/pkg/other/../pfblockerng/./pfblockerng.inc"
    assert cap.find_violations([non_normalized]), "the PHP resolver has no construction exemption"


def test_annotation_does_not_allow_literal_interpreter(tmp_path: Path) -> None:
    line = f'    exec("{_APPLIANCE_PY}.11 /tmp/x.py"); // appliance-python-ok: dependency-derived\n'
    assert _find(tmp_path, line), "annotation must not permit a literal interpreter invocation"


def test_nested_copy_of_resolver_path_is_not_exempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A file whose path merely ENDS WITH the resolver's path string must NOT inherit the
    # exemption. _REPO_ROOT is anchored at tmp_path so the nested copy sits INSIDE the
    # anchored root: without that, any path under tmp_path is outside the real root and
    # the assertion would hold for a reason unrelated to nesting.
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    prefix = "/usr/local/bin/" + "python"
    line = f"    $interpreter = '{prefix}' . $version; // appliance-python-ok: dependency-derived\n"
    relative_path = "nested/src/usr/local/pkg/pfblockerng/pfblockerng.inc"
    assert _find(tmp_path, line, relative_path), "a path merely ending with the resolver path must not be exempt"


def test_derived_construction_is_forbidden_outside_resolver_file(tmp_path: Path) -> None:
    prefix = "/usr/local/bin/" + "python"
    line = f"    $interpreter = '{prefix}' . $version; // appliance-python-ok: dependency-derived\n"
    assert _find(tmp_path, line), "dependency-derived construction must be confined to the resolver file"


def test_resolver_path_used_as_a_directory_component_is_not_exempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A path that merely CONTAINS the resolver path (as a directory, with another
    # file inside it) is not the resolver file itself and must still be flagged.
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    prefix = "/usr/local/bin/" + "python"
    line = f"    $interpreter = '{prefix}' . $version; // appliance-python-ok: dependency-derived\n"
    relative_path = "src/usr/local/pkg/pfblockerng/pfblockerng.inc/other.inc"
    assert _find(tmp_path, line, relative_path), "resolver path used as a directory component must not be exempt"


def test_other_line_in_real_resolver_file_is_still_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The resolver file's exemption covers only the exact derived-construction line;
    # any other forbidden-literal line in that same file is still a violation.
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    line = f'    vm.ssh(f"{_APPLIANCE_PY} -c {{snippet}}")\n'
    relative_path = "src/usr/local/pkg/pfblockerng/pfblockerng.inc"
    assert _find(tmp_path, line, relative_path), "a non-exempt line in the resolver file must still be flagged"


def test_clean_php_is_not_flagged(tmp_path: Path) -> None:
    # The correct form: drive the box via PHP / the package's own ledger API.
    clean = (
        "    snippet = \"require_once('...extra.inc');pfb_due_ledger_write_entry(...);\"\n"
        "    result = h.php_eval(vm, snippet)\n"
    )
    assert _find(tmp_path, clean) == [], "PHP via php_eval must stay clean"


def test_bare_python3_client_vm_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Bare `python3` names the dev-host / client-VM interpreter (e.g. the civm tcp probe,
    # or scripts/ bench tooling on the dev box) — out of scope, must NOT be flagged.
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    bare = '    client_vm.ssh("python3 /tmp/tcp_rst_probe.py 2.0")\n'
    assert _find(tmp_path, bare, "tests/smoke/probe.py") == [], "client-VM python3 must not be flagged"


@pytest.mark.parametrize(
    "command",
    [
        '    vm.ssh("python3 -c x")\n',
        '    smoke_vm.ssh("python3.11 -c x")\n',
        '    vm.ssh("python3 -c x")  # unlike client_vm\n',
    ],
)
def test_bare_python_guest_ssh_in_smoke_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    violations = _find(tmp_path, command, "tests/smoke/probe.py")
    assert len(violations) == 1, f"pfSense guest Python command must be flagged; got {violations}"


def test_bare_python_dev_host_command_in_smoke_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cap, "_REPO_ROOT", tmp_path.resolve())
    command = '    subprocess.run(["python3", "tool.py"], check=True)\n'
    assert _find(tmp_path, command, "tests/smoke/probe.py") == []


def test_bare_python3_source_command_is_flagged(tmp_path: Path) -> None:
    source = '    subprocess.run(["python3", "-c", snippet], check=True)\n'
    violations = _find(tmp_path, source)
    assert len(violations) == 1, f"bare appliance python3 source command must be flagged; got {violations}"


def test_hardcoded_versioned_python_source_command_is_flagged(tmp_path: Path) -> None:
    source = '    subprocess.run(["python3.11", script], check=True)\n'
    violations = _find(tmp_path, source)
    assert len(violations) == 1, f"hardcoded versioned python source command must be flagged; got {violations}"


def test_comment_only_python_mentions_are_not_flagged(tmp_path: Path) -> None:
    assert _find(tmp_path, "# documentation mentions python3 and python3.11\n") == []


def test_wrapper_invocation_is_not_flagged(tmp_path: Path) -> None:
    wrapper = '    subprocess.run(["/usr/local/pkg/pfblockerng/pfb_python.sh", script], check=True)\n'
    assert _find(tmp_path, wrapper) == []


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
