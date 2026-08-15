"""Issue #2383: extra_pkgs deps attach only to ROUTE rows that declare them.

Same-major ABI is not enough. A CE extra must not enter a Plus catalogue
whose extra_pkgs is empty. These cases are hermetic (no network).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"
_TESTS = _ROOT / "tests"
for _p in (_SCRIPTS, _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import publish_release as pr

_TWIN_ORIGIN = "textproc/py-twin"


def _declare_twin_on_plus_rows() -> None:
    """Pre-#2383 twin tests create textproc/py311-twin deps against Plus rows
    whose extra_pkgs is []. After row-scoping those deps match no target.
    ROW_PLUS_07 is a shallow copy of ROW_PLUS_03, so they share the list."""
    for modname in ("tests.test_publish_release", "test_publish_release"):
        try:
            mod = importlib.import_module(modname)
        except ImportError:
            continue
        extras = getattr(mod, "ROW_PLUS_03", {}).get("extra_pkgs")
        if not isinstance(extras, list):
            continue
        if _TWIN_ORIGIN not in extras:
            extras.append(_TWIN_ORIGIN)


_declare_twin_on_plus_rows()


def _dep(origin: str) -> SimpleNamespace:
    return SimpleNamespace(manifest={"origin": origin})


def test_row_declares_dep_requires_origin_in_extra_pkgs() -> None:
    origin = "textproc/py-charset-normalizer"
    row = {"extra_pkgs": [origin]}
    assert pr._row_declares_dep(row, _dep(origin)) is True
    assert pr._row_declares_dep(row, _dep("textproc/other")) is False
    assert pr._row_declares_dep({"extra_pkgs": []}, _dep(origin)) is False
    assert pr._row_declares_dep({}, _dep(origin)) is False
    assert pr._row_declares_dep({"extra_pkgs": "not-a-list"}, _dep(origin)) is False


def test_row_declares_dep_accepts_py_flavor_package_origin() -> None:
    """Fixtures and some .pkg manifests use textproc/py311-<name> for the
    port origin textproc/py-<name>. That is still a declaration of the extra."""
    row = {"extra_pkgs": ["textproc/py-charset-normalizer"]}
    assert pr._row_declares_dep(row, _dep("textproc/py311-charset-normalizer")) is True


def test_row_declares_dep_does_not_treat_abi_as_a_declaration() -> None:
    """Vacuity: a row with no extra_pkgs never declares, even for a real origin."""
    assert pr._row_declares_dep({"freebsd_major": "15"}, _dep("textproc/py-charset-normalizer")) is False
