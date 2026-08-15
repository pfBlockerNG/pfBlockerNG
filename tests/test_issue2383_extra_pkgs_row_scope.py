"""Issue #2383: extra_pkgs deps attach only to ROUTE rows that declare them.

Same-major ABI is not enough. A CE extra must not enter a Plus catalogue
whose extra_pkgs is empty. These cases are hermetic (no network).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import publish_release as pr


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
