"""Issue #2383 / #2403: extra_pkgs deps attach only to ROUTE rows that declare them.

Same-major ABI is not enough. A CE extra must not enter a Plus catalogue
whose extra_pkgs is empty. Category is part of the origin identity:
www/py-foo must not satisfy textproc/py-foo. These cases are hermetic
(no network). Twin dest tests own their extra_pkgs rows; this module
must not mutate shared Plus fixtures at import.
"""

from __future__ import annotations

import inspect
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


def test_row_declares_dep_rejects_different_category() -> None:
    """issue #2403: www/py-foo must not satisfy textproc/py-foo."""
    row = {"extra_pkgs": ["textproc/py-charset-normalizer"]}
    assert pr._row_declares_dep(row, _dep("www/py-charset-normalizer")) is False
    assert pr._row_declares_dep(row, _dep("www/py311-charset-normalizer")) is False


def test_row_declares_dep_rejects_non_py_last_component_other_category() -> None:
    """A non-py last component in another category is not the extra."""
    row = {"extra_pkgs": ["textproc/py-charset-normalizer"]}
    assert pr._row_declares_dep(row, _dep("security/charset-normalizer")) is False


def test_row_declares_dep_does_not_treat_abi_as_a_declaration() -> None:
    """Vacuity: a row with no extra_pkgs never declares, even for a real origin."""
    assert pr._row_declares_dep({"freebsd_major": "15"}, _dep("textproc/py-charset-normalizer")) is False


def test_build_targets_match_requires_row_declares_dep() -> None:
    """_build_targets must consult _row_declares_dep for dest extra attach."""
    source = inspect.getsource(pr._build_targets)
    assert "_row_declares_dep" in source
    assert "and _row_declares_dep" in source or "and pr._row_declares_dep" in source
