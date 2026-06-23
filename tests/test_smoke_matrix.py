"""Unit tests for tests/smoke/_matrix.py — the matrix-derived variant topology used by the
ADR-20 repo smoke. Loaded by path (like test_gen_landing) so no live-VM / conftest baggage.

These pin that ALL ABI/PHP/Python/catalog facts come from the version matrix (never a literal):
the JSON source of truth, the per-(ABI, edition) variant derivation, own/opposite selection,
and the env overrides — so adding a pfSense version to the matrix needs no edit in the smoke test.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

# Load tests/smoke/_matrix.py by path, REGISTERING it in sys.modules so its @dataclass resolves.
_PATH = Path(__file__).resolve().parent / "smoke" / "_matrix.py"
_SPEC = importlib.util.spec_from_file_location("smoke_matrix_under_test", _PATH)
assert _SPEC and _SPEC.loader
mx = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = mx
_SPEC.loader.exec_module(mx)


# A representative multi-edition, multi-arch matrix (CE amd64 + Plus amd64 + Plus aarch64).
_MATRIX = (
    '[{"pfsense_version":"2.8.0","freebsd_major":"15","arch":"amd64","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
    '{"pfsense_version":"26.03.1","freebsd_major":"16","arch":"amd64","php_version":"8.5","py_flavor":"py311","variant":"Plus"},'
    '{"pfsense_version":"26.03.1","freebsd_major":"16","arch":"aarch64","php_version":"8.5","py_flavor":"py311","variant":"Plus"}]'
)


@pytest.fixture(autouse=True)
def _clear_matrix_cache() -> Any:
    """build_matrix() is lru_cached; clear it around each case so env changes take effect."""
    mx.build_matrix.cache_clear()
    yield
    mx.build_matrix.cache_clear()


def _set_env(monkeypatch: pytest.MonkeyPatch, **kv: str | None) -> None:
    for k in ("SMOKE_MATRIX_JSON", "SMOKE_ABI", "SMOKE_PHP_VERSION", "SMOKE_PY_FLAVOR"):
        monkeypatch.delenv(k, raising=False)
    for k, v in kv.items():
        if v is not None:
            monkeypatch.setenv(k, v)


def test_catalog_name_maps_version_and_variant() -> None:
    """catalog_name = <edition>-<major.minor>, regardless of patch component."""
    assert mx.catalog_name("2.8.0", "CE") == "ce-2.8"
    assert mx.catalog_name("26.03.1", "Plus") == "plus-26.03"
    assert mx.catalog_name("2.8", "CE") == "ce-2.8"  # two-component version


def test_build_matrix_parses_env_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed SMOKE_MATRIX_JSON array is returned as a tuple of entries."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    m = mx.build_matrix()
    assert m is not None and len(m) == 3 and m[0]["variant"] == "CE"


def test_build_matrix_none_on_malformed_or_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed JSON / a non-array / an empty array -> None (caller SKIPs, never a bogus pass)."""
    for bad in ("not json", '{"not":"an array"}', "[]"):
        mx.build_matrix.cache_clear()
        _set_env(monkeypatch, SMOKE_MATRIX_JSON=bad)
        assert mx.build_matrix() is None


def test_variants_derived_per_abi_edition(monkeypatch: pytest.MonkeyPatch) -> None:
    """One Variant per (ABI, edition), php/catalog/py derived from the matrix entry."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    by_abi = {v.abi: v for v in mx.matrix_variants()}
    assert set(by_abi) == {"FreeBSD:15:amd64", "FreeBSD:16:amd64", "FreeBSD:16:aarch64"}
    assert by_abi["FreeBSD:15:amd64"] == mx.Variant("php83", "FreeBSD:15:amd64", "ce-2.8", "py311", "CE")
    assert by_abi["FreeBSD:16:aarch64"].php == "php85" and by_abi["FreeBSD:16:aarch64"].catalog == "plus-26.03"


def test_own_and_opposite_follow_smoke_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    """own = the SMOKE_ABI entry; opposite = the first entry of a DIFFERENT edition.

    Before/after: the CE leg's own is CE / opposite is Plus; flipping SMOKE_ABI to the Plus
    box swaps both — proving the selection tracks the matrix, not a hardcoded side.
    """
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:15:amd64", SMOKE_PHP_VERSION="8.3")
    assert mx.own_variant().variant == "CE" and mx.own_variant().abi == "FreeBSD:15:amd64"
    assert mx.opposite_variant().variant == "Plus"  # a different edition

    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:16:amd64", SMOKE_PHP_VERSION="8.5")
    assert mx.own_variant().variant == "Plus" and mx.own_variant().abi == "FreeBSD:16:amd64"
    assert mx.opposite_variant().variant == "CE"


def test_bare_dispatch_defaults_to_ce_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no SMOKE_ABI, own defaults to the matrix's CE entry (the bare-dispatch default)."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    assert mx.own_variant().variant == "CE" and mx.matrix_abi() == "FreeBSD:15:amd64"
    assert mx.matrix_py_flavor() == "py311"


def test_env_overrides_win_over_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """SMOKE_* env values override the derived matrix defaults (the per-leg injection)."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:16:aarch64", SMOKE_PY_FLAVOR="py312")
    assert mx.matrix_abi() == "FreeBSD:16:aarch64"
    assert mx.matrix_py_flavor() == "py312"  # env wins
    assert mx.matrix_php_dep() == "php85"  # derived from the matched entry (no SMOKE_PHP_VERSION)


def test_php_version_mismatch_is_a_wiring_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """If SMOKE_PHP_VERSION disagrees with the matched entry's php, own_variant() FAILS loudly
    (a CI-wiring bug), never silently passes."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:15:amd64", SMOKE_PHP_VERSION="8.5")
    with pytest.raises(AssertionError, match="matrix inconsistency"):
        mx.own_variant()


def test_topology_skips_when_matrix_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No SMOKE_MATRIX_JSON and no readable matrix -> matrix_variants() SKIPs (not a bogus pass).

    Point the fallback script lookup at a missing path so build_matrix() yields None.
    """
    _set_env(monkeypatch)  # clears SMOKE_MATRIX_JSON
    monkeypatch.setattr(mx, "_REPO_ROOT", Path("/nonexistent-repo-root"))
    mx.build_matrix.cache_clear()
    assert mx.build_matrix() is None
    with pytest.raises(pytest.skip.Exception):
        mx.matrix_variants()


# Build-only matrix (the shape smoke-single.yml always injects via --print-build, which excludes
# route-only entries). This documents how route-only entries are kept out of the topology:
# they never reach SMOKE_MATRIX_JSON because --print-build filters them at the reader level.
# The _matrix.py:build_matrix() function trusts the injected JSON, so CI-injected
# SMOKE_MATRIX_JSON (from --print-build) is always free of route-only entries.
_BUILD_ONLY_MATRIX = (
    '[{"pfsense_version":"2.8.0","freebsd_major":"15","arch":"amd64",'
    '"php_version":"8.3","py_flavor":"py311","variant":"CE"}]'
)


def test_smoke_topology_excludes_route_only_via_build_matrix_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The smoke topology never produces a variant for a route-only pfSense version.

    Protection mechanism: smoke-single.yml injects SMOKE_MATRIX_JSON from
    ``read-version-matrix.sh --print-build``, which excludes ``role=route-only``
    entries. _matrix.py:build_matrix() reads the injected JSON as-is. So the
    topology never sees route-only entries — the exclusion is at the reader level.

    Before/after: with a build-only matrix (no route-only), the topology produces
    a CE variant. Adding a second build CE entry (e.g. the next version) produces two
    variants — proving the topology faithfully mirrors its input, so the only way
    a route-only entry would appear is if the wrong --print-* mode were injected
    (documented: always use --print-build for SMOKE_MATRIX_JSON).
    """
    # BEFORE: single-entry build matrix → one CE variant (FreeBSD:15:amd64).
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_BUILD_ONLY_MATRIX)
    variants_before = mx.matrix_variants()
    abis_before = {v.abi for v in variants_before}
    assert "FreeBSD:15:amd64" in abis_before, f"before: CE 2.8 variant expected; got {abis_before!r}"
    # The route-only 2.7 ABI must NOT appear (it is absent from the injected JSON).
    assert "FreeBSD:14:amd64" not in abis_before, (
        f"before: route-only 2.7 ABI must not appear (not in build matrix); got {abis_before!r}"
    )

    # AFTER: add a second build CE entry → two variants; the topology mirrors its input.
    two_ce = (
        '[{"pfsense_version":"2.8.0","freebsd_major":"15","arch":"amd64","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
        '{"pfsense_version":"2.9.0","freebsd_major":"16","arch":"amd64","php_version":"8.5","py_flavor":"py311","variant":"CE"}]'
    )
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=two_ce)
    mx.build_matrix.cache_clear()
    variants_after = mx.matrix_variants()
    abis_after = {v.abi for v in variants_after}
    assert "FreeBSD:15:amd64" in abis_after, f"after: 2.8 CE still present; got {abis_after!r}"
    assert "FreeBSD:16:amd64" in abis_after, f"after: 2.9 CE present; got {abis_after!r}"
    # Still no route-only 2.7 ABI (never injected via --print-build).
    assert "FreeBSD:14:amd64" not in abis_after, (
        f"after: route-only ABI must remain absent from smoke topology; got {abis_after!r}"
    )
