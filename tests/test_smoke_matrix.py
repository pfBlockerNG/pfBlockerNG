"""Unit tests for tests/smoke/_matrix.py — the matrix-derived variant topology used by the
ADR-20 repo smoke. Loaded by path (like test_gen_landing) so no live-VM / conftest baggage.

These pin that ALL ABI/PHP/Python/catalog facts come from the version matrix (never a literal):
the JSON source of truth, the per-ROW variant derivation, this leg's own-row selection,
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


# A representative multi-edition matrix (CE + Plus, distinct FreeBSD majors — no
# `arch` field: issue #1806 retires it, the catalog is arch-less).
_MATRIX = (
    '[{"pfsense_version":"2.8.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
    '{"pfsense_version":"26.03.1","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"Plus"}]'
)

# The same two rows with Plus FIRST — pins that the bare-dispatch default is "row 0",
# never "the CE one" (issue #2464).
_PLUS_FIRST_MATRIX = (
    '[{"pfsense_version":"26.03.1","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"Plus"},'
    '{"pfsense_version":"2.8.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"}]'
)

# Two editions sharing the SAME freebsd_major (issue #1806: with `arch` retired,
# this is a real possible shape now, not just an ADR-24 transition-window
# hypothetical) — exercises the SMOKE_IMAGE_REF disambiguation in _own_entry().
_COLLIDING_MATRIX = (
    '[{"pfsense_version":"2.8.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
    '{"pfsense_version":"15.1.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"Plus"}]'
)


@pytest.fixture(autouse=True)
def _clear_matrix_cache() -> Any:
    """build_matrix() is lru_cached; clear it around each case so env changes take effect."""
    mx.build_matrix.cache_clear()
    yield
    mx.build_matrix.cache_clear()


def _set_env(monkeypatch: pytest.MonkeyPatch, **kv: str | None) -> None:
    for k in (
        "SMOKE_MATRIX_JSON",
        "SMOKE_ABI",
        "SMOKE_PHP_VERSION",
        "SMOKE_PY_FLAVOR",
        "SMOKE_IMAGE_REF",
        "SMOKE_PFSENSE_VERSION",
    ):
        monkeypatch.delenv(k, raising=False)
    for k, v in kv.items():
        if v is not None:
            monkeypatch.setenv(k, v)


def test_catalog_name_maps_version_and_variant() -> None:
    """catalog_name = <edition>-<major.minor>, regardless of patch component."""
    assert mx.catalog_name("2.8.0", "CE") == "ce-2.8"
    assert mx.catalog_name("26.03.1", "Plus") == "plus-26.03"
    assert mx.catalog_name("2.8", "CE") == "ce-2.8"  # two-component version


def test_catalog_name_strips_prerelease_suffix() -> None:
    """A pre-release box resolves its release line's catalog (issue #1965).

    "26.07-BETA" carries the suffix inside the minor field; the production rc.d
    hook strips it before deriving the varver, so this oracle must too — otherwise
    the smoke expects a ``plus-26.07-BETA`` catalog no producer ever publishes.
    """
    assert mx.catalog_name("26.07-BETA", "Plus") == "plus-26.07"
    assert mx.catalog_name("2.9-RC1", "CE") == "ce-2.9"
    assert mx.catalog_name("2.8.1-RELEASE", "CE") == "ce-2.8"


def test_build_matrix_parses_env_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed SMOKE_MATRIX_JSON array is returned as a tuple of entries."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    m = mx.build_matrix()
    assert m is not None and len(m) == 2 and m[0]["variant"] == "CE"


def test_build_matrix_none_on_malformed_or_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malformed JSON / a non-array / an empty array -> None (caller SKIPs, never a bogus pass)."""
    for bad in ("not json", '{"not":"an array"}', "[]"):
        mx.build_matrix.cache_clear()
        _set_env(monkeypatch, SMOKE_MATRIX_JSON=bad)
        assert mx.build_matrix() is None


def test_variants_derived_per_matrix_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """One Variant per ROW, every field derived from that row.

    Keyed by version, never by ABI: an ABI-keyed dict silently drops every row after the first
    that shares an ABI, which would make this oracle vacuous on the real matrix (issue #2464).
    """
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    by_version = {v.version: v for v in mx.matrix_variants()}
    assert set(by_version) == {"2.8.0", "26.03.1"}
    assert by_version["2.8.0"] == mx.Variant(
        php="php83", abi="FreeBSD:15:amd64", catalog="ce-2.8", py="py311", variant="CE", version="2.8.0"
    )
    assert by_version["26.03.1"] == mx.Variant(
        php="php85", abi="FreeBSD:16:amd64", catalog="plus-26.03", py="py311", variant="Plus", version="26.03.1"
    )


def test_own_follows_smoke_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    """own = the entry SMOKE_ABI selects, with that entry's own php/py/catalog.

    Before/after: pointing SMOKE_ABI at the FreeBSD:15 box derives the FreeBSD:15 row;
    flipping it to FreeBSD:16 derives that row instead — the selection tracks the matrix,
    never a hardcoded side.
    """
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:15:amd64", SMOKE_PHP_VERSION="8.3")
    own = mx.own_variant()
    assert (own.abi, own.php, own.catalog) == ("FreeBSD:15:amd64", "php83", "ce-2.8")

    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:16:amd64", SMOKE_PHP_VERSION="8.5")
    own = mx.own_variant()
    assert (own.abi, own.php, own.catalog) == ("FreeBSD:16:amd64", "php85", "plus-26.03")


def test_bare_dispatch_defaults_to_the_first_matrix_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no leg env at all, own defaults to the matrix's FIRST ROW — not to an edition.

    issue #2464: "the CE entry" is not a row identity. The matrix holds two CE rows (CE 2.8 and
    CE 2.9), so an edition-keyed default picks one of them by list position and then derives an
    ABI that may match several rows. The bare-dispatch default is deliberately just "row 0",
    documented as arbitrary; a leg that cares names itself with SMOKE_PFSENSE_VERSION.
    """
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX)
    assert mx.own_variant().version == "2.8.0" and mx.matrix_abi() == "FreeBSD:15:amd64"
    assert mx.matrix_py_flavor() == "py311"

    # A matrix whose first row is Plus defaults to THAT row: no edition preference survives.
    mx.build_matrix.cache_clear()  # a second matrix in one case: the lru_cache would serve the first
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_PLUS_FIRST_MATRIX)
    own = mx.own_variant()
    assert (own.variant, own.catalog) == ("Plus", "plus-26.03")


def test_two_rows_sharing_an_abi_are_not_collapsed_by_the_unit_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rows sharing a FreeBSD major stay distinct — CE 2.9 and Plus 26.03 both are FreeBSD:16."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_COLLIDING_SHAPES_MATRIX)
    same_abi = sorted(v.catalog for v in mx.matrix_variants() if v.abi == "FreeBSD:16:amd64")
    assert same_abi == ["ce-2.9", "plus-26.03", "plus-26.07"]


def test_env_overrides_win_over_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """SMOKE_* env values override the derived matrix defaults (the per-leg injection)."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:16:amd64", SMOKE_PY_FLAVOR="py312")
    assert mx.matrix_abi() == "FreeBSD:16:amd64"
    assert mx.matrix_py_flavor() == "py312"  # env wins
    assert mx.matrix_php_dep() == "php85"  # derived from the matched entry (no SMOKE_PHP_VERSION)


def test_php_version_mismatch_is_a_wiring_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """If SMOKE_PHP_VERSION disagrees with the matched entry's php, own_variant() FAILS loudly
    (a CI-wiring bug), never silently passes."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_MATRIX, SMOKE_ABI="FreeBSD:15:amd64", SMOKE_PHP_VERSION="8.5")
    with pytest.raises(AssertionError, match="matrix inconsistency"):
        mx.own_variant()


# --------------------------------------------------------------------------- #
# gate-A-era hazard (issue #1806): with `arch` retired, two editions CAN share
# a freebsd_major (not just an ADR-24 transition-window hypothetical), so
# SMOKE_ABI alone no longer uniquely selects a variant. SMOKE_IMAGE_REF (already
# exported by smoke-single.yml as the resolved GHCR ref, e.g.
# .../pfsense-plus:15.1.0) disambiguates by image name; when it can't, own_entry
# must refuse to silently pick one rather than guess.
# --------------------------------------------------------------------------- #
def test_own_entry_disambiguates_same_major_variants_via_smoke_image_ref(monkeypatch: pytest.MonkeyPatch) -> None:
    """SMOKE_ABI matches both CE and Plus on freebsd_major=15; SMOKE_IMAGE_REF picks the right one."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_COLLIDING_MATRIX, SMOKE_ABI="FreeBSD:15:amd64")
    monkeypatch.setenv("SMOKE_IMAGE_REF", "ghcr.io/pfblockerng/pfsense-plus:15.1.0")
    assert mx.own_variant().variant == "Plus"

    monkeypatch.setenv("SMOKE_IMAGE_REF", "ghcr.io/pfblockerng/pfsense-ce:2.8.0")
    assert mx.own_variant().variant == "CE"


def test_own_entry_refuses_to_silently_pick_when_image_ref_cannot_disambiguate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No SMOKE_IMAGE_REF (or one naming neither edition) -> a loud RuntimeError, never a guess."""
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_COLLIDING_MATRIX, SMOKE_ABI="FreeBSD:15:amd64")
    with pytest.raises(RuntimeError, match="does not disambiguate"):
        mx.own_variant()

    monkeypatch.setenv("SMOKE_IMAGE_REF", "ghcr.io/pfblockerng/pfsense-somethingelse:1.0")
    with pytest.raises(RuntimeError, match="does not disambiguate"):
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


# CI-matrix shape (the shape smoke-single.yml always injects via --print-ci, which excludes
# role=route-only entries, same as --print-build — issue #1806 W3). This documents how
# route-only entries are kept out of the topology: they never reach SMOKE_MATRIX_JSON because
# --print-ci filters them at the reader level. The _matrix.py:build_matrix() function trusts
# the injected JSON, so CI-injected SMOKE_MATRIX_JSON (from --print-ci) is always free of
# route-only entries.
_CI_ONLY_MATRIX = (
    '[{"pfsense_version":"2.8.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"}]'
)


def test_smoke_topology_excludes_route_only_via_ci_matrix_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The smoke topology never produces a variant for a route-only pfSense version.

    Protection mechanism: smoke-single.yml injects SMOKE_MATRIX_JSON from
    ``read-version-matrix.sh --print-ci`` (issue #1806 W3), which excludes ``role=route-only``
    entries. _matrix.py:build_matrix() reads the injected JSON as-is. So the
    topology never sees route-only entries — the exclusion is at the reader level.

    Before/after: with a CI-only matrix (no route-only), the topology produces
    a CE variant. Adding a second CI entry (e.g. the next version) produces two
    variants — proving the topology faithfully mirrors its input, so the only way
    a route-only entry would appear is if the wrong --print-* mode were injected
    (documented: always use --print-ci for SMOKE_MATRIX_JSON).
    """
    # BEFORE: single-entry CI matrix → one CE variant (FreeBSD:15:amd64).
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_CI_ONLY_MATRIX)
    variants_before = mx.matrix_variants()
    abis_before = {v.abi for v in variants_before}
    assert "FreeBSD:15:amd64" in abis_before, f"before: CE 2.8 variant expected; got {abis_before!r}"
    # The route-only 2.7 ABI must NOT appear (it is absent from the injected JSON).
    assert "FreeBSD:14:amd64" not in abis_before, (
        f"before: route-only 2.7 ABI must not appear (not in the CI matrix); got {abis_before!r}"
    )

    # AFTER: add a second CI CE entry → two variants; the topology mirrors its input.
    two_ce = (
        '[{"pfsense_version":"2.8.0","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
        '{"pfsense_version":"2.9.0","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"CE"}]'
    )
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=two_ce)
    mx.build_matrix.cache_clear()
    variants_after = mx.matrix_variants()
    abis_after = {v.abi for v in variants_after}
    assert "FreeBSD:15:amd64" in abis_after, f"after: 2.8 CE still present; got {abis_after!r}"
    assert "FreeBSD:16:amd64" in abis_after, f"after: 2.9 CE present; got {abis_after!r}"
    # Still no route-only 2.7 ABI (never injected via --print-ci).
    assert "FreeBSD:14:amd64" not in abis_after, (
        f"after: route-only ABI must remain absent from smoke topology; got {abis_after!r}"
    )


# The two collision SHAPES a row-keyed topology must survive (issue #2464), not a snapshot
# of the live matrix — a copy of the live row set here would just rot: two rows sharing an
# edition AND a FreeBSD major, and two rows sharing a build target across editions. Nothing
# about a row is derivable from another row's edition or major.
_COLLIDING_SHAPES_MATRIX = (
    '[{"pfsense_version":"2.8","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
    '{"pfsense_version":"26.03","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"Plus"},'
    '{"pfsense_version":"26.07","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"Plus"},'
    '{"pfsense_version":"2.9","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"CE"}]'
)


def test_every_matrix_row_derives_its_own_variant(monkeypatch: pytest.MonkeyPatch) -> None:
    """issue #2464 — one Variant per ROW. No row is collapsed into another's.

    Keying the topology on (ABI, edition) silently dropped Plus 26.07 — it shares both
    with Plus 26.03 — so that leg resolved to the ``plus-26.03`` catalog and asserted
    against a release line it does not build. A matrix row is identified by its own
    version, not by a property it happens to share with a sibling.
    """
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=_COLLIDING_SHAPES_MATRIX)
    catalogs = sorted(v.catalog for v in mx.matrix_variants())
    assert catalogs == ["ce-2.8", "ce-2.9", "plus-26.03", "plus-26.07"], (
        f"a matrix row was collapsed into another: got {catalogs}"
    )


def test_own_row_selected_by_smoke_pfsense_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """The leg's own row is addressed by SMOKE_PFSENSE_VERSION — the identity CI exports.

    smoke-single.yml and ui-tests.yml export SMOKE_PFSENSE_VERSION alongside SMOKE_ABI for
    every leg, so a leg never has to be inferred from properties it shares with siblings.
    The Plus 26.07 leg must resolve to plus-26.07, not to the first FreeBSD:16 Plus row.
    """
    _set_env(
        monkeypatch,
        SMOKE_MATRIX_JSON=_COLLIDING_SHAPES_MATRIX,
        SMOKE_PFSENSE_VERSION="26.07",
        SMOKE_ABI="FreeBSD:16:amd64",
        SMOKE_PHP_VERSION="8.5",
        SMOKE_IMAGE_REF="ghcr.io/pfblockerng/pfsense-plus:16.0.0",
    )
    own = mx.own_variant()
    assert (own.catalog, own.variant, own.php, own.abi) == ("plus-26.07", "Plus", "php85", "FreeBSD:16:amd64")

    _set_env(
        monkeypatch,
        SMOKE_MATRIX_JSON=_COLLIDING_SHAPES_MATRIX,
        SMOKE_PFSENSE_VERSION="26.03",
        SMOKE_ABI="FreeBSD:16:amd64",
        SMOKE_PHP_VERSION="8.5",
        SMOKE_IMAGE_REF="ghcr.io/pfblockerng/pfsense-plus:16.0.0",
    )
    assert mx.own_variant().catalog == "plus-26.03"


def test_own_row_selection_needs_no_edition_to_major_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two editions on ONE major resolve to their own rows — no CE-is-15 / Plus-is-16 rule.

    CE 2.9 and Plus 26.03 share FreeBSD:16 and php85; only the row identity separates them.
    """
    for version, expected in (("2.9", "ce-2.9"), ("26.03", "plus-26.03")):
        _set_env(
            monkeypatch,
            SMOKE_MATRIX_JSON=_COLLIDING_SHAPES_MATRIX,
            SMOKE_PFSENSE_VERSION=version,
            SMOKE_ABI="FreeBSD:16:amd64",
            SMOKE_PHP_VERSION="8.5",
        )
        assert mx.own_variant().catalog == expected


def test_unknown_smoke_pfsense_version_falls_through_to_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    """A SMOKE_PFSENSE_VERSION that names no row is not a row identity — fall through to ABI.

    scripts/smoke-on-box.sh exports the pfSense IMAGE TAG (or a literal "?" when the ref is
    digest-pinned), which need not equal any matrix pfsense_version. Treating that as a row
    identity turned a working local on-box run into a hard RuntimeError. The ABI path still
    refuses ambiguity loudly on its own, so nothing is silently mis-selected.
    """
    for stray in ("?", "15.1.0", ""):
        _set_env(
            monkeypatch,
            SMOKE_MATRIX_JSON=_MATRIX,
            SMOKE_PFSENSE_VERSION=stray,
            SMOKE_ABI="FreeBSD:15:amd64",
        )
        own = mx.own_variant()
        assert (own.version, own.abi) == ("2.8.0", "FreeBSD:15:amd64"), f"stray={stray!r}"


def test_ambiguous_smoke_pfsense_version_still_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two rows carrying the same pfsense_version is a matrix bug — refuse, never pick one."""
    dupe = (
        '[{"pfsense_version":"2.8","freebsd_major":"15","php_version":"8.3","py_flavor":"py311","variant":"CE"},'
        '{"pfsense_version":"2.8","freebsd_major":"16","php_version":"8.5","py_flavor":"py311","variant":"Plus"}]'
    )
    _set_env(monkeypatch, SMOKE_MATRIX_JSON=dupe, SMOKE_PFSENSE_VERSION="2.8", SMOKE_ABI="FreeBSD:15:amd64")
    with pytest.raises(RuntimeError, match="matches 2 matrix rows"):
        mx.own_variant()
