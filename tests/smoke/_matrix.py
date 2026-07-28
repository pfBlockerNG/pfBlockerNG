"""Per-leg variant topology for the ADR-20 repo smoke — DERIVED FROM THE VERSION MATRIX.

Every ABI / PHP / Python / catalog fact comes from the ci-metadata version matrix, never a
literal. The whole BUILD matrix is read from ``SMOKE_MATRIX_JSON`` (injected by smoke-single.yml from
``read-version-matrix.sh --print-build``); a local run falls back to running that script itself;
when neither is available the variant-topology cases SKIP. Per-leg selection still honours
``SMOKE_ABI`` / ``SMOKE_PHP_VERSION`` / ``SMOKE_PY_FLAVOR`` (the fan-out exports them per matrix
entry) plus ``SMOKE_IMAGE_REF`` (issue #1806: disambiguates two editions sharing a freebsd_major,
now that the matrix carries no ``arch`` column) — SMOKE_ABI itself stays a CONCRETE guest ABI env
var; a bare dispatch defaults to the matrix's CE entry. So adding a pfSense version to the matrix
needs no edit here.

Kept in its own stdlib-only module (no intra-package smoke imports) so the derivation is
unit-testable off-box — see ``tests/test_smoke_matrix.py``.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

# tests/smoke/_matrix.py -> repo root, for the read-version-matrix.sh fallback.
_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Variant:
    """A distributed pfSense variant, derived from a matrix entry: its pkg ``php`` dependency,
    ABI, catalog dir, ``py`` flavor, and edition (``variant``)."""

    php: str
    abi: str
    catalog: str
    py: str
    variant: str


def catalog_name(pfsense_version: str, variant: str) -> str:
    """``("2.8.1", "CE") -> "ce-2.8"`` / ``("26.03.1", "Plus") -> "plus-26.03"`` — the
    variant-keyed catalog dir (variant + the pfSense major.minor; mirrors
    build-repo-portable.py:catalog_name_from_version)."""
    parts = [p for p in str(pfsense_version).split(".") if p != ""]
    return f"{variant.lower()}-{'.'.join(parts[:2])}"


@functools.lru_cache(maxsize=1)
def build_matrix() -> tuple[dict, ...] | None:
    """The whole BUILD matrix (every CE+Plus entry), or None when unavailable.

    Prefers ``SMOKE_MATRIX_JSON`` (smoke-single.yml injects ``read-version-matrix.sh --print-build``);
    falls back to running that script on the runner; None when neither yields a non-empty JSON
    array (the caller then SKIPs the topology cases)."""
    raw = os.environ.get("SMOKE_MATRIX_JSON", "").strip()
    if not raw:
        script = _REPO_ROOT / "scripts" / "read-version-matrix.sh"
        if script.is_file():
            try:
                proc = subprocess.run(
                    ["sh", str(script), "--print-build"],
                    capture_output=True,
                    text=True,
                    timeout=30.0,
                    check=False,
                )
                if proc.returncode == 0:
                    raw = proc.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                raw = ""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return tuple(data) if isinstance(data, list) and data else None


def matrix_variants() -> list[Variant]:
    """One Variant per distinct (ABI, edition) build target in the matrix. SKIPs when the matrix
    is unavailable, so the topology cases never silently pass on hardcoded values."""
    entries = build_matrix()
    if entries is None:
        pytest.skip(
            "version matrix unavailable (set SMOKE_MATRIX_JSON, or make the ci-metadata ref "
            "readable by scripts/read-version-matrix.sh) — cannot derive the variant topology"
        )
    entries = cast(tuple[dict, ...], entries)
    out: dict[tuple[str, str], Variant] = {}
    for e in entries:
        major = str(e.get("freebsd_major", "")).strip()
        # issue #1806: the matrix carries no `arch` field at all any more (every
        # pfSense-pkg-pfBlockerNG port is NO_ARCH, the catalog is arch-less) —
        # "amd64" here is an inert CPU placeholder, never read from the entry.
        abi = f"FreeBSD:{major}:amd64"
        variant = str(e.get("variant", "")).strip()
        out.setdefault(
            (abi, variant),
            Variant(
                php="php" + str(e.get("php_version", "")).replace(".", ""),
                abi=abi,
                catalog=catalog_name(str(e.get("pfsense_version", "")), variant),
                py=str(e.get("py_flavor", "")).strip(),
                variant=variant,
            ),
        )
    return list(out.values())


def _own_entry() -> Variant:
    """This leg's variant: matched by SMOKE_ABI, else the matrix CE entry (bare dispatch).

    issue #1806: with `arch` retired, two editions CAN share a freebsd_major (not just an
    ADR-24 transition-window hypothetical) — SMOKE_ABI alone (a CONCRETE guest ABI env var;
    that contract is unchanged) then matches more than one Variant. Disambiguate via
    SMOKE_IMAGE_REF (already exported by smoke-single.yml as the resolved GHCR ref, e.g.
    ".../pfsense-plus:15.1.0") by checking which candidate's "pfsense-<variant>" image name
    it names; refuse (loudly) rather than silently pick matches[0] when it doesn't resolve to
    exactly one — a gate-A-era hazard this closes.
    """
    variants = matrix_variants()
    abi = os.environ.get("SMOKE_ABI")
    if not abi:
        ce = [v for v in variants if v.variant.lower() == "ce"]
        abi = (ce[0] if ce else variants[0]).abi
    matches = [v for v in variants if v.abi == abi]
    if not matches:
        raise RuntimeError(f"no matrix variant for ABI {abi!r} (known: {sorted(v.abi for v in variants)})")
    if len(matches) == 1:
        return matches[0]
    image_ref = os.environ.get("SMOKE_IMAGE_REF", "")
    disambiguated = [v for v in matches if f"pfsense-{v.variant.lower()}" in image_ref]
    if len(disambiguated) == 1:
        return disambiguated[0]
    raise RuntimeError(
        f"ABI {abi!r} matches {len(matches)} variants ({[v.variant for v in matches]!r}) and "
        f"SMOKE_IMAGE_REF={image_ref!r} does not disambiguate to exactly one — refusing to "
        f"silently pick one (set SMOKE_IMAGE_REF to the resolved image ref)"
    )


def matrix_php_dep() -> str:
    """This leg's pkg PHP dep name (``php83``/``php85``) — SMOKE_PHP_VERSION when set, else the
    matrix entry's php_version."""
    ver = os.environ.get("SMOKE_PHP_VERSION")
    return "php" + ver.replace(".", "") if ver else _own_entry().php


def matrix_abi() -> str:
    """This leg's target ABI — SMOKE_ABI when set, else the matrix entry's ABI."""
    return os.environ.get("SMOKE_ABI") or _own_entry().abi


def matrix_py_flavor() -> str:
    """This leg's Python flavor (``py311``) — SMOKE_PY_FLAVOR when set, else the matrix entry's."""
    return os.environ.get("SMOKE_PY_FLAVOR") or _own_entry().py


def own_variant() -> Variant:
    """The variant THIS leg runs (matrix-derived). When SMOKE_PHP_VERSION is also set it must
    agree with the matrix entry's php dep — a mismatch is a CI-wiring bug, not a silent pass."""
    own = _own_entry()
    env_php = os.environ.get("SMOKE_PHP_VERSION")
    if env_php:
        assert own.php == "php" + env_php.replace(".", ""), (
            f"matrix inconsistency: ABI {own.abi} maps to {own.php} but SMOKE_PHP_VERSION={env_php}"
        )
    return own


def opposite_variant() -> Variant:
    """The OTHER edition — the 'wrong' variant for this box (the forged package the wrong-variant
    guard must reject): the first matrix variant of a different edition."""
    own = own_variant()
    others = [v for v in matrix_variants() if v.variant.lower() != own.variant.lower()]
    if not others:
        pytest.skip(f"matrix has no opposite-edition variant to {own.variant!r} — skipping the wrong-variant guard")
    return others[0]
