"""Per-leg variant topology for the ADR-20 repo smoke — DERIVED FROM THE VERSION MATRIX.

Every ABI / PHP / Python / catalog fact comes from the ci-metadata version matrix, never a
literal. The whole CI matrix (ONE ROW PER VERSION, never deduped by freebsd_major) is read from
``SMOKE_MATRIX_JSON`` (injected by smoke-single.yml from ``read-version-matrix.sh --print-ci`` —
issue #2926 W3: --print-build dedupes to one row per runtime tuple, which would hide a second edition
sharing a major from matrix_variants() entirely and make the SMOKE_IMAGE_REF disambiguation below
unreachable); a local run falls back to running that script itself; when neither is available the
variant-topology cases SKIP. Per-leg selection still honours ``SMOKE_ABI`` / ``SMOKE_PHP_VERSION``
/ ``SMOKE_PY_FLAVOR`` (the fan-out exports them per matrix entry) plus ``SMOKE_IMAGE_REF``
(issue #1806: disambiguates two editions sharing a freebsd_major, now that the matrix carries no
``arch`` column) — SMOKE_ABI itself stays a CONCRETE guest ABI env var. A leg is addressed by its
own row identity, ``SMOKE_PFSENSE_VERSION`` (exported per leg by smoke-single.yml and
ui-tests.yml); a bare dispatch that names no leg falls back to the matrix's first row, an
arbitrary but deterministic default. Nothing here maps an edition to an ABI, a php version, or a
release line — two rows may share any of those (issue #2464). So adding a pfSense version to the
matrix needs no edit here.

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
    """One MATRIX ROW, derived: its pkg ``php`` dependency, ABI, catalog dir, ``py`` flavor,
    edition (``variant``) and the ``pfsense_version`` that identifies the row.

    A row is identified by itself, never by a property it shares with a sibling: two rows may
    share an edition and a FreeBSD major (Plus 26.03 / Plus 26.07), or a build target across
    editions (CE 2.9 / Plus 26.03 are both FreeBSD:16 / php85) — issue #2464."""

    php: str
    abi: str
    catalog: str
    py: str
    variant: str
    version: str


def catalog_name(pfsense_version: str, variant: str) -> str:
    """``("2.8.1", "CE") -> "ce-2.8"`` / ``("26.03.1", "Plus") -> "plus-26.03"`` — the
    variant-keyed catalog dir (variant + the pfSense major.minor; mirrors
    build-repo-portable.py:catalog_name_from_version).

    A pre-release suffix is stripped first (``"26.07-BETA" -> "plus-26.07"``): it sits
    inside the minor field, and both the producer and the on-box rc.d hook drop it
    before deriving the varver (issue #1965)."""
    parts = [p for p in str(pfsense_version).split("-")[0].split(".") if p != ""]
    return f"{variant.lower()}-{'.'.join(parts[:2])}"


@functools.lru_cache(maxsize=1)
def build_matrix() -> tuple[dict, ...] | None:
    """The whole CI matrix (every CE+Plus ci:true entry, one row per version), or None when
    unavailable.

    Prefers ``SMOKE_MATRIX_JSON`` (smoke-single.yml injects ``read-version-matrix.sh --print-ci``
    — issue #2926 W3, never ``--print-build``: that dedupes by runtime tuple, which would hide a
    same-major second edition from this topology entirely); falls back to running that script on
    the runner; None when neither yields a non-empty JSON array (the caller then SKIPs the
    topology cases)."""
    raw = os.environ.get("SMOKE_MATRIX_JSON", "").strip()
    if not raw:
        script = _REPO_ROOT / "scripts" / "read-version-matrix.sh"
        if script.is_file():
            try:
                proc = subprocess.run(
                    ["sh", str(script), "--print-ci"],
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
    """One Variant per matrix ROW (duplicate rows collapse; distinct rows never do). SKIPs when
    the matrix is unavailable, so the topology cases never silently pass on hardcoded values.

    Keying this on (ABI, edition) is what issue #2464 removed: Plus 26.07 shares both with Plus
    26.03, so it vanished from the topology and its leg silently resolved to the plus-26.03
    catalog — a release line it does not build."""
    entries = build_matrix()
    if entries is None:
        pytest.skip(
            "version matrix unavailable (set SMOKE_MATRIX_JSON, or make the ci-metadata ref "
            "readable by scripts/read-version-matrix.sh) — cannot derive the variant topology"
        )
    entries = cast(tuple[dict, ...], entries)
    out: dict[Variant, None] = {}
    for e in entries:
        major = str(e.get("freebsd_major", "")).strip()
        # issue #1806: the matrix carries no `arch` field at all any more (every
        # pfSense-pkg-pfBlockerNG port is NO_ARCH, the catalog is arch-less) —
        # "amd64" here is an inert CPU placeholder, never read from the entry.
        abi = f"FreeBSD:{major}:amd64"
        variant = str(e.get("variant", "")).strip()
        version = str(e.get("pfsense_version", "")).strip()
        out.setdefault(
            Variant(
                php="php" + str(e.get("php_version", "")).replace(".", ""),
                abi=abi,
                catalog=catalog_name(version, variant),
                py=str(e.get("py_flavor", "")).strip(),
                variant=variant,
                version=version,
            )
        )
    return list(out)


def _own_entry() -> Variant:
    """This leg's ROW: matched by SMOKE_PFSENSE_VERSION, else SMOKE_ABI, else the matrix's
    first row (bare dispatch).

    SMOKE_PFSENSE_VERSION is the row's own identity and is exported for every leg by
    smoke-single.yml and ui-tests.yml, so a leg never has to be inferred from a property it
    shares with a sibling row (issue #2464). ABI matching stays as the fallback for a run that
    sets only SMOKE_ABI.

    issue #1806: with `arch` retired, two editions CAN share a freebsd_major (not just an
    ADR-24 transition-window hypothetical) — SMOKE_ABI alone (a CONCRETE guest ABI env var;
    that contract is unchanged) then matches more than one Variant. Disambiguate via
    SMOKE_IMAGE_REF (already exported by smoke-single.yml as the resolved GHCR ref, e.g.
    ".../pfsense-plus:15.1.0") by checking which candidate's "pfsense-<variant>" image name
    it names; refuse (loudly) rather than silently pick matches[0] when it doesn't resolve to
    exactly one — a gate-A-era hazard this closes.
    """
    variants = matrix_variants()
    version = os.environ.get("SMOKE_PFSENSE_VERSION", "").strip()
    if version:
        rows = [v for v in variants if v.version == version]
        if len(rows) > 1:
            raise RuntimeError(f"pfsense_version {version!r} matches {len(rows)} matrix rows: {rows!r}")
        if rows:
            return rows[0]
        # Names no row, so it is not a row identity: scripts/smoke-on-box.sh exports the pfSense
        # IMAGE TAG here (or a literal "?" for a digest-pinned ref), which need not equal any
        # matrix pfsense_version. Fall through to ABI matching, which refuses ambiguity loudly
        # on its own — nothing is silently mis-selected.
    abi = os.environ.get("SMOKE_ABI")
    if not abi:
        # Bare dispatch names no leg at all: fall back to the matrix's FIRST ROW. Deliberately
        # positional and documented as arbitrary — "the CE entry" was not a row identity once a
        # second CE row existed (issue #2464), and an edition-keyed default then derived an ABI
        # that several rows answer to. A leg that cares sets SMOKE_PFSENSE_VERSION.
        return variants[0]
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
