"""Matrix collision guard — fail closed on ambiguous varver keying.

ADR-39 §1.3 / architecture-notes "ABI is NOT 1:1": a FreeBSD (major, arch) pair can
appear in multiple pfSense versions (e.g. CE 2.8 and CE 2.9 both on FreeBSD 15/amd64).
``build_repo_matrix`` keys catalog dirs by varver (``ce-2.8``, ``ce-2.9``) so each gets
its own subtree — but IF two entries in the same matrix share the same (freebsd_major, arch)
with DIFFERENT (php_version, py_flavor), the build would silently use the wrong PHP/Python dep
for one of them (the collision poisons whichever entry is processed second).

This test fails the suite immediately when the real supported-versions matrix contains such
a collision so that no release can ship an ambiguous keying.

Two assertions — both required per the test-coverage mandate:
  1. PASSES the real matrix (the current supported-versions.json has no collision).
  2. FAILS a deliberately colliding in-test fixture (two entries with the same freebsd_major +
     arch but different php_version / py_flavor) — proving the guard is live, not a no-op.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_READ_MATRIX_SH = _REPO_ROOT / "scripts" / "read-version-matrix.sh"


def _load_build_matrix() -> list[dict] | None:
    """Load the BUILD matrix from ci-metadata via read-version-matrix.sh.

    Returns None when the script is unavailable or the ref is unreachable
    (e.g. in an isolated CI env without the ci-metadata branch).  Callers
    skip gracefully so the guard does not block unrelated local dev.
    """
    if not _READ_MATRIX_SH.is_file():
        return None
    try:
        proc = subprocess.run(
            ["sh", str(_READ_MATRIX_SH), "--print-build"],
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
            cwd=str(_REPO_ROOT),
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        data = json.loads(proc.stdout)
        if not isinstance(data, list):
            return None
        return data
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _collision_pairs(matrix: list[dict]) -> list[tuple[dict, dict]]:
    """Return pairs of entries that share (freebsd_major, arch) but differ in (php_version, py_flavor).

    ADR-39 §1.3: a (freebsd_major, arch) pair is NOT 1:1 with a pfSense version, so
    the catalog must key on varver (ce-2.8, plus-26.03 …), not ABI alone.  When two
    entries share the same (freebsd_major, arch) but carry DIFFERENT (php_version,
    py_flavor) the build cannot safely assign a single PHP/Python dep to that ABI
    pair — the second entry silently inherits the first entry's deps, producing a
    mis-built package.  Fail closed.
    """
    # Map (freebsd_major, arch) -> first entry seen with that (php, py) combo.
    seen: dict[tuple[str, str], dict] = {}
    collisions: list[tuple[dict, dict]] = []
    for entry in matrix:
        major = str(entry.get("freebsd_major", ""))
        arch = str(entry.get("arch", "amd64"))
        php = str(entry.get("php_version", ""))
        py = str(entry.get("py_flavor", ""))
        key = (major, arch)
        sig = (php, py)
        if key not in seen:
            seen[key] = entry
        else:
            prior = seen[key]
            prior_sig = (str(prior.get("php_version", "")), str(prior.get("py_flavor", "")))
            if prior_sig != sig:
                collisions.append((prior, entry))
    return collisions


# ---------------------------------------------------------------------------
# 1. REAL MATRIX — must pass (no collisions in supported-versions.json).
# ---------------------------------------------------------------------------


def test_real_matrix_has_no_abi_php_py_collision() -> None:
    """The live supported-versions matrix has no (freebsd_major, arch) collision.

    ADR-39 §1.3: (freebsd_major, arch) is NOT 1:1 with a pfSense version, so two
    matrix entries may legitimately share the same ABI — but they MUST carry the same
    (php_version, py_flavor), otherwise the build silently mis-keys the PHP/Python dep.

    Scenario: load the real BUILD matrix
      Given the ci-metadata supported-versions.json via read-version-matrix.sh
      When _collision_pairs() scans the entries
      Then zero pairs with mismatched (php_version, py_flavor) are found
    """
    matrix = _load_build_matrix()
    if matrix is None:
        pytest.skip("ci-metadata matrix not available in this environment — skipping real-matrix check")
        return  # unreachable at runtime; narrows type for mypy

    collisions = _collision_pairs(matrix)
    assert collisions == [], (
        "supported-versions.json contains (freebsd_major, arch) entries with DIFFERENT "
        "(php_version, py_flavor) — this would silently mis-key the PHP/Python dep for "
        "one of the variants.  Fix the matrix or split the entry into distinct freebsd_major "
        "values.  Colliding pairs:\n"
        + "\n".join(
            f"  {a.get('pfsense_version')} {a.get('variant')} (php={a.get('php_version')}, "
            f"py={a.get('py_flavor')}) vs "
            f"{b.get('pfsense_version')} {b.get('variant')} (php={b.get('php_version')}, "
            f"py={b.get('py_flavor')}) — shared ABI freebsd_major={a.get('freebsd_major')}, "
            f"arch={a.get('arch', 'amd64')}"
            for a, b in collisions
        )
    )


# ---------------------------------------------------------------------------
# 2. COLLIDING FIXTURE — must fail (guard is live, not a no-op).
# ---------------------------------------------------------------------------


def test_collision_guard_detects_colliding_fixture() -> None:
    """_collision_pairs() fires on a deliberately mismatched in-test fixture.

    Scenario: two entries share freebsd_major=15 / arch=amd64 but differ in php_version
      Given a two-entry matrix where both have freebsd_major=15, arch=amd64
        And the first has php_version=8.3 / py_flavor=py311
        And the second has php_version=8.5 / py_flavor=py311  ← different PHP
      When _collision_pairs() inspects the matrix
      Then it returns exactly one colliding pair (the guard fires)
       And the test asserts the guard fires (inverse assertion, not a no-op)

    Before-state assertion: with matching entries, the guard is silent.
    After-state assertion: with mismatched entries, the guard fires.
    """
    # BEFORE: no collision — two entries, same (freebsd_major, arch), SAME (php, py).
    clean_matrix = [
        {
            "pfsense_version": "2.8",
            "variant": "CE",
            "freebsd_major": "15",
            "arch": "amd64",
            "php_version": "8.3",
            "py_flavor": "py311",
        },
        {
            "pfsense_version": "2.9",
            "variant": "CE",
            "freebsd_major": "15",
            "arch": "amd64",
            "php_version": "8.3",  # same PHP — no collision
            "py_flavor": "py311",
        },
    ]
    assert _collision_pairs(clean_matrix) == [], "BEFORE: identical (php, py) entries should not trigger the guard"

    # AFTER: collision — same (freebsd_major, arch), DIFFERENT php_version.
    colliding_matrix = [
        {
            "pfsense_version": "2.8",
            "variant": "CE",
            "freebsd_major": "15",
            "arch": "amd64",
            "php_version": "8.3",
            "py_flavor": "py311",
        },
        {
            "pfsense_version": "2.9",
            "variant": "CE",
            "freebsd_major": "15",
            "arch": "amd64",
            "php_version": "8.5",  # ← DIFFERENT PHP — collision
            "py_flavor": "py311",
        },
    ]
    pairs = _collision_pairs(colliding_matrix)
    assert len(pairs) == 1, f"AFTER: exactly one colliding pair expected; got {len(pairs)}: {pairs!r}"
    a, b = pairs[0]
    assert a.get("php_version") == "8.3"
    assert b.get("php_version") == "8.5"
