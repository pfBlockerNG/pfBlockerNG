"""Nightly pkgversion is derived in one place (issue #2754).

nightly.yml, smoke-single.yml, and smoke-on-box.sh must call the same helper
so a local nightly smoke cannot silently build a different pkgversion than CI.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from scripts import release_version as rv

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "nightly-pkgversion.sh"
NIGHTLY_YML = ROOT / ".github" / "workflows" / "nightly.yml"
SMOKE_SINGLE_YML = ROOT / ".github" / "workflows" / "smoke-single.yml"

_SHA = "fd978e098ecdd3b982c7a3f8e02fefde36df14e5"
_VERSION_RE = re.compile(r"^[0-9]{14}\.[0-9a-f]{7}$")


def test_nightly_pkgversion_helper_exists() -> None:
    """Given the shared nightly identity helper
    When the tree is checked
    Then the script is tracked. Callers invoke it with ``sh``, so the git
    exec bit is not load-bearing.
    """
    assert HELPER.is_file()
    tracked = subprocess.check_output(
        ["git", "ls-files", "--", "scripts/nightly-pkgversion.sh"],
        cwd=ROOT,
        text=True,
    ).strip()
    assert tracked == "scripts/nightly-pkgversion.sh"


def test_nightly_pkgversion_helper_emits_utc_seconds_plus_short_sha() -> None:
    """Given a 40-character source SHA
    When the helper runs
    Then the printed version is YYYYMMDDHHMMSS.<7-hex> and validates.
    """
    result = subprocess.run(
        ["dash", str(HELPER), _SHA],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    version = result.stdout.strip()
    assert _VERSION_RE.fullmatch(version), version
    assert version.endswith(".fd978e0")
    assert rv.validate_nightly_version(version, source_sha=_SHA) == version


def test_nightly_pkgversion_helper_uses_utc_not_local_time() -> None:
    """``date -u`` is load-bearing: a local-time helper would disagree across TZs."""
    env_utc = {**os.environ, "TZ": "UTC"}
    env_east = {**os.environ, "TZ": "America/New_York"}
    utc = subprocess.run(
        ["dash", str(HELPER), _SHA],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env_utc,
    )
    east = subprocess.run(
        ["dash", str(HELPER), _SHA],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env_east,
    )
    assert utc.returncode == 0, utc.stderr
    assert east.returncode == 0, east.stderr
    a, b = utc.stdout.strip(), east.stdout.strip()
    assert _VERSION_RE.fullmatch(a), a
    assert _VERSION_RE.fullmatch(b), b
    assert a.endswith(".fd978e0")
    assert b.endswith(".fd978e0")
    # Local clocks in these zones differ by hours; UTC stamps agree within 2s.
    assert abs(int(a.split(".", 1)[0]) - int(b.split(".", 1)[0])) <= 2, (a, b)


def test_nightly_pkgversion_helper_rejects_short_sha() -> None:
    """Given a SHA shorter than 7 hex characters
    When the helper runs
    Then it exits non-zero rather than padding or guessing.
    """
    result = subprocess.run(
        ["dash", str(HELPER), "abc"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""


def test_nightly_yml_and_smoke_single_call_the_same_helper() -> None:
    """Given CI nightly and repo-flow smoke
    When each workflow derives a nightly pkgversion
    Then both invoke scripts/nightly-pkgversion.sh rather than inlining date+sha.
    """
    nightly = NIGHTLY_YML.read_text(encoding="utf-8")
    smoke = SMOKE_SINGLE_YML.read_text(encoding="utf-8")
    assert 'PKG_VERSION="$(sh "$TRUSTED_DIR/scripts/nightly-pkgversion.sh" "$SOURCE_SHA")"' in nightly
    assert 'NIGHTLY_VERSION="$(sh scripts/nightly-pkgversion.sh "$SOURCE_SHA")"' in smoke
    assert 'PKG_VERSION="${BUILD_TIMESTAMP}.${SOURCE_SHORT_SHA}"' not in nightly
    assert 'NIGHTLY_VERSION="$(date -u +%Y%m%d%H%M%S).${SOURCE_SHORT_SHA}"' not in smoke
