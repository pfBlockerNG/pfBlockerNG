"""
Scenario: --print-build-origins emits the correct set and a sparse build is byte-identical.

Background:
    A local FreeBSD-ports clone is required.  The test discovers it via the env var
    FREEBSD_PORTS_DIR, or falls back to a ``FreeBSD-ports`` sibling of the repo root.
    When neither is present the tests are skipped — this is a local-only test;
    CI uses the sparse-clone-ports.sh helper to produce a real sparse clone and
    relies on the release.yml / smoke-single.yml run to validate end-to-end.

Given:
    A full FreeBSD-ports checkout is available at PORTS_DIR.

When (test 1):
    --print-build-origins is called for (devel, php=8.3, py311).

Then (test 1):
    The output includes every dir in the known-good set, including devel/php83-intl
    resolved via the filesystem glob.

When (test 2):
    A sparse ports tree containing ONLY the printed origin dirs is assembled in a
    temp dir by copying those dirs from the full clone, and the .pkg is built from
    both the full tree and the sparse copy.

Then (test 2):
    The two .pkg files are byte-identical (cmp passes).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Repo root → sibling FreeBSD-ports checkout (the conventional dev location).
_DEFAULT_PORTS = Path(__file__).parent.parent.parent / "FreeBSD-ports"
_BUILDER = Path(__file__).parent.parent / "scripts" / "build-pkg-portable.py"

# Known-good origin set for (channel=devel, php=8.3, py_flavor=py311)
_EXPECTED_ORIGINS = {
    "databases/py-sqlite3",
    "devel/php83-intl",
    "lang/php83",
    "lang/python311",
    "net-mgmt/grepcidr",
    "net-mgmt/iprange",
    "net/libmaxminddb",
    "net/pfSense-pkg-pfBlockerNG-devel",
    "net/py-maxminddb",
    "net/rsync",
    "textproc/gnugrep",
    "textproc/jq",
    "www/lighttpd",
}

_CHANNEL = "devel"
_PHP = "8.3"
_PY = "py311"
_ABI = "FreeBSD:15:amd64"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _ports_dir() -> Path | None:
    env = os.environ.get("FREEBSD_PORTS_DIR")
    p = Path(env) if env else _DEFAULT_PORTS
    if p.is_dir() and (p / "net" / "pfSense-pkg-pfBlockerNG-devel" / "Makefile").is_file():
        return p
    return None


def _run_builder(*args: str, ports: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_BUILDER), "--ports", str(ports), *args],
        capture_output=True,
        text=True,
        check=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_ports_dir() is None, reason="FreeBSD-ports checkout not found locally; skip in CI")
def test_print_build_origins_includes_expected_dirs() -> None:
    """--print-build-origins for (devel, php=8.3, py311) emits every expected dir.

    Given a full FreeBSD-ports checkout.
    When  --print-build-origins is called with the devel channel + CE 2.8 variants.
    Then  the output is a superset of the 13 known-good origin dirs, including
          devel/php83-intl resolved via the filesystem glob.
    """
    ports = _ports_dir()
    assert ports is not None  # redundant after skipif, but makes mypy happy

    result = _run_builder(
        "--channel",
        _CHANNEL,
        "--php",
        _PHP,
        "--py-flavor",
        _PY,
        "--print-build-origins",
        ports=ports,
    )
    assert result.returncode == 0, (
        f"--print-build-origins exited {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    got = set(result.stdout.strip().splitlines())
    missing = _EXPECTED_ORIGINS - got
    assert not missing, (
        f"--print-build-origins missing expected origins:\n"
        f"  expected: {sorted(_EXPECTED_ORIGINS)}\n"
        f"  got:      {sorted(got)}\n"
        f"  missing:  {sorted(missing)}"
    )


@pytest.mark.skipif(_ports_dir() is None, reason="FreeBSD-ports checkout not found locally; skip in CI")
def test_sparse_build_byte_identical_to_full_build() -> None:
    """A build from a sparse tree (only --print-build-origins dirs) is byte-identical.

    Scenario: sparse-clone byte identity.

    Given a full FreeBSD-ports checkout.
    When  the .pkg is built from the full tree.
    And   a sparse copy (containing only the printed origin dirs) is assembled.
    And   the .pkg is built from the sparse copy.
    Then  the two .pkg files are byte-identical.

    This pins the core invariant that the sparse checkout contains every file the
    builder reads — if any origin dir is missing the sparse build either fails
    or produces a different manifest.
    """
    ports_full = _ports_dir()
    assert ports_full is not None

    # 1. Get the origin set.
    result = _run_builder(
        "--channel",
        _CHANNEL,
        "--php",
        _PHP,
        "--py-flavor",
        _PY,
        "--print-build-origins",
        ports=ports_full,
    )
    assert result.returncode == 0, result.stderr
    origins = result.stdout.strip().splitlines()
    assert origins, "--print-build-origins produced no output"

    with tempfile.TemporaryDirectory(prefix="pfbng-sparse-test-") as tmpdir:
        tmp = Path(tmpdir)

        # 2. Build from the full tree.
        out_full = tmp / "out-full"
        out_full.mkdir()
        r_full = _run_builder(
            "--channel",
            _CHANNEL,
            "--abi",
            _ABI,
            "--php",
            _PHP,
            "--py-flavor",
            _PY,
            "--local-src",
            str(Path(__file__).parent.parent),
            "--out",
            str(out_full),
            ports=ports_full,
        )
        assert r_full.returncode == 0, f"full build failed\nstdout: {r_full.stdout}\nstderr: {r_full.stderr}"
        pkgs_full = list(out_full.glob("*.pkg"))
        assert len(pkgs_full) == 1, f"expected 1 .pkg from full build, got {pkgs_full}"
        pkg_full = pkgs_full[0]

        # 3. Assemble a sparse ports tree by copying (not symlinking) only the printed
        #    origin dirs.  We copy so that the sparse tree is self-contained and the
        #    test does not depend on symlink traversal behaviour.
        ports_sparse = tmp / "ports-sparse"
        for origin in origins:
            src = ports_full / origin
            dst = ports_sparse / origin
            if src.is_dir():
                shutil.copytree(src, dst)

        # 4. Build from the sparse tree.
        out_sparse = tmp / "out-sparse"
        out_sparse.mkdir()
        r_sparse = _run_builder(
            "--channel",
            _CHANNEL,
            "--abi",
            _ABI,
            "--php",
            _PHP,
            "--py-flavor",
            _PY,
            "--local-src",
            str(Path(__file__).parent.parent),
            "--out",
            str(out_sparse),
            ports=ports_sparse,
        )
        assert r_sparse.returncode == 0, f"sparse build failed\nstdout: {r_sparse.stdout}\nstderr: {r_sparse.stderr}"
        pkgs_sparse = list(out_sparse.glob("*.pkg"))
        assert len(pkgs_sparse) == 1, f"expected 1 .pkg from sparse build, got {pkgs_sparse}"
        pkg_sparse = pkgs_sparse[0]

        # 5. Byte-identical check.
        bytes_full = pkg_full.read_bytes()
        bytes_sparse = pkg_sparse.read_bytes()
        assert bytes_full == bytes_sparse, (
            f"sparse and full builds produced different .pkg files\n"
            f"  full:   {pkg_full}  ({len(bytes_full)} bytes)\n"
            f"  sparse: {pkg_sparse}  ({len(bytes_sparse)} bytes)\n"
            f"origins used: {origins}"
        )
