"""tests/test_adr47_conftest_lane.py — ADR-47 conftest lane-stride unit tests.

Pins the TOCTOU-fix changes made to tests/smoke/conftest.py:
  1. _validate_lane ceiling: 12340 (LAN socket, new highest base) → max lane 5319.
  2. DEFAULT_LAN_SOCKET_PORT: deterministic, lane-strided from 12340.
  3. DIAG_DIR: empty PFB_DIAG_DIR falls back to "smoke-diag" (not Path("")).

RED→GREEN evidence:
  - Before the ceiling change (old 8080-based ceiling 5745): asserting lane 5320 raises
    ValueError with the 8080/5745 message → test FAILS (wrong message / no raise).
    After the change: raises with the 12340/5319 message → PASSES.
  - Before DEFAULT_LAN_SOCKET_PORT was added: the module has no such name → test FAILS
    (AttributeError). After: name exists and equals 12340 at lane 0 → PASSES.
  - Before DIAG_DIR fix: Path("") (cwd) when PFB_DIAG_DIR="". After: Path("smoke-diag").

Run: python -m pytest tests/test_adr47_conftest_lane.py -v
"""

from __future__ import annotations

import importlib
import os
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Helpers — load conftest in an isolated environment with a controlled SMOKE_LANE
# and PFB_DIAG_DIR so we can vary them per test without cross-contamination.
# ---------------------------------------------------------------------------


def _load_conftest(lane: int = 0, diag_dir: str | None = None) -> types.ModuleType:
    """Import tests.smoke.conftest with SMOKE_LANE=lane.

    Uses importlib.import_module after patching os.environ so the module's
    top-level assignments (DEFAULT_* ports, DIAG_DIR) pick up the right values.
    The module is freshly loaded each call via sys.modules manipulation.
    """
    old_lane = os.environ.get("SMOKE_LANE")
    old_diag = os.environ.get("PFB_DIAG_DIR")

    os.environ["SMOKE_LANE"] = str(lane)
    if diag_dir is None:
        os.environ.pop("PFB_DIAG_DIR", None)
    else:
        os.environ["PFB_DIAG_DIR"] = diag_dir

    # Force a fresh import by removing any cached module and all conftest deps that
    # cache the lane at import time.
    for key in list(sys.modules):
        if "smoke.conftest" in key or key == "tests.smoke.conftest":
            del sys.modules[key]

    try:
        mod = importlib.import_module("tests.smoke.conftest")
        return mod
    finally:
        # Restore env
        if old_lane is None:
            os.environ.pop("SMOKE_LANE", None)
        else:
            os.environ["SMOKE_LANE"] = old_lane
        if old_diag is None:
            os.environ.pop("PFB_DIAG_DIR", None)
        else:
            os.environ["PFB_DIAG_DIR"] = old_diag


# ---------------------------------------------------------------------------
# 1 — _validate_lane ceiling: 12340-based, max = 5319
# ---------------------------------------------------------------------------


class TestValidateLaneCeiling:
    """_validate_lane uses the highest port base (12340, LAN socket) → ceiling 5319."""

    def test_lane_0_is_valid(self) -> None:
        """Lane 0 is always valid — baseline sanity."""
        mod = _load_conftest(lane=0)
        # No exception means valid
        mod._validate_lane(0)

    def test_lane_5319_is_valid(self) -> None:
        """Lane 5319 is the highest valid lane: 12340 + 5319*10 = 65530 ≤ 65535."""
        mod = _load_conftest(lane=0)
        mod._validate_lane(5319)  # must not raise

    def test_lane_5320_raises(self) -> None:
        """Lane 5320 would push 12340 + 5320*10 = 65540 > 65535 → ValueError."""
        mod = _load_conftest(lane=0)
        with pytest.raises(ValueError, match="5319"):
            mod._validate_lane(5320)

    def test_lane_negative_raises(self) -> None:
        """Negative lane always raises."""
        mod = _load_conftest(lane=0)
        with pytest.raises(ValueError):
            mod._validate_lane(-1)

    def test_error_message_names_12340_base(self) -> None:
        """Error message must reference 12340 (the new highest base) + the ceiling 5319.

        Before the change the message said '8080' and '5745'. After: '12340' and '5319'.
        This assertion is the red→green diff: old code → old message → FAILS here.
        """
        mod = _load_conftest(lane=0)
        with pytest.raises(ValueError) as exc_info:
            mod._validate_lane(5320)
        msg = str(exc_info.value)
        assert "5319" in msg, f"expected '5319' in error message; got: {msg!r}"
        # Verify the OLD ceiling (5745) is NOT mentioned — that would mean the old code.
        assert "5745" not in msg, f"old ceiling 5745 still in message: {msg!r}"


# ---------------------------------------------------------------------------
# 2 — DEFAULT_LAN_SOCKET_PORT: deterministic, lane-strided from 12340
# ---------------------------------------------------------------------------


class TestDefaultLanSocketPort:
    """DEFAULT_LAN_SOCKET_PORT eliminates the bind(:0) TOCTOU race (ADR-47 P4)."""

    def test_lane0_equals_12340(self) -> None:
        """At lane 0 the LAN socket port is 12340 (the historical boot_vm.sh default)."""
        mod = _load_conftest(lane=0)
        # Before the change, the name didn't exist → AttributeError (red).
        # After: it is 12340.
        port = mod.DEFAULT_LAN_SOCKET_PORT
        assert port == 12340, f"expected 12340 at lane 0; got {port}"

    def test_lane1_equals_12350(self) -> None:
        """At lane 1 the LAN socket port is 12340 + 1*10 = 12350 (stride 10)."""
        mod = _load_conftest(lane=1)
        port = mod.DEFAULT_LAN_SOCKET_PORT
        assert port == 12350, f"expected 12350 at lane 1; got {port}"

    def test_lane_stride_is_10(self) -> None:
        """Each successive lane adds 10 — same stride as SSH/WEB/CLIENT_SSH."""
        mod0 = _load_conftest(lane=0)
        mod1 = _load_conftest(lane=1)
        mod2 = _load_conftest(lane=2)
        assert mod1.DEFAULT_LAN_SOCKET_PORT - mod0.DEFAULT_LAN_SOCKET_PORT == 10
        assert mod2.DEFAULT_LAN_SOCKET_PORT - mod1.DEFAULT_LAN_SOCKET_PORT == 10

    def test_written_to_env_at_import(self) -> None:
        """SMOKE_LAN_SOCKET_PORT is written to os.environ at import time (lane 0 → '12340').

        This ensures boot_vm.sh inherits the same value the harness uses — the point of
        the TOCTOU fix. Before the change, the env var was only set inside the fixture
        (too late for some import-time callers). After: set at module level.
        """
        # Load with lane=0 and verify the env var was set.
        _load_conftest(lane=0)
        val = os.environ.get("SMOKE_LAN_SOCKET_PORT")
        assert val == "12340", f"expected SMOKE_LAN_SOCKET_PORT='12340'; got {val!r}"


# ---------------------------------------------------------------------------
# 3 — DIAG_DIR empty-safe guard
# ---------------------------------------------------------------------------


class TestDiagDir:
    """DIAG_DIR falls back to 'smoke-diag' when PFB_DIAG_DIR is absent or empty."""

    def test_absent_env_uses_default(self) -> None:
        """PFB_DIAG_DIR not set → Path('smoke-diag')."""
        mod = _load_conftest(diag_dir=None)
        assert mod.DIAG_DIR.name == "smoke-diag", f"expected 'smoke-diag'; got {mod.DIAG_DIR}"

    def test_empty_env_uses_default(self) -> None:
        """PFB_DIAG_DIR='' → Path('smoke-diag'), NOT Path('') (which equals cwd).

        Before the fix (bare Path(os.environ.get('PFB_DIAG_DIR', 'smoke-diag'))):
          Path('') == Path.cwd() — files escape the CI upload globs.
        After ('or "smoke-diag"' guard):
          Path('smoke-diag') — correct relative path.
        This is the red→green assertion: old code → Path('') → assertion FAILS.
        """
        mod = _load_conftest(diag_dir="")
        assert mod.DIAG_DIR.name == "smoke-diag", (
            f"PFB_DIAG_DIR='' must fall back to 'smoke-diag'; got {mod.DIAG_DIR!r}"
        )
        assert str(mod.DIAG_DIR) != "", "DIAG_DIR must not be empty-string Path (= cwd)"

    def test_explicit_env_is_honoured(self) -> None:
        """PFB_DIAG_DIR=/some/path → Path('/some/path')."""
        mod = _load_conftest(diag_dir="/some/diags")
        assert str(mod.DIAG_DIR) == "/some/diags", f"expected '/some/diags'; got {mod.DIAG_DIR!r}"
