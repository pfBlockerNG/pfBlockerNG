"""ADR-28 Phase 1 — round-trip identity tests for the cfg adapters inlined in pfb_unbound.py.

Rule (ADR-28 §2.2): for every adapted field, every existing stored value
(incl. empty / unset / any legacy variant) must satisfy write(read(v)) == v
for canonical values, or must map to the documented canonical value for
legacy migration values.

The adapters (IdnMode, PfbToggle, PfbLenient, pfb_cfg_*_read/write) live in
pfb_unbound.py (ADR-28 Phase 8 inline — pfb_cfg_adapters.py deleted; pfb_unbound.py
is the only consumer and the sole shipped file, so no separate plist entry is needed).

Scenario A — IdnMode: 'all' / 'confusable' / 'off' / '' / 'on' (legacy).
  Background: pfb_unbound.py reads the idn_mode ini key; pfb_global() (PHP)
    normalises 'on' -> 'all' at runtime.
    Given a raw stored value v.
    When pfb_cfg_idn_mode_read(v) -> enum, pfb_cfg_idn_mode_write(enum) -> stored.
    Then write(read(v)) == v for canonical values ('all', 'confusable', 'off').
    And  write(read('on')) == 'all'   (documented one-way migration).
    And  write(read('')) == 'off'     (normalised default).
    And  junk -> Off -> 'off'         (default).

Scenario B — PfbToggle: 'on' / '' two-state checkbox.
  Background: checkboxes stored 'on' (checked) or '' (unchecked / absent).
    Given a raw stored value v.
    When pfb_cfg_toggle_read(v) -> enum, pfb_cfg_toggle_write(enum) -> stored.
    Then write(read(v)) == v for canonical values.

Scenario C — PfbLenient: 'on' / 'off' / '' leniency flag.
  Background: ADR-22 scheme-parsing toggle.
    Given a raw stored value v.
    When pfb_cfg_lenient_read(v) -> enum, pfb_cfg_lenient_write(enum) -> stored.
    Then write(read(v)) == v for 'on'/'off'; '' normalises to 'off'.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Adapters are inlined into pfb_unbound.py (ADR-28 Phase 8).
# conftest.py already adds src/usr/local/pkg/pfblockerng to sys.path and
# injects Unbound globals onto builtins, so a bare import resolves.
# ---------------------------------------------------------------------------
from pfb_unbound import (
    IdnMode,
    PfbLenient,
    PfbToggle,
    pfb_cfg_idn_mode_read,
    pfb_cfg_idn_mode_write,
    pfb_cfg_lenient_read,
    pfb_cfg_lenient_write,
    pfb_cfg_toggle_read,
    pfb_cfg_toggle_write,
)

# ===========================================================================
# Scenario A — IdnMode
# ===========================================================================


class TestIdnModeRead:
    """pfb_cfg_idn_mode_read maps every stored value to the right enum case."""

    def test_read_all_returns_all(self) -> None:
        assert pfb_cfg_idn_mode_read("all") is IdnMode.All

    def test_read_confusable_returns_confusable(self) -> None:
        assert pfb_cfg_idn_mode_read("confusable") is IdnMode.Confusable

    def test_read_off_returns_off(self) -> None:
        assert pfb_cfg_idn_mode_read("off") is IdnMode.Off

    def test_read_empty_returns_off(self) -> None:
        # '' (absent key / blank) -> Off.
        assert pfb_cfg_idn_mode_read("") is IdnMode.Off

    def test_read_none_returns_off(self) -> None:
        # None (missing config key) -> Off.
        assert pfb_cfg_idn_mode_read(None) is IdnMode.Off

    def test_read_legacy_on_returns_all(self) -> None:
        # 'on' is the LEGACY value (pre-ADR-08 UI).
        # Before: raw legacy string.
        raw = "on"
        assert raw == "on"

        # When read.
        result = pfb_cfg_idn_mode_read(raw)

        # Then All — normalised (matches pfb_global() :1373).
        assert result is IdnMode.All

    def test_read_junk_returns_default(self) -> None:
        assert pfb_cfg_idn_mode_read("yes") is IdnMode.Off
        assert pfb_cfg_idn_mode_read("enabled") is IdnMode.Off
        assert pfb_cfg_idn_mode_read("IDN_MODE_ALL") is IdnMode.Off
        assert pfb_cfg_idn_mode_read("1") is IdnMode.Off


class TestIdnModeWrite:
    """pfb_cfg_idn_mode_write returns the exact canonical stored string."""

    def test_write_all(self) -> None:
        assert pfb_cfg_idn_mode_write(IdnMode.All) == "all"

    def test_write_confusable(self) -> None:
        assert pfb_cfg_idn_mode_write(IdnMode.Confusable) == "confusable"

    def test_write_off(self) -> None:
        assert pfb_cfg_idn_mode_write(IdnMode.Off) == "off"

    def test_legacy_on_never_re_emitted(self) -> None:
        # 'on' normalises to All; write(All) -> 'all', never 'on'.
        result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read("on"))
        assert result == "all"
        assert result != "on"


class TestIdnModeRoundTrip:
    """Round-trip identity: write(read(v)) == v for every canonical value."""

    @pytest.mark.parametrize("v", ["all", "confusable", "off"])
    def test_canonical_values_round_trip(self, v: str) -> None:
        # Before: raw canonical string.
        assert isinstance(v, str)

        # When round-tripped.
        result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read(v))

        # Then identical.
        assert result == v

    def test_legacy_on_normalises_to_all(self) -> None:
        # Documented one-way migration: 'on' -> 'all'.
        # Before: legacy value exists.
        raw = "on"
        assert raw == "on"

        # After: stored as canonical 'all'.
        result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read(raw))
        assert result == "all"
        assert result != "on"

    def test_empty_normalises_to_off(self) -> None:
        # '' (absent) -> 'off' (canonical off).
        result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read(""))
        assert result == "off"

    def test_none_normalises_to_off(self) -> None:
        result = pfb_cfg_idn_mode_write(pfb_cfg_idn_mode_read(None))
        assert result == "off"


class TestIdnModeDefault:
    def test_default_is_off(self) -> None:
        assert IdnMode.default() is IdnMode.Off
        assert IdnMode.default().value == "off"


# ===========================================================================
# Scenario B — PfbToggle
# ===========================================================================


class TestPfbToggleRead:
    def test_read_on_returns_on(self) -> None:
        assert pfb_cfg_toggle_read("on") is PfbToggle.On

    def test_read_empty_returns_off(self) -> None:
        assert pfb_cfg_toggle_read("") is PfbToggle.Off

    def test_read_none_returns_off(self) -> None:
        assert pfb_cfg_toggle_read(None) is PfbToggle.Off

    def test_read_junk_returns_off(self) -> None:
        assert pfb_cfg_toggle_read("yes") is PfbToggle.Off
        assert pfb_cfg_toggle_read("off") is PfbToggle.Off
        assert pfb_cfg_toggle_read("1") is PfbToggle.Off
        assert pfb_cfg_toggle_read("true") is PfbToggle.Off


class TestPfbToggleWrite:
    def test_write_on(self) -> None:
        assert pfb_cfg_toggle_write(PfbToggle.On) == "on"

    def test_write_off(self) -> None:
        # Off is stored as '' (empty checkbox value).
        assert pfb_cfg_toggle_write(PfbToggle.Off) == ""


class TestPfbToggleRoundTrip:
    @pytest.mark.parametrize("v", ["on", ""])
    def test_canonical_values_round_trip(self, v: str) -> None:
        # Before: raw canonical string.
        assert isinstance(v, str)

        # When round-tripped.
        result = pfb_cfg_toggle_write(pfb_cfg_toggle_read(v))

        # Then identical.
        assert result == v

    def test_default_is_off_empty_string(self) -> None:
        assert PfbToggle.default() is PfbToggle.Off
        assert PfbToggle.default().value == ""


# ===========================================================================
# Scenario C — PfbLenient
# ===========================================================================


class TestPfbLenientRead:
    def test_read_on_returns_on(self) -> None:
        assert pfb_cfg_lenient_read("on") is PfbLenient.On

    def test_read_off_returns_off(self) -> None:
        assert pfb_cfg_lenient_read("off") is PfbLenient.Off

    def test_read_empty_returns_off(self) -> None:
        # '' (pre-ADR-22 / absent key) -> Off (strict default).
        assert pfb_cfg_lenient_read("") is PfbLenient.Off

    def test_read_none_returns_off(self) -> None:
        assert pfb_cfg_lenient_read(None) is PfbLenient.Off

    def test_read_junk_returns_off(self) -> None:
        assert pfb_cfg_lenient_read("yes") is PfbLenient.Off
        assert pfb_cfg_lenient_read("1") is PfbLenient.Off
        assert pfb_cfg_lenient_read("enabled") is PfbLenient.Off


class TestPfbLenientWrite:
    def test_write_on(self) -> None:
        assert pfb_cfg_lenient_write(PfbLenient.On) == "on"

    def test_write_off(self) -> None:
        # Off is stored as 'off' (not '' like PfbToggle).
        assert pfb_cfg_lenient_write(PfbLenient.Off) == "off"


class TestPfbLenientRoundTrip:
    @pytest.mark.parametrize("v", ["on", "off"])
    def test_canonical_values_round_trip(self, v: str) -> None:
        result = pfb_cfg_lenient_write(pfb_cfg_lenient_read(v))
        assert result == v

    def test_empty_normalises_to_off(self) -> None:
        # '' normalises to 'off' — pre-ADR-22 installs treated as strict.
        result = pfb_cfg_lenient_write(pfb_cfg_lenient_read(""))
        assert result == "off"
        assert result != ""

    def test_default_is_off(self) -> None:
        assert PfbLenient.default() is PfbLenient.Off
        assert PfbLenient.default().value == "off"


# ===========================================================================
# Cross-field: Off values are field-specific
# ===========================================================================


class TestCrossFieldOffValues:
    """PfbToggle::Off = '' but PfbLenient::Off = 'off' — must NOT be confused."""

    def test_toggle_off_is_empty_string(self) -> None:
        assert pfb_cfg_toggle_write(PfbToggle.Off) == ""

    def test_lenient_off_is_off_string(self) -> None:
        assert pfb_cfg_lenient_write(PfbLenient.Off) == "off"

    def test_toggle_and_lenient_off_differ(self) -> None:
        toggle_off = pfb_cfg_toggle_write(PfbToggle.Off)
        lenient_off = pfb_cfg_lenient_write(PfbLenient.Off)
        assert toggle_off != lenient_off
