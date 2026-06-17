"""pfb_cfg_adapters — ADR-28 Phase 1.

Internal enum types and field-aware read/write adapters for config flags that
pfb_unbound.py will adopt in a later phase.  BEHAVIOUR-PRESERVING: nothing in
production imports this module yet.

Rule (ADR-28 §2.2):
- config.xml stored values NEVER change.
- Enums are an INTERNAL runtime representation only.
- read adapter: IdnMode(stored) or a default; write adapter: mode.value.
- Where a field's "off" is '' for one field and 'off' for another the adapter
  is field-specific — no single global toggle.

Stdlib only (pfb_unbound.py runs inside Unbound's Python loader).
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# IdnMode — ADR-08 IDN-feature mode selector (Python side).
#
# pfb_unbound.py already defines IDN_MODE_OFF/ALL/CONFUSABLE as plain string
# constants ('off'/'all'/'confusable').  This enum carries the same backing
# values so a future phase can replace the constants without changing stored
# data or ini parsing.
#
# Stored (ini) vocabulary:
#   'all'        -- block every xn-- query
#   'confusable' -- TR39 cross-script homoglyph analysis
#   'off'        -- IDN feature disabled
#   ''           -- absent / not configured -> Off
#   'on'         -- LEGACY (pre-ADR-08 UI writes 'on' for 'all'); normalised
#                   on read, never re-emitted on write.
# ---------------------------------------------------------------------------


class IdnMode(Enum):
    """IDN-feature mode selector (ADR-08 §2.2, backed by canonical stored string)."""

    All = "all"
    Confusable = "confusable"
    Off = "off"

    @classmethod
    def default(cls) -> IdnMode:
        return cls.Off


# ---------------------------------------------------------------------------
# Field-aware adapter helpers (pfb_cfg_* naming per CLAUDE.md).
# ---------------------------------------------------------------------------

# Mapping for pfb_cfg_idn_mode_read — covers all stored values including legacy.
_IDN_MODE_READ_MAP: dict[str, IdnMode] = {
    "all": IdnMode.All,
    "on": IdnMode.All,  # legacy: 'on' normalises to All (pfb_global() :1373)
    "confusable": IdnMode.Confusable,
    "off": IdnMode.Off,
    "": IdnMode.Off,  # absent key / blank -> Off
}


def pfb_cfg_idn_mode_read(stored: str | None) -> IdnMode:
    """Read a raw stored IDN-mode value into an IdnMode enum.

    Replicates pfb_global() :1372-1373 normalisation:
      'on'  -> All (legacy migration; canonical stored value is 'all')
      'all' -> All
      'confusable' -> Confusable
      '' / None / anything else -> Off

    Args:
        stored: raw value from the ini / pfb dict (may be None if key absent).
    """
    return _IDN_MODE_READ_MAP.get(stored or "", IdnMode.default())


def pfb_cfg_idn_mode_write(mode: IdnMode) -> str:
    """Write an IdnMode back to its canonical stored string.

    Returns 'all', 'confusable', or 'off'.  The legacy value 'on' is NEVER
    re-emitted; it normalises to 'all' on read and is stored as 'all' on write.
    """
    return mode.value


# ---------------------------------------------------------------------------
# PfbToggle — checkbox fields stored as 'on' (checked) or '' (unchecked).
#
# Python side analogue of the PHP PfbToggle enum.  Used for flags that
# pfb_unbound.py reads from the ini (e.g. python_hsts, python_cname).
# ---------------------------------------------------------------------------


class PfbToggle(Enum):
    """Two-state checkbox toggle ('on' / '')."""

    On = "on"
    Off = ""

    @classmethod
    def default(cls) -> PfbToggle:
        return cls.Off


def pfb_cfg_toggle_read(stored: str | None) -> PfbToggle:
    """Read a raw stored toggle value into a PfbToggle enum.

    Maps 'on' -> On, anything else (incl. None / '') -> Off.
    """
    if stored == "on":
        return PfbToggle.On
    return PfbToggle.default()


def pfb_cfg_toggle_write(toggle: PfbToggle) -> str:
    """Write a PfbToggle back to its stored string ('on' or '')."""
    return toggle.value


# ---------------------------------------------------------------------------
# PfbLenient — the ADR-22 scheme-parsing leniency flag ('on' / 'off' / '').
#
# Python side analogue of the PHP PfbLenient enum.  Included for completeness;
# the lenient flag is primarily consumed by PHP but the adapter lives here so
# round-trip tests are symmetric.
# ---------------------------------------------------------------------------


class PfbLenient(Enum):
    """ADR-22 scheme-parsing leniency ('on' = lenient, 'off' = strict)."""

    On = "on"
    Off = "off"

    @classmethod
    def default(cls) -> PfbLenient:
        return cls.Off


def pfb_cfg_lenient_read(stored: str | None) -> PfbLenient:
    """Read a raw stored leniency value into a PfbLenient enum.

    Maps 'on' -> On, anything else (incl. None / '' / 'off') -> Off.
    Replicates pfb_global() :1364 normalisation.
    """
    if stored == "on":
        return PfbLenient.On
    return PfbLenient.default()


def pfb_cfg_lenient_write(lenient: PfbLenient) -> str:
    """Write a PfbLenient back to its stored string ('on' or 'off')."""
    return lenient.value
