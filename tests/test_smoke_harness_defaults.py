"""Pin the smoke-harness boot defaults that ADR-24 parameterizes.

The pfSense Plus smoke image (ADR-24) must boot with ITS source-VM MAC, distinct
from the CE pin, because pfSense matches interface assignment by MAC AND the Plus
license/NDI registration is keyed to it. ``tests/smoke/conftest.py`` boots
exclusively via ``boot_vm.sh``, so a single ``SMOKE_VM_MAC`` env override
parameterizes the whole harness while keeping CE byte-identical when unset.

These tests read ``boot_vm.sh`` as text (no QEMU/VM needed) and pin:

* the CE default MAC string is present — a regression pin guarding against
  accidental drift of the documented CE source-VM MAC (it appears in both the
  header comment and the assignment); and
* the assignment is the env-override form ``${SMOKE_VM_MAC:-<CE pin>}`` — so a
  Plus run can override it while CE keeps the pin as the default.

Both branches of the override are covered: CE (env unset -> pin) by the default
string assertion, Plus (env set -> override) by the override-form assertion.
"""

from __future__ import annotations

from pathlib import Path

# The CE source-VM MAC pin (also documented in boot_vm.sh's header + the ADR).
CE_DEFAULT_MAC = "BC:24:11:37:9C:AC"

_BOOT_VM_SH = Path(__file__).resolve().parent.parent / "tests" / "smoke" / "boot_vm.sh"


def _boot_vm_text() -> str:
    return _BOOT_VM_SH.read_text(encoding="utf-8")


def test_ce_default_mac_pin_present() -> None:
    """The CE source-VM MAC pin is present in boot_vm.sh.

    Regression pin: the documented CE source-VM MAC must stay the harness
    default; a typo'd or drifted pin would drop it and fail. (It legitimately
    appears more than once — the header comment plus the assignment default —
    so this asserts presence, not a count.)
    """
    text = _boot_vm_text()
    assert CE_DEFAULT_MAC in text


def test_vm_mac_is_env_override_with_ce_default() -> None:
    """VM_MAC is the SMOKE_VM_MAC override form, defaulting to the CE pin.

    With SMOKE_VM_MAC unset the expansion yields the CE pin (default path,
    byte-identical to pre-ADR-24); a Plus run sets SMOKE_VM_MAC to override it.
    """
    text = _boot_vm_text()
    expected = f'VM_MAC="${{SMOKE_VM_MAC:-{CE_DEFAULT_MAC}}}"'
    assert expected in text
