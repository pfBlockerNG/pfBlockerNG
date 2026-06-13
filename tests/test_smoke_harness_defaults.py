"""Pin the smoke-harness boot defaults that ADR-24 parameterizes.

The pfSense Plus smoke image (ADR-24) must boot with ITS source-VM identity (NIC
MAC + SMBIOS type-1 uuid), distinct from the CE pins, because pfSense matches
interface assignment by MAC AND the Plus license/NDI registration is keyed to the
MAC + uuid pair (the NDI is derived from both). ``tests/smoke/conftest.py`` boots
exclusively via ``boot_vm.sh``, so single ``SMOKE_VM_MAC`` / ``SMOKE_VM_SMBIOS_UUID``
env overrides parameterize the whole harness while keeping CE byte-identical when
unset (the Plus values come from the SMOKE_PLUS_* secrets, never the public matrix).

These tests read ``boot_vm.sh`` as text (no QEMU/VM needed) and pin, for BOTH the
MAC and the SMBIOS uuid:

* the CE default string is present — a regression pin guarding against accidental
  drift of the documented CE source-VM value (each appears in both the header
  comment and the assignment); and
* the assignment is the env-override form ``${SMOKE_VM_*:-<CE pin>}`` — so a Plus
  run can override it while CE keeps the pin as the default.

Both branches of each override are covered: CE (env unset -> pin) by the default
string assertion, Plus (env set -> override) by the override-form assertion.
"""

from __future__ import annotations

from pathlib import Path

# The CE source-VM MAC pin (also documented in boot_vm.sh's header + the ADR).
CE_DEFAULT_MAC = "BC:24:11:37:9C:AC"
# The CE source-VM SMBIOS type-1 uuid pin. Like the MAC it is per-image: CE pins
# the public source-VM uuid; a Plus image overrides via SMOKE_VM_SMBIOS_UUID (its
# NDI is derived from MAC + uuid, so the uuid is as license-keyed as the MAC and
# comes from the SMOKE_PLUS_SMBIOS_UUID secret, never the public matrix).
CE_DEFAULT_SMBIOS_UUID = "58fd7964-c40c-4f47-bf02-3fdad18f8b00"

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


def test_ce_default_smbios_uuid_pin_present() -> None:
    """The CE source-VM SMBIOS uuid pin is present in boot_vm.sh.

    Regression pin (mirror of the MAC pin): the documented CE source-VM SMBIOS
    uuid must stay the harness default; a typo'd or drifted pin would drop it and
    fail. It legitimately appears more than once (header comment + assignment),
    so this asserts presence, not a count.
    """
    text = _boot_vm_text()
    assert CE_DEFAULT_SMBIOS_UUID in text


def test_vm_smbios_uuid_is_env_override_with_ce_default() -> None:
    """VM_SMBIOS_UUID is the SMOKE_VM_SMBIOS_UUID override form, defaulting to the CE uuid.

    With SMOKE_VM_SMBIOS_UUID unset the expansion yields the CE pin (default path,
    byte-identical to pre-ADR-24); a Plus run sets SMOKE_VM_SMBIOS_UUID (from the
    SMOKE_PLUS_SMBIOS_UUID secret) to override it. Both branches of the override are
    covered: CE (env unset -> pin) by the default-string assertion above, Plus (env
    set -> override) by this override-form assertion.
    """
    text = _boot_vm_text()
    expected = f'VM_SMBIOS_UUID="${{SMOKE_VM_SMBIOS_UUID:-{CE_DEFAULT_SMBIOS_UUID}}}"'
    assert expected in text
