"""Pin the smoke-harness boot defaults for the two-VM topology (ADR-04 / ADR-24).

``tests/smoke/conftest.py`` boots exclusively via ``boot_vm.sh``, which takes a
``--role pfsense|client`` selector and is parameterized by env:

* ``SMOKE_VM_MAC`` — the pfSense NIC MAC(s). CE identity is don't-care, so when
  unset it falls back to the pinned CE source-VM 8-MAC list (``DEFAULT_CE_MAC``,
  one per NIC in order). A pfSense Plus image overrides it with the
  license/NDI-keyed, NEWLINE-separated 8-MAC list, split per-NIC by ``nth_mac``.
  The Plus values come from the SMOKE_PLUS_* secrets, never the public matrix.
* ``SMOKE_VM_SMBIOS_UUID`` — SMBIOS type-1 uuid. CE pins the public source-VM
  uuid; a Plus image overrides it (its NDI is derived from MAC + uuid).
* ``SMOKE_CLIENT_MAC_ADDRESS`` — the civm data-NIC MAC, matched by pfSense's
  static DHCP lease so the client always gets 192.168.1.10.

These tests read ``boot_vm.sh`` as text (no QEMU/VM needed) and pin the
load-bearing topology contract: the management/LAN/WAN addressing the harness
and the image agree on, and the identity override forms.
"""

from __future__ import annotations

from pathlib import Path

# The CE source-VM SMBIOS type-1 uuid pin (also in boot_vm.sh's header + the ADR).
# CE pins the public source-VM uuid; a Plus image overrides via
# SMOKE_VM_SMBIOS_UUID (its NDI is derived from MAC + uuid, so the uuid is as
# license-keyed as the MAC and comes from the SMOKE_PLUS_SMBIOS_UUID secret).
CE_DEFAULT_SMBIOS_UUID = "58fd7964-c40c-4f47-bf02-3fdad18f8b00"

# The static management IP baked into every pfSense image — the host->guest
# ssh/web forwards target it, so a drift here silently breaks the control path.
PFSENSE_MGMT_IP = "10.0.0.20"

_BOOT_VM_SH = Path(__file__).resolve().parent.parent / "tests" / "smoke" / "boot_vm.sh"


def _boot_vm_text() -> str:
    return _BOOT_VM_SH.read_text(encoding="utf-8")


# The CE source VM's 8 NIC MACs (net0..net7, in order), committed in boot_vm.sh
# as non-secret defaults so a CE boot mirrors the source hardware. net0 is the
# long-standing WAN pin. A MAC is not sensitive; the Plus NDI identity is, and
# stays in the SMOKE_PLUS_MAC secret.
CE_DEFAULT_MACS = (
    "BC:24:11:37:9C:AC",
    "BC:24:11:80:42:35",
    "BC:24:11:D6:90:DD",
    "BC:24:11:FB:41:8A",
    "BC:24:11:2D:95:0A",
    "BC:24:11:36:D3:34",
    "BC:24:11:02:0B:68",
    "BC:24:11:46:D1:DE",
)


def test_vm_mac_defaults_to_ce_source_macs() -> None:
    """VM_MAC defaults to the CE source VM's 8 NIC MACs; SMOKE_VM_MAC overrides.

    With SMOKE_VM_MAC empty/unset the expansion falls back to the committed
    DEFAULT_CE_MAC list, so each NIC gets its source MAC (net0..net7 in order). A
    Plus run sets SMOKE_VM_MAC to its NDI-keyed list, taking precedence (the
    per-NIC split is pinned by the test below). Pins the fallback form and every
    default MAC, in NIC order.
    """
    text = _boot_vm_text()
    assert 'VM_MAC="${SMOKE_VM_MAC:-$DEFAULT_CE_MAC}"' in text
    # Every CE default MAC present, in NIC order, within the DEFAULT_CE_MAC block.
    block = text[text.index("DEFAULT_CE_MAC=") :]
    last = -1
    for mac in CE_DEFAULT_MACS:
        pos = block.find(mac)
        assert pos != -1, f"missing CE default MAC {mac}"
        assert pos > last, f"CE default MAC {mac} out of NIC order"
        last = pos


def test_plus_mac_list_split_per_nic() -> None:
    """The MAC list is split per-NIC by line (Plus: 8 MACs, one per NIC in order).

    ``nth_mac`` selects the Nth line of the newline-separated SMOKE_VM_MAC, and
    the device is emitted WITH ``mac=`` only when that line is non-empty (CE
    omits it). Pins the split mechanism + the conditional application.
    """
    text = _boot_vm_text()
    assert "nth_mac()" in text
    assert "printf '%s\\n' \"$VM_MAC\" | sed -n" in text
    assert 'mac="$(nth_mac "$i")"' in text


def test_client_nic_macs_default_with_env_override() -> None:
    """The civm NICs default to the source VM's MACs; env overrides each.

    net1 (data) connects to the pfSense LAN socket and carries the static-lease
    MAC so the DHCP mapping hands the client 192.168.1.10; net0 (management) gets
    its own MAC. Both have committed defaults, overridable via
    SMOKE_CLIENT_MAC_ADDRESS / SMOKE_CLIENT_MGMT_MAC — so the client role needs
    no env to boot.
    """
    text = _boot_vm_text()
    assert 'CLIENT_MGMT_MAC="${SMOKE_CLIENT_MGMT_MAC:-BC:24:11:29:A4:1B}"' in text
    assert 'CLIENT_MAC="${SMOKE_CLIENT_MAC_ADDRESS:-02:49:E4:CE:92:72}"' in text


def test_client_smbios_uuid_default_with_env_override() -> None:
    """civm SMBIOS type-1 uuid defaults to the civm source VM's; env overrides.

    Mirrors the pfSense SMBIOS pin: the client role boots with a stable SMBIOS
    uuid (so machine-id / DHCP identity stay stable across overlay boots),
    overridable via SMOKE_CLIENT_SMBIOS_UUID. The arg is applied for the client
    role (`-smbios type=1,uuid=...`).
    """
    text = _boot_vm_text()
    assert 'CLIENT_SMBIOS_UUID="${SMOKE_CLIENT_SMBIOS_UUID:-7dc13783-e65c-4f62-8fd8-45eeae4c77b9}"' in text
    assert "type=1,uuid=${CLIENT_SMBIOS_UUID}" in text


def test_pfsense_management_path_targets_static_ip() -> None:
    """The host->guest ssh/web forwards target the image's static management IP.

    The forwards live on net1 (management, 10.0.0.0/16) and point at
    10.0.0.20 — the harness control path. A drift in either the subnet or the IP
    would break SSH/Web reachability.
    """
    text = _boot_vm_text()
    assert f'PFSENSE_MGMT_IP="{PFSENSE_MGMT_IP}"' in text
    assert "net=10.0.0.0/16" in text
    assert "hostfwd=tcp::${SSH_HOSTPORT}-${PFSENSE_MGMT_IP}:22" in text


def test_pfsense_wan_and_lan_topology() -> None:
    """WAN is the 10.10.0.0/24 runner-services net; LAN is the socket crossover.

    The guest reaches the runner-side mock servers via the WAN host alias
    10.10.0.2; the LAN (net2) is a QEMU socket LISTENER that the civm data NIC
    connects to. Pins both addressing facts the rest of the harness assumes.
    """
    text = _boot_vm_text()
    assert "net=10.10.0.0/24,host=10.10.0.2" in text
    assert "socket,id=net2,listen=127.0.0.1:${LAN_SOCKET_PORT}" in text
    assert "socket,id=net1,connect=127.0.0.1:${LAN_SOCKET_PORT}" in text


def test_ce_default_smbios_uuid_pin_present() -> None:
    """The CE source-VM SMBIOS uuid pin is present in boot_vm.sh.

    Regression pin: the documented CE source-VM SMBIOS uuid must stay the harness
    default; a typo'd or drifted pin would drop it and fail. It legitimately
    appears more than once (header comment + assignment), so this asserts
    presence, not a count.
    """
    text = _boot_vm_text()
    assert CE_DEFAULT_SMBIOS_UUID in text


def test_vm_smbios_uuid_is_env_override_with_ce_default() -> None:
    """VM_SMBIOS_UUID is the SMOKE_VM_SMBIOS_UUID override form, defaulting to the CE uuid.

    With SMOKE_VM_SMBIOS_UUID unset the expansion yields the CE pin; a Plus run
    sets SMOKE_VM_SMBIOS_UUID (from the SMOKE_PLUS_SMBIOS_UUID secret) to override
    it. Both branches covered: CE (unset -> pin) by the presence test above, Plus
    (set -> override) by this override-form assertion.
    """
    text = _boot_vm_text()
    expected = f'VM_SMBIOS_UUID="${{SMOKE_VM_SMBIOS_UUID:-{CE_DEFAULT_SMBIOS_UUID}}}"'
    assert expected in text
