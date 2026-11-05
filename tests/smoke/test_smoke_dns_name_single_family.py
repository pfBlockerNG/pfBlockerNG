"""Single-family VIP-only DNS Names own the missing address family locally."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

import pytest

from . import helpers
from .test_smoke_dns_gateway import (
    DDR_DNS_NAME,
    DNS_GENERAL_PAGE,
    _apply,
    _capture,
    _ensure_ddr,
    _parse_reply,
    _say,
)
from .test_smoke_dns_gateway import gateway_on as gateway_on
from .test_smoke_dns_gateway import go_toolchain as go_toolchain
from .test_smoke_dns_gateway import gui as gui
from .test_smoke_dns_gateway import gw as gw
from .test_smoke_dns_gateway import probe_binary as probe_binary
from .ui.test_dns_general_foreign_list_warning import _put, _snapshot

if TYPE_CHECKING:
    from .conftest import SmokeVM
    from .test_smoke_dns_gateway import Gateway
    from .test_smoke_dns_proxy import State
    from .ui.webui import WebUI

pytestmark = [pytest.mark.smoke, pytest.mark.timeout(900)]


def _check_name_pair(vm: SmokeVM, targets: list[str], pair: tuple[str | None, str | None], phase: str) -> None:
    kinds = ("AAAA", "A") if pair[0] is None else ("A", "AAAA")
    for address in targets:
        for transport in ("udp", "tcp"):
            for kind in kinds:
                expected = pair[0 if kind == "A" else 1]
                args = ["/usr/bin/timeout", "-s", "TERM", "-k1", "5", "/usr/bin/drill", "-b1232"]
                args += ["-6", "-I::1"] if ":" in address else ["-I127.0.0.1"]
                if transport == "tcp":
                    args.append("-t")
                args += ["-p", "53", DDR_DNS_NAME, f"@{address}", kind]
                result = vm.ssh(*args)
                raw = result.stdout + result.stderr
                _say(f"{phase} {transport} {kind} at {address}:53\n{raw}")
                assert result.returncode == 0, raw
                assert re.search(rf"^;;\s*{re.escape(DDR_DNS_NAME)}\.\s+IN\s+{kind}\s*$", raw, re.MULTILINE), raw
                reply = _parse_reply(raw)
                assert reply.rcode == "NOERROR" and {"qr", "rd"} <= reply.flags, raw
                if expected is not None:
                    answers = [ipaddress.ip_address(row.rdata) for row in reply.answer if row.rtype == kind]
                    assert answers == [ipaddress.ip_address(expected)], raw
                    assert len(reply.answer) == 1 and not reply.authority, raw
                else:
                    assert "aa" in reply.flags and not reply.answer, raw
                    assert len(reply.authority) == 1, raw
                    soa = reply.authority[0]
                    assert (soa.owner, soa.ttl, soa.rtype) == (f"{DDR_DNS_NAME}.", 300, "SOA"), raw
                    assert soa.rdata.split()[-1] == "300", raw
                    assert re.search(rf"^{re.escape(DDR_DNS_NAME)}\.\s+300\s+IN\s+SOA\s+", raw, re.MULTILINE), raw


@pytest.mark.parametrize("family", (4, 6), ids=("ipv4-only", "ipv6-only"))
def test_vip_only_single_family_name_returns_owned_nodata(
    gw: Gateway, gateway_on: State, gui: WebUI, family: int
) -> None:
    """A missing owned family must not delegate the Name or return an upstream address."""
    vm = gw.vm
    _ensure_ddr(gw, on=True)
    advertisements = {path: _snapshot(vm, path) for path in ("dhcpd", "dhcpdv6")}

    def select_families(v4: str, v6: str) -> tuple[str, str]:
        response = gui.post(
            DNS_GENERAL_PAGE,
            {
                "pfb_dns_listen_vip": "on",
                "pfb_dns_listen_vip_only": "on",
                "pfb_dns_listen_vip4": v4,
                "pfb_dns_listen_vip6": v6,
                "pfb_dns_listen_interface": "lo0",
            },
        )
        assert response.status_code == 200, response.text
        assert helpers.config_get(vm, f"{helpers.CFG_GLOBAL}/pfb_dns_listen_vip_only") == "on", response.text
        _apply(vm)
        return (
            helpers.config_get(vm, f"{helpers.CFG_GLOBAL}/pfb_dns_listen_auto4"),
            helpers.config_get(vm, f"{helpers.CFG_GLOBAL}/pfb_dns_listen_auto6"),
        )

    try:
        full = select_families("auto", "auto")
        assert all(full), f"dual-stack Resolver VIP fixture missing: {full}"
        _check_name_pair(vm, [*full, "127.0.0.1", "::1"], full, "dual-pair before single-family")
        # The other family must not advertise an ordinary address while no VIP serves it.
        _put(vm, "dhcpdv6" if family == 4 else "dhcpd", {})
        current = select_families("auto" if family == 4 else "none", "auto" if family == 6 else "none")
        active = current[0 if family == 4 else 1]
        assert active, f"IPv{family} Resolver VIP fixture missing: {current}"
        sockets = _capture(vm).proxy_sockets()
        assert {(f"udp{family}", f"{active}:53"), (f"tcp{family}", f"{active}:53")} <= sockets, sockets
        removed = full[1 if family == 4 else 0]
        assert not any(local == f"{removed}:53" for _, local in sockets), sockets
        expected = (active, None) if family == 4 else (None, active)
        _check_name_pair(vm, [active, "127.0.0.1", "::1"], expected, f"IPv{family}-only")
    finally:
        try:
            restored = select_families("auto", "auto")
            assert all(restored), f"restored dual-stack Resolver VIP fixture missing: {restored}"
            _check_name_pair(vm, [*restored, "127.0.0.1", "::1"], restored, "dual-pair restored")
        finally:
            try:
                gui.post(
                    DNS_GENERAL_PAGE,
                    {
                        "pfb_dns_listen_vip": "",
                        "pfb_dns_listen_vip_only": "",
                        "pfb_dns_listen_vip4": "none",
                        "pfb_dns_listen_vip6": "none",
                    },
                )
            finally:
                for path, original in advertisements.items():
                    _put(vm, path, original)
                _apply(vm)
