"""Optional counter authority must never admit or reject DNS filtering service."""

from __future__ import annotations

import asyncio
import ipaddress
import sys
from pathlib import Path

import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import ALLOWED, BLOCKED, DNSBL_IPV4, LogFeed
from frontend_helpers import FakeUnbound, build_query


@pytest.mark.parametrize("accounting", ["uninitialized", "unavailable", "read_failure"])
def test_real_boot_and_resolve_do_not_depend_on_counter_authority(
    accounting: str, module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if accounting == "unavailable":
        (module_dir / "pfb_py_dnsbl.sqlite").mkdir()
    monkeypatch.chdir(module_dir)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    module = pfb_dns_proxy.boot(str(module_dir))
    log = LogFeed()
    monkeypatch.setattr(module, "pfb_log", lambda name, line: log.append((name, line)))
    try:
        diagnostic = {
            "state": accounting,
            "sqlite_available": module.pfb["mod_sqlite3"],
            "counter_connection": module.pfb["sqlite3_dnsbl_con"],
            "dns_snapshot": hasattr(module, "_snapshot"),
        }
        if accounting == "read_failure":
            connection = module._db_conns[module.DB_DNSBL]
            connection.execute("DROP TABLE dnsbl_group_epochs")
            connection.commit()
            assert module.rebuild_and_swap(module._build_swap_snapshot, emit_counts=False), (
                "counter read failure must not reject a DNS filtering snapshot"
            )
        upstream = FakeUnbound({(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]})
        frontend = pfb_dns_proxy.Frontend(module)
        blocked_wire = asyncio.run(frontend.resolve(build_query(BLOCKED), "192.0.2.10", upstream, transport="UDP"))
        assert blocked_wire is not None
        blocked = dnswire.parse(blocked_wire)
        assert blocked.rcode == 0, (diagnostic, blocked)
        assert [answer.rdata for answer in blocked.answers] == [ipaddress.IPv4Address(DNSBL_IPV4).packed]
        assert upstream.queries == [], "blocked DNS must not become a relay when accounting is unavailable"
        allowed_wire = asyncio.run(frontend.resolve(build_query(ALLOWED), "192.0.2.10", upstream, transport="UDP"))
        assert allowed_wire is not None
        allowed = dnswire.parse(allowed_wire)
        assert allowed.rcode == 0, (diagnostic, allowed)
        assert [answer.rdata for answer in allowed.answers] == [bytes([192, 0, 2, 77])]
        assert module._snapshot.group_epochs.get(("TestGroup", "custom")) is None, (
            "uninitialized custom authority must not be invented to keep DNS working"
        )
    finally:
        pfb_dns_proxy.shutdown(module)
