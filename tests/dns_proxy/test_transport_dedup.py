"""A different original transport is a distinct DNSBL event (#3751)."""

from __future__ import annotations

import asyncio
import csv

import pfb_dns_proxy
from frontend_constants import BLOCKED, Booted
from frontend_helpers import FakeUnbound, build_query


def test_transport_changes_do_not_hide_block_rows(booted: Booted) -> None:
    frontend = pfb_dns_proxy.Frontend(booted.module)
    for transport in ("UDP", "DoH", "DoH"):
        asyncio.run(frontend.resolve(build_query(BLOCKED), "192.0.2.12", FakeUnbound({}), transport=transport))
    rows = [next(csv.reader([line])) for _, line in booted.log]
    assert [row[9] for row in rows] == ["+", "+", "-"]
    assert all(len(row) == 14 and row[-2:] == ["", ""] for row in rows)
    assert [row[11] for row in rows] == ["UDP", "DoH", "DoH"]
