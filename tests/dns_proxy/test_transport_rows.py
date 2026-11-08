"""Original listener transport survives IPC and the existing module row writers (#3751)."""

from __future__ import annotations

import asyncio
import csv
import logging
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace

import decision_service
import dnswire
import pfb_dns_proxy
import pytest
import test_reply_log
import unbound_shim as shim
from frontend_constants import ALLOWED, BLOCKED, Booted
from frontend_helpers import FakeUnbound, build_query
from test_reply_log import Logged

NAMES = ("TCP", "UDP", "DoT", "DoH", "DoQ")
ZONE = {(ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"]}
replylog = test_reply_log.replylog


def rows(feed: Iterable[tuple[str, str]]) -> list[tuple[str, list[str]]]:
    return [(path, next(csv.reader([line]))) for path, line in feed]


@pytest.mark.parametrize("byte,name", list(enumerate(NAMES)))
def test_query_parser_preserves_five_distinct_transports(byte: int, name: str) -> None:
    assert decision_service._split_query(bytes([byte, 9]) + b"192.0.2.1\x00\x00\x00wire") == (
        name,
        b"192.0.2.1",
        b"",
        b"",
        b"wire",
    )


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x05\x01x", b"\xff\x01x", b"\x00\x00", b"\x00\x02x"])
def test_malformed_query_metadata_is_protocol_error(payload: bytes) -> None:
    with pytest.raises(decision_service.ProtocolError):
        decision_service._split_query(payload)


@pytest.mark.parametrize("ip", [b"\xff", b"not-an-ip", b"192.0.2.1/24"])
def test_invalid_ip_text_is_not_resolved(ip: bytes) -> None:
    assert decision_service._client_ip(ip) is None


@pytest.mark.parametrize("transport", NAMES)
@pytest.mark.parametrize("blocked", [False, True], ids=["allowed", "blocked"])
def test_real_module_rows_preserve_original_transport(booted: Booted, transport: str, blocked: bool) -> None:
    name = BLOCKED if blocked else ALLOWED
    client = "2001:db8::12" if transport in ("UDP", "DoH") else "192.0.2.12"
    wire = asyncio.run(
        pfb_dns_proxy.Frontend(booted.module).resolve(build_query(name), client, FakeUnbound(ZONE), transport=transport)
    )
    assert dnswire.parse(wire).answers
    [(path, row)] = rows(booted.log)
    assert path.endswith("dnsbl.log" if blocked else "dns_reply.log")
    assert len(row) == (14 if blocked else 13)
    assert row[3 if blocked else 7] == client
    assert row[-3:] == [transport, "", ""]
    assert row[10 if blocked else 3] == "A"


@pytest.mark.parametrize("transport", NAMES)
@pytest.mark.parametrize("outcome,count", [("success", 1), ("servfail", 2), ("silent", 1)])
def test_no_module_logger_keeps_transport_and_existing_event_count(
    replylog: Logged, transport: str, outcome: str, count: int
) -> None:
    query = build_query(ALLOWED)

    async def forward(wire: bytes) -> bytes | None:
        if outcome == "silent":
            return None
        answer = await FakeUnbound(ZONE)(wire)
        if outcome == "servfail":
            answer = answer[:3] + bytes([(answer[3] & 0xF0) | 2]) + answer[4:]
        return answer

    wire = asyncio.run(
        pfb_dns_proxy.Frontend(None, replylog.log).resolve(query, "2001:db8::12", forward, transport=transport)
    )
    assert dnswire.parse(wire).rcode == (0 if outcome == "success" else 2)
    emitted = rows(replylog.rows)
    assert len(emitted) == count
    assert all(len(row) == 13 and row[-3:] == [transport, "", ""] for _, row in emitted)


@pytest.mark.parametrize(
    "value",
    [None, "", 1, [], {}, " UDP", "UDP ", "UDP,TCP", "UDP\r\nTCP", "<b>UDP</b>", "ÜDP", "U" * 10000],
)
def test_untrusted_metadata_is_unknown_without_row_injection(booted: Booted, value: object) -> None:
    module = booted.module
    qstate = shim.module_qstate(shim.query_info(ALLOWED, dnswire.TYPE_A), "192.0.2.12")
    qstate.pfb_transport = value
    module.get_details_reply("cache", None, qstate, None, {"pfb_addr": "192.0.2.12", "pfb_transport": value})
    [(_, row)] = rows(booted.log)
    assert len(row) == 13 and row[-3:] == ["Unknown", "", ""]


@pytest.mark.parametrize("kind", ["reply_cache", "reply_local", "reply_servfail"])
@pytest.mark.parametrize("transport", ["DoQ", None])
def test_callbacks_preserve_shim_metadata_or_unknown_native(booted: Booted, kind: str, transport: str | None) -> None:
    qstate = shim.module_qstate(shim.query_info(ALLOWED, dnswire.TYPE_A), "192.0.2.12")
    if transport is not None:
        qstate.pfb_transport = transport
    shim.fire_reply_callback(kind, qstate, None, 2 if kind == "reply_servfail" else 0)
    [(_, row)] = rows(booted.log)
    assert row[-3:] == [transport or "Unknown", "", ""]
    assert row[2] == kind.removeprefix("reply_")


def test_explicit_kwargs_and_historical_native_api(booted: Booted) -> None:
    module = booted.module
    assert module.get_q_transport(SimpleNamespace(), None) == "Unknown"
    assert module.get_q_transport(None, None) == "Unknown"
    for transport in NAMES:
        assert module.get_q_transport(None, {"pfb_transport": transport}) == transport


@pytest.mark.parametrize("transport", ["DoH", "Unknown"])
def test_idn_and_upstream_writers_append_same_dnsbl_column(booted: Booted, transport: str) -> None:
    module = booted.module
    module._log_idn_alert("xn--test.example", "192.0.2.12", ("feed", "group", "display"), "AAAA", transport)
    module._log_upstream_block(ALLOWED, "192.0.2.12", module.UpstreamBlock("NXRA", "NXRA", ""), "A", transport)
    emitted = rows(booted.log)
    assert len(emitted) == 2
    assert [row[5] for _, row in emitted] == ["Homoglyph_Alert", "Upstream_Block"]
    assert all(len(row) == 14 and row[-3:] == [transport, "", ""] for _, row in emitted)
    assert [row[10] for _, row in emitted] == ["AAAA", "A"]


def test_native_observer_does_not_guess_transport(booted: Booted) -> None:
    module = booted.module
    module.pfb["forwarding"] = True
    qstate, response = pfb_dns_proxy._upstream_report(
        b'{"client":"192.0.2.12","qname":"allowed.example.","qtype":1,"flags":32771,"opts":[]}'
    )
    module.inplace_cb_query_response(qstate, response)
    [(_, row)] = rows(booted.log)
    assert len(row) == 14 and row[-3:] == ["Unknown", "", ""] and row[5] == "Upstream_Block"


def test_logging_disabled_still_answers_without_rows(booted: Booted) -> None:
    booted.module.pfb["python_reply"] = False
    answer = asyncio.run(
        pfb_dns_proxy.Frontend(booted.module).resolve(
            build_query(ALLOWED), "192.0.2.12", FakeUnbound(ZONE), transport="DoT"
        )
    )
    assert dnswire.parse(answer).answers
    assert not booted.log


def test_logger_failure_does_not_change_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    from dns_reply_log import ReplyLog

    reply_log = ReplyLog()
    handler = logging.FileHandler(tmp_path, delay=True)
    logger = logging.Logger("transport-row-failure", logging.INFO)
    logger.addHandler(handler)
    monkeypatch.setitem(reply_log.module.pfb_loggers, "/var/log/pfblockerng/dns_reply.log", logger)
    query = build_query(ALLOWED)
    upstream = FakeUnbound(ZONE)
    expected = asyncio.run(upstream(query))
    try:
        actual = asyncio.run(
            pfb_dns_proxy.Frontend(None, reply_log).resolve(query, "192.0.2.12", upstream, transport="DoH")
        )
        assert actual == expected
        error = capfd.readouterr().err
        assert "DNS Reply logging failed" in error
        assert "IsADirectoryError" in error
        assert str(tmp_path) in error
        assert "get_details_reply" in error and "pfb_log" in error
        assert handler.stream is None
    finally:
        handler.close()
        reply_log.close()


@pytest.mark.parametrize("blocked", [False, True], ids=["allowed", "blocked"])
def test_frontend_endpoint_reaches_real_module_qstate(
    booted: Booted, monkeypatch: pytest.MonkeyPatch, blocked: bool
) -> None:
    module = booted.module
    operate = module.operate
    seen = []

    def record(module_id: int, event: int, qstate: shim.module_qstate, qdata: object) -> bool:
        seen.append((qstate.pfb_listener_ip, qstate.pfb_listener_interface))
        return operate(module_id, event, qstate, qdata)

    monkeypatch.setattr(module, "operate", record)
    interface = '内网, "guest"\\vlan'
    wire = asyncio.run(
        pfb_dns_proxy.Frontend(module).resolve(
            build_query(BLOCKED if blocked else ALLOWED),
            "192.0.2.12",
            FakeUnbound(ZONE),
            transport="DoH",
            listener_ip="2001:db8::53",
            listener_interface=interface,
        )
    )
    assert dnswire.parse(wire).answers
    assert seen == [("2001:db8::53", interface)] * (1 if blocked else 2)


@pytest.mark.parametrize("outcome", ["success", "servfail", "silent"])
def test_no_module_endpoint_reaches_shared_reply_writer(
    replylog: Logged, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    shared = replylog.log.module.get_details_reply
    seen = []

    def record(m_type: str, qinfo: object, qstate: object, rep: object, kwargs: dict) -> bool:
        seen.append((kwargs.get("pfb_listener_ip", "<missing>"), kwargs.get("pfb_listener_interface", "<missing>")))
        return shared(m_type, qinfo, qstate, rep, kwargs)

    monkeypatch.setattr(replylog.log.module, "get_details_reply", record)

    async def forward(wire: bytes) -> bytes | None:
        if outcome == "silent":
            return None
        answer = await FakeUnbound(ZONE)(wire)
        if outcome == "servfail":
            answer = answer[:3] + bytes([(answer[3] & 0xF0) | 2]) + answer[4:]
        return answer

    interface = '内网, "guest"\\vlan'
    answer = asyncio.run(
        pfb_dns_proxy.Frontend(None, replylog.log).resolve(
            build_query(ALLOWED),
            "192.0.2.12",
            forward,
            transport="DoT",
            listener_ip="2001:db8::53",
            listener_interface=interface,
        )
    )
    assert dnswire.parse(answer).rcode == (0 if outcome == "success" else 2)
    assert seen == [("2001:db8::53", interface)] * (2 if outcome == "servfail" else 1)


def test_observer_endpoint_is_unavailable_not_inferred_from_client() -> None:
    qstate, _ = pfb_dns_proxy._upstream_report(
        b'{"client":"192.0.2.12","qname":"allowed.example.","qtype":1,"flags":32771,"opts":[]}'
    )
    assert (
        getattr(qstate, "pfb_listener_ip", "<missing>"),
        getattr(qstate, "pfb_listener_interface", "<missing>"),
    ) == (
        "",
        "",
    )
