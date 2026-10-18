"""pfB-DNS with DNSBL off writes the existing DNS Reply log when the DNS Reply Logging preference is on (issue #3515).

`--no-module --reply-log` keeps the proxy a plain forwarder (no feeds, no decisions, no DNSBL lifecycle) and logs each
reply with the shipped pfb_unbound.py's own get_details_reply(), so dns_reply.log gets the rows, the escaping and the
columns that Reports and Stats already read. The module mode is the reference: every case below is pinned in BOTH modes
against the same expected rows (tests/fixtures/dns_reply_standalone_rows.json, which the PHP viewer tests read too).
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging.handlers
import os
import struct
import subprocess
import sys
import threading
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import dnswire
import pfb_dns_proxy
import pytest
import unbound_shim as shim
from frontend_constants import ALLOWED, REPO_ROOT, SHIPPED_DIR, Booted, LogFeed
from frontend_helpers import (
    WATCHDOG,
    FakeProxyUpstream,
    FakeUnbound,
    UpstreamVerdict,
    build_query,
    running_proxy,
    serving,
    udp_exchange,
)

if TYPE_CHECKING:
    import dns_reply_log

ROWS = json.loads((REPO_ROOT / "tests" / "fixtures" / "dns_reply_standalone_rows.json").read_text(encoding="utf-8"))
STAMP: str = ROWS["stamp"]
CLIENT: str = ROWS["client"]
LOG_FILE = "/var/log/pfblockerng/dns_reply.log"
CLIENT_ON_LOOPBACK = "127.0.0.2"  # 127.0.0.1 is the firewall itself, which the module logs as a "resolver" row
HOSTILE = "a,b\"c<d>\\010e&'.example."  # comma, quotes, markup, a newline (\010) and an ampersand in one name

ZONE = {
    (ALLOWED, dnswire.TYPE_A): [f"{ALLOWED} 300 IN A 192.0.2.77"],
    (ALLOWED, dnswire.TYPE_AAAA): [f"{ALLOWED} 300 IN AAAA 2001:db8::77"],
    (ALLOWED, dnswire.TYPE_TXT): [f'{ALLOWED} 300 IN TXT "hello world"'],
    (ALLOWED, dnswire.TYPE_SOA): [f"{ALLOWED} 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 60"],
    (ALLOWED, 255): [f"{ALLOWED} 300 IN A 192.0.2.77"],  # ANY
    ("alias.example.", dnswire.TYPE_A): [
        "alias.example. 300 IN CNAME allowed.example.",
        f"{ALLOWED} 300 IN A 192.0.2.77",
    ],
    ("nodata.example.", dnswire.TYPE_AAAA): [],  # the name exists, no AAAA
    ("geo.example.", dnswire.TYPE_A): ["geo.example. 300 IN A 8.8.8.8"],
    ("lan.example.", dnswire.TYPE_A): ["lan.example. 300 IN A 10.1.2.3"],
}
VERDICTS = {  # what the upstream says, whatever the table holds
    "refused.example.": UpstreamVerdict(rcode=5),
    "servfail.example.": UpstreamVerdict(rcode=2),
    "nxd.example.": UpstreamVerdict(rcode=3),
    "nxcname.example.": UpstreamVerdict(rcode=3, answers=("{name} 300 IN CNAME allowed.example.",)),
}


@dataclass(frozen=True)
class Case:
    qname: str
    qtype: int = dnswire.TYPE_A
    silent: bool = False  # Unbound never answers


CASES = {
    "a": Case(ALLOWED),
    "aaaa": Case(ALLOWED, dnswire.TYPE_AAAA),
    "txt": Case(ALLOWED, dnswire.TYPE_TXT),
    "soa": Case(ALLOWED, dnswire.TYPE_SOA),
    "any": Case(ALLOWED, 255),
    "cname-chain": Case("alias.example."),
    "nxdomain": Case("nx.example."),
    "nxdomain-with-soa": Case("nxd.example."),
    "nxdomain-with-cname": Case("nxcname.example."),
    "no-answer": Case("nodata.example.", dnswire.TYPE_AAAA),
    "refused": Case("refused.example."),
    "servfail-from-unbound": Case("servfail.example."),
    "unbound-silent": Case("silent.example.", silent=True),
    "hostile-name": Case(HOSTILE),
}

Forward = Callable[[bytes], Awaitable[bytes | None]]


async def _silent(_wire: bytes) -> None:
    return None


def _upstream(case: Case) -> Forward:
    if case.silent:
        return _silent
    unbound = FakeUnbound(ZONE)
    unbound.verdicts.update(VERDICTS)
    return unbound


def _ask(module: Any, qname: str, qtype: int, forward: Forward, **frontend: Any) -> bytes | None:
    asked = pfb_dns_proxy.Frontend(module, ("127.0.0.1", 9), timeout=WATCHDOG, **frontend)
    return asyncio.run(asked.resolve(build_query(qname, qtype), CLIENT, forward))


def _resolve(module: Any, case: Case, reply_log: Any = None) -> bytes | None:
    frontend = {} if reply_log is None else {"reply_log": reply_log}
    return _ask(module, case.qname, case.qtype, _upstream(case), **frontend)


def _lines(feed: list[tuple[str, str]]) -> list[str]:
    return [line for name, line in feed if name == LOG_FILE]


@dataclass
class Logged:
    log: dns_reply_log.ReplyLog
    rows: LogFeed


@pytest.fixture
def replylog(monkeypatch: pytest.MonkeyPatch) -> Iterator[Logged]:
    """The reply log as --no-module --reply-log starts it, from the shipped source: no module dir, no ini, no feed."""
    import dns_reply_log  # late: a proxy without it fails each test here for that reason

    log = dns_reply_log.ReplyLog()
    rows = LogFeed()
    monkeypatch.setattr(log.module, "pfb_log", lambda name, line: rows.append((name, line)))
    monkeypatch.setattr(log.module, "make_timestamp", lambda: STAMP)
    try:
        yield Logged(log, rows)
    finally:
        log.close()


class _RecordingHandler(logging.Handler):
    """Stands in for the WatchedFileHandler the module's log pipeline writes through: no file, every line kept."""

    made: ClassVar[list[_RecordingHandler]] = []

    def __init__(self, path: str, mode: str = "a", encoding: str | None = None, delay: bool = False) -> None:
        super().__init__()
        self.path = path
        self.delay = delay
        self.lines: list[str] = []
        self.made.append(self)

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def handlers(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[_RecordingHandler]]:
    _RecordingHandler.made.clear()
    monkeypatch.setattr(logging.handlers, "WatchedFileHandler", _RecordingHandler)
    yield _RecordingHandler.made
    _RecordingHandler.made.clear()


def _written(handlers: list[_RecordingHandler]) -> list[str]:
    return [line for handler in handlers if handler.path == LOG_FILE for line in handler.lines]


# --- the flag ----------------------------------------------------------------------------------------


def test_reply_log_is_off_unless_asked_for() -> None:
    assert pfb_dns_proxy.parse_args(["--no-module"]).reply_log is False
    assert pfb_dns_proxy.parse_args(["--no-module", "--reply-log"]).reply_log is True


def test_reply_log_is_refused_while_the_module_runs_because_the_module_has_its_own_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as refused:
        pfb_dns_proxy.parse_args(["--reply-log"])
    assert refused.value.code == 2
    assert "--reply-log needs --no-module" in capsys.readouterr().err


# --- the rows: the same in both modes ------------------------------------------------------------------------


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_module_mode_writes_these_rows(booted: Booted, monkeypatch: pytest.MonkeyPatch, case_id: str) -> None:
    monkeypatch.setattr(booted.module, "make_timestamp", lambda: STAMP)
    _resolve(booted.module, CASES[case_id])
    assert _lines(booted.log) == ROWS["rows"][case_id]


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_without_the_module_the_same_rows_are_written(replylog: Logged, case_id: str) -> None:
    _resolve(None, CASES[case_id], replylog.log)
    assert _lines(replylog.rows) == ROWS["rows"][case_id]


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_logging_never_changes_what_the_client_gets(replylog: Logged, case_id: str) -> None:
    logged = _resolve(None, CASES[case_id], replylog.log)
    assert logged is not None
    assert logged == _resolve(None, CASES[case_id])


def test_the_client_address_in_the_row_is_the_clients_not_the_proxys(replylog: Logged) -> None:
    _resolve(None, CASES["a"], replylog.log)
    assert next(csv.reader(_lines(replylog.rows)))[7] == CLIENT


def test_a_row_is_one_physical_line_with_ten_columns_for_the_php_readers_whatever_the_name(replylog: Logged) -> None:
    _resolve(None, CASES["hostile-name"], replylog.log)
    [line] = _lines(replylog.rows)
    assert "\n" not in line and "\r" not in line
    script = "echo json_encode(fgetcsv(STDIN, 0, ',', '\"', ''));"  # the readers' own call (pfblockerng_alerts.php)
    fields = json.loads(
        subprocess.run(["php", "-r", script], input=line, capture_output=True, check=True, text=True).stdout
    )
    assert len(fields) == 10 and fields[:2] == ["DNS-reply", STAMP]
    assert fields[7] == CLIENT
    assert not set("<>\"'&") & set(fields[6]), f"markup survives in the name column: {fields[6]!r}"


# --- boundaries: what is not a reply, and what must not break the answer --------------------------------


def test_a_reply_that_does_not_parse_is_relayed_as_it_is_and_logs_nothing(replylog: Logged) -> None:
    async def forward(_wire: bytes) -> bytes:
        return b"not even a DNS message"

    assert _ask(None, ALLOWED, dnswire.TYPE_A, forward, reply_log=replylog.log) == b"not even a DNS message"
    assert _lines(replylog.rows) == []


def test_a_refused_reply_of_a_header_alone_is_relayed_as_it_is_and_logged_as_refused(replylog: Logged) -> None:
    # Unbound's access-control REFUSED carries no question section at all
    refused = struct.pack("!HHHHHH", 0x1234, dnswire.QR | dnswire.RD | dnswire.RA | 5, 0, 0, 0, 0)

    async def forward(_wire: bytes) -> bytes:
        return refused

    assert _ask(None, ALLOWED, dnswire.TYPE_A, forward, reply_log=replylog.log) == refused
    [row] = (next(csv.reader([line])) for line in _lines(replylog.rows))
    assert (row[2], row[6], row[7], row[8]) == ("reply", "allowed.example", CLIENT, "Refused")


def test_a_reply_too_short_for_a_header_is_the_proxys_servfail_and_one_row(replylog: Logged) -> None:
    async def forward(_wire: bytes) -> bytes:
        return b"\x00\x01"

    reply = dnswire.parse(_ask(None, ALLOWED, dnswire.TYPE_A, forward, reply_log=replylog.log) or b"")
    assert reply.rcode == 2
    assert [line.split(",")[2] for line in _lines(replylog.rows)] == ["servfail"]


@pytest.mark.parametrize(
    "wire",
    [
        pytest.param(bytes(11), id="no-header"),
        pytest.param(build_query(ALLOWED)[:2] + b"\x80" + bytes(9), id="a-response"),
    ],
)
def test_a_packet_that_is_not_a_query_is_dropped_before_anything_is_logged(replylog: Logged, wire: bytes) -> None:
    async def forward(_wire: bytes) -> bytes:
        raise AssertionError("never forwarded")

    frontend = pfb_dns_proxy.Frontend(None, ("127.0.0.1", 9), timeout=WATCHDOG, reply_log=replylog.log)
    assert asyncio.run(frontend.resolve(wire, CLIENT, forward)) is None
    assert _lines(replylog.rows) == []


def test_a_logger_that_fails_still_lets_the_answer_through_and_is_reported_once(
    replylog: Logged, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    def broken(*_args: Any, **_kwargs: Any) -> bool:
        raise RuntimeError("disk full")

    monkeypatch.setattr(replylog.log.module, "get_details_reply", broken)
    expected = _resolve(None, CASES["a"])
    assert expected is not None
    assert [_resolve(None, CASES["a"], replylog.log) for _ in range(2)] == [expected, expected]
    assert capfd.readouterr().err.count("DNS Reply logging failed") == 1


# --- what the logging setup is, and is not -----------------------------------------------------------------


def test_it_logs_with_the_shipped_module_but_never_runs_its_dnsbl_lifecycle(replylog: Logged) -> None:
    pfb = replylog.log.module.pfb
    assert pfb["python_reply"] is True
    assert not any(
        pfb.get(key) for key in ("reload_watcher", "control_watcher", "query_watcher", "db_worker", "async_worker")
    )
    assert not any(pfb.get(key) for key in ("sqlite3_dnsbl_con", "sqlite3_resolver_con", "python_enable"))
    assert Path(replylog.log.module.__file__) == SHIPPED_DIR / "pfb_unbound.py"


def test_the_working_directory_stays_where_it_was(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import dns_reply_log

    monkeypatch.chdir(tmp_path)
    log = dns_reply_log.ReplyLog()
    try:
        assert Path.cwd() == tmp_path
    finally:
        log.close()


def test_closing_flushes_queued_rows_stops_the_log_thread_and_takes_the_module_out(
    handlers: list[_RecordingHandler],
) -> None:
    import dns_reply_log

    before = {thread.name for thread in threading.enumerate()}
    slot = sys.modules.get("pfb_unbound")
    log = dns_reply_log.ReplyLog()
    assert [(handler.path, handler.delay) for handler in handlers if handler.path == LOG_FILE] == [(LOG_FILE, True)]
    assert sys.modules["pfb_unbound"] is log.module
    log.module.pfb_log(LOG_FILE, "DNS-reply,queued")
    log.close()
    assert _written(handlers) == ["DNS-reply,queued"]  # a line still queued at shutdown is written, not lost
    assert {thread.name for thread in threading.enumerate()} == before
    assert sys.modules.get("pfb_unbound") is slot and shim._saved is None


def test_a_log_pipeline_that_does_not_start_is_an_error_and_leaves_no_module_behind(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    import dns_reply_log

    def unwritable(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(logging.handlers, "WatchedFileHandler", unwritable)
    slot = sys.modules.get("pfb_unbound")
    with pytest.raises(RuntimeError, match="log"):
        dns_reply_log.ReplyLog()
    assert sys.modules.get("pfb_unbound") is slot and shim._saved is None
    capfd.readouterr()


def test_rcodes_are_the_modules_own_table(booted: Booted) -> None:
    import dns_reply_log

    assert dns_reply_log.RCODES == booted.module.rcodeDB


def test_the_geoip_database_is_the_one_the_module_opens() -> None:
    import dns_reply_log

    assert f'pfb["maxminddb"] = "{dns_reply_log.GEOIP_DB}"' in (SHIPPED_DIR / "pfb_unbound.py").read_text(
        encoding="utf-8"
    )


# --- GeoIP column ------------------------------------------------------------------------------------------


class _FakeGeoIp:
    closed = False

    def get(self, address: str) -> dict[str, Any]:
        return {"country": {"iso_code": "DE"}}

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def geoip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _FakeGeoIp:
    """A GeoIP database present and a maxminddb module that opens it (the dev box has neither)."""
    import dns_reply_log

    reader = _FakeGeoIp()
    database = tmp_path / "GeoLite2-Country.mmdb"
    database.write_bytes(b"")
    monkeypatch.setattr(dns_reply_log, "GEOIP_DB", str(database))
    fake = type(sys)("maxminddb")
    fake.open_database = lambda path: reader  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "maxminddb", fake)
    return reader


def _iso(log: Logged, qname: str) -> str:
    log.rows.clear()
    _ask(None, qname, dnswire.TYPE_A, _upstream(Case(qname)), reply_log=log.log)
    return next(csv.reader(_lines(log.rows)))[9]


def test_the_geoip_column_is_filled_as_in_module_mode_when_the_database_is_there(
    geoip: _FakeGeoIp, replylog: Logged
) -> None:
    assert (_iso(replylog, "geo.example."), _iso(replylog, "lan.example."), _iso(replylog, "nx.example.")) == (
        "DE",
        "prv",
        "unk",
    )


def test_closing_closes_the_geoip_database(geoip: _FakeGeoIp) -> None:
    import dns_reply_log

    log = dns_reply_log.ReplyLog()
    assert geoip.closed is False
    log.close()
    assert geoip.closed is True


def test_the_geoip_column_is_unk_without_the_database(replylog: Logged) -> None:
    assert _iso(replylog, "geo.example.") == "unk"


# --- serve(): off, on, and a start that must not depend on the module's runtime dir -------------------------


def _serve_and_ask(argv: list[str], qname: str = ALLOWED) -> bytes:
    async def scenario() -> bytes:
        async with FakeProxyUpstream(FakeUnbound(ZONE)) as upstream:
            args = pfb_dns_proxy.parse_args(["--listen", "127.0.0.1", "--port", "0", *argv])
            args.upstream = f"127.0.0.1:{upstream.port}"
            async with serving(args) as [server]:  # a client that is not the firewall itself (127.0.0.1)
                return (await udp_exchange(server, build_query(qname), source=CLIENT_ON_LOOPBACK))[0]

    return asyncio.run(scenario())


def test_with_the_preference_off_nothing_is_loaded_started_or_written(
    handlers: list[_RecordingHandler], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    threads = {thread.name for thread in threading.enumerate()}
    slot = sys.modules.get("pfb_unbound")
    reply = _serve_and_ask(["--no-module", "--module-dir", str(tmp_path / "absent")])
    assert [rr.rdata for rr in dnswire.parse(reply).answers] == [bytes([192, 0, 2, 77])]
    assert handlers == [] and sys.modules.get("pfb_unbound") is slot and shim._saved is None
    assert {thread.name for thread in threading.enumerate()} == threads
    assert os.listdir(tmp_path) == []


def test_with_the_preference_on_a_query_is_answered_and_its_row_is_written_without_any_module_dir(
    handlers: list[_RecordingHandler], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    slot = sys.modules.get("pfb_unbound")
    reply = _serve_and_ask(["--no-module", "--reply-log", "--module-dir", str(tmp_path / "absent")])
    assert [rr.rdata for rr in dnswire.parse(reply).answers] == [bytes([192, 0, 2, 77])]
    [row] = [next(csv.reader([line])) for line in _written(handlers)]
    assert (row[0], row[2:9]) == (
        "DNS-reply",
        ["reply", "A", "A", "300", "allowed.example", CLIENT_ON_LOOPBACK, "192.0.2.77"],
    )
    assert sys.modules.get("pfb_unbound") is slot and shim._saved is None  # taken out again at shutdown
    assert os.listdir(tmp_path) == []


def test_a_reply_log_that_cannot_start_leaves_the_proxy_forwarding_with_one_error_line(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    def broken(_directory: str) -> Any:
        raise ImportError("no pfb_unbound.py")

    monkeypatch.setattr(shim, "install", broken)
    reply = _serve_and_ask(["--no-module", "--reply-log"])
    assert [rr.rdata for rr in dnswire.parse(reply).answers] == [bytes([192, 0, 2, 77])]
    assert capfd.readouterr().err.count("DNS Reply logging is off") == 1


def test_a_module_mode_proxy_ignores_a_reply_log_it_was_handed_so_a_row_is_never_written_twice(booted: Booted) -> None:
    calls: list[tuple[Any, ...]] = []

    def spy(*args: Any) -> None:
        calls.append(args)

    _ask(booted.module, ALLOWED, dnswire.TYPE_A, _upstream(CASES["a"]), reply_log=spy)
    assert calls == []
    assert len(_lines(booted.log)) == 1  # the module's own row, and only that


def test_the_real_process_starts_with_a_reply_log_and_no_module_dir_and_stops_cleanly_on_sigterm(
    tmp_path: Path,
) -> None:
    argv = ["--no-module", "--reply-log", "--listen", "127.0.0.1", "--port", "0"]
    argv += ["--upstream", "127.0.0.1:9", "--module-dir", str(tmp_path / "absent")]
    with running_proxy(argv, cwd=tmp_path):
        pass  # listening was seen; leaving the block sends SIGTERM and requires exit status 0
