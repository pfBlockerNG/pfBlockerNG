"""pfB-DNS's modes in the decision service (issue #3513): `--decision-fd` with the mode flags the gateway hands on.

DNSBL off is `--no-module [--reply-log]`: the decider boots no pfb_unbound.py, decides nothing and forwards every query
through the FORWARD/REPLY exchange; with the DNS Reply Logging preference on it writes the existing DNS Reply log row
for each reply. The upstream observer socket exists only with `--observer` (DNSBL on, Resolver forwarding). The rows are
the ones tests/fixtures/dns_reply_standalone_rows.json pins for both modes and the PHP viewer tests read.
"""

from __future__ import annotations

import csv
import json
import logging.handlers
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dns_reply_log
import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import ALLOWED, BLOCKED, REPO_ROOT
from frontend_helpers import FakeUnbound, build_query
from test_decision_service import ANSWER, CLIENT, FORWARD, REPLY, ZONE, Gateway, _serve_decisions, frame, query_frame
from test_reply_log import LOG_FILE, _RecordingHandler, _written

ROWS = json.loads((REPO_ROOT / "tests" / "fixtures" / "dns_reply_standalone_rows.json").read_text(encoding="utf-8"))
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


@pytest.fixture
def empty_module_dir(tmp_path: Path) -> Path:
    """What --no-module is given: a directory with no pfb_unbound.py, no ini, no manifest and no feed in it."""
    directory = tmp_path / "no-module-here"
    directory.mkdir()
    return directory


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[_RecordingHandler]]:
    """The module's log pipeline writes through recorders instead of files: every handler made, with its lines."""
    _RecordingHandler.made.clear()
    monkeypatch.setattr(logging.handlers, "WatchedFileHandler", _RecordingHandler)
    yield _RecordingHandler.made
    _RecordingHandler.made.clear()


@pytest.fixture
def never_boots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pfb_dns_proxy, "boot", lambda *_args: pytest.fail("the DNSBL module must not boot"))


async def _forwarded(gateway: Gateway, fid: int, wire: bytes) -> bytes:
    """Send one QUERY, play Unbound for the FORWARD it must produce, and return the ANSWER the decider sends."""
    await gateway.send(query_frame(fid, wire))
    assert await gateway.recv() == (FORWARD, fid, wire), "the decider must forward the client's own bytes"
    await gateway.send(frame(REPLY, fid, FakeUnbound(ZONE).answer(wire)))
    ftype, answered, answer = await gateway.recv()
    assert (ftype, answered) == (ANSWER, fid)
    return answer


# --- DNSBL off: nothing is booted and nothing is decided ------------------------------------------------------


def test_no_module_boots_nothing_and_relays_a_listed_name_and_the_modules_control_name_to_unbound_untouched(
    empty_module_dir: Path, never_boots: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = sys.modules.get("pfb_unbound")
    answers: list[tuple[bytes, bytes]] = []

    async def scenario(gateway: Gateway) -> None:
        for fid, wire in enumerate(
            (build_query(BLOCKED), build_query("python_control.bogus.cmd.", dnswire.TYPE_TXT)), start=1
        ):
            answers.append((wire, await _forwarded(gateway, fid, wire)))

    events, _ = _serve_decisions(empty_module_dir, monkeypatch, scenario, "--no-module")

    assert events == [], "no boot and no shutdown: there is no module"
    assert [answer for _, answer in answers] == [FakeUnbound(ZONE).answer(wire) for wire, _ in answers]
    assert sys.modules.get("pfb_unbound") is before, "the DNSBL module was not even imported"


def test_no_module_still_drops_privilege_before_anything_else(
    empty_module_dir: Path, never_boots: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def nothing(_gateway: Gateway) -> None:
        return None

    events, _ = _serve_decisions(empty_module_dir, monkeypatch, nothing, "--no-module", "--user", "root")

    assert [event[0] for event in events] == ["setgroups", "setgid", "setuid"]


# --- DNS Reply Logging: the existing log, the existing columns, only when the preference is on ---------------------


def test_with_the_reply_log_on_the_relayed_reply_is_one_row_the_reports_tab_reads_and_the_client_gets_it_unchanged(
    empty_module_dir: Path, never_boots: None, recorded: list[_RecordingHandler], monkeypatch: pytest.MonkeyPatch
) -> None:
    query = build_query(ALLOWED)
    answers: list[bytes] = []

    async def scenario(gateway: Gateway) -> None:
        answers.append(await _forwarded(gateway, 1, query))

    _serve_decisions(empty_module_dir, monkeypatch, scenario, "--no-module", "--reply-log")

    assert answers == [FakeUnbound(ZONE).answer(query)], "logging never changes what the client gets"
    [line] = _written(recorded)  # the session's end flushed the queue
    row = next(csv.reader([line]))
    assert STAMP.match(row[1]), f"the row is stamped as the module stamps: {row[1]!r}"
    [expected] = ROWS["rows"]["a"]
    assert [*row[:1], *row[2:]] == [*expected.split(",")[:1], *expected.split(",")[2:]], (
        "the fixture's row for this reply"
    )
    assert row[7] == CLIENT == ROWS["client"], "the client of the row is the gateway's, not the decider's"
    php = "echo json_encode(fgetcsv(STDIN, 0, ',', '\"', ''));"  # the Reports readers' own call
    fields = json.loads(
        subprocess.run(["php", "-r", php], input=line, capture_output=True, check=True, text=True).stdout
    )
    assert len(fields) == 10 and fields[:3] == ["DNS-reply", row[1], "reply"]


def test_with_the_reply_log_off_nothing_is_logged_and_no_log_pipeline_is_made(
    empty_module_dir: Path, never_boots: None, recorded: list[_RecordingHandler], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario(gateway: Gateway) -> None:
        await _forwarded(gateway, 1, build_query(ALLOWED))

    _serve_decisions(empty_module_dir, monkeypatch, scenario, "--no-module")

    assert [handler.path for handler in recorded] == [], "no log file is opened, so none is created"
    assert _written(recorded) == []


def test_the_reply_log_starts_only_after_the_privilege_drop_so_its_file_belongs_to_the_user(
    empty_module_dir: Path, never_boots: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    order: list[str] = []

    class Recorder:
        def __init__(self) -> None:
            order.append("log opened")

        def close(self) -> None:
            order.append("log closed")

        def __call__(self, *_args: Any) -> None:
            return None

    monkeypatch.setattr(dns_reply_log, "ReplyLog", Recorder)
    monkeypatch.setattr(pfb_dns_proxy, "drop_privileges", lambda _account: order.append("dropped"))

    async def nothing(_gateway: Gateway) -> None:
        return None

    _serve_decisions(empty_module_dir, monkeypatch, nothing, "--no-module", "--reply-log", "--user", "root")

    assert order == ["dropped", "log opened", "log closed"]
    assert LOG_FILE.endswith("dns_reply.log")


# --- the observer socket: only with --observer ----------------------------------------------------------------


def test_without_the_observer_flag_the_decider_makes_no_observer_socket(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = module_dir / pfb_dns_proxy.OBSERVER_SOCKET
    seen: list[bool] = []

    async def scenario(_gateway: Gateway) -> None:
        seen.append(socket_path.exists())

    _serve_decisions(module_dir, monkeypatch, scenario)

    assert seen == [False], "DNSBL on without forwarding has no upstream to observe: no socket, nothing to forge"
