"""Green-only coverage for the unified DNSBL drain row schema."""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace
from typing import Any, Callable, cast

import pytest

from tests.smoke import test_syslog_export as syslog


def test_syslog_event_history_reads_current_and_rotated_generations(monkeypatch: pytest.MonkeyPatch) -> None:
    current = "pfblockerng: act=dnsbl qname=barrier.example.com qip=192.168.1.10"
    rotated = "pfblockerng: act=dnsbl qname=subject.example.com qip=192.168.1.10"
    monkeypatch.setattr(syslog.h, "read_log_file", lambda *_args, **_kwargs: current)

    def ssh(*args: str, **_kwargs: object) -> SimpleNamespace:
        assert args[:2] == ("/bin/sh", "-c")
        script = args[2]
        assert f"{syslog.PFB_SYSLOG_LOG} {syslog.PFB_SYSLOG_LOG}.[0-9]*" in script
        assert "/usr/bin/bsdcat" in script
        return SimpleNamespace(returncode=0, stdout=f"{current}\n{rotated}\n", stderr="")

    vm = SimpleNamespace(ssh=ssh)
    assert syslog._pfb_event_history_lines(cast(syslog.SmokeVM, vm)) == [current, rotated]


def test_syslog_event_history_decompression_failure_is_loud() -> None:
    vm = SimpleNamespace(
        ssh=lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout="partial", stderr="bad archive")
    )
    with pytest.raises(RuntimeError, match="history read failed.*bad archive"):
        syslog._pfb_event_history_lines(cast(syslog.SmokeVM, vm))


def test_syslog_unified_drain_expiry_reports_expected_and_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(syslog, "_unified_dnsbl_lines", lambda _vm: ["DNSBL-python,other,row"])
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(
        syslog.h,
        "wait_until",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("condition not met before timeout")),
    )

    with pytest.raises(
        RuntimeError,
        match=r"salvage cap expired / stuck or environment.*drain.example.com.*baseline_len=2.*marker count=0.*other",
    ):
        syslog._wait_for_unified_dnsbl(
            cast(syslog.SmokeVM, object()), "drain.example.com", baseline_len=2, dnsbl_baseline=0
        )


@pytest.mark.parametrize(
    ("drain", "encoded_drain"),
    [
        ("drain.example.com", "drain.example.com"),
        ("drain,quoted.example.com", '"drain,quoted.example.com"'),
        ('drain"quoted.example.com', '"drain""quoted.example.com"'),
    ],
)
def test_syslog_unified_drain_matches_the_real_dnsbl_csv_schema(
    monkeypatch: pytest.MonkeyPatch, drain: str, encoded_drain: str
) -> None:
    row = f"DNSBL-python,2026-08-01 12:00:00,{encoded_drain},192.168.1.10,A,VIP,group,{encoded_drain},feed,,A,UDP"
    monkeypatch.setattr(syslog.h, "read_log_file", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: 1)

    def observe_once(predicate: Callable[[], bool], **_kwargs: Any) -> bool:
        assert predicate()
        return True

    monkeypatch.setattr(syslog.h, "wait_until", observe_once)

    assert (
        syslog._wait_for_unified_dnsbl(cast(syslog.SmokeVM, object()), drain, baseline_len=0, dnsbl_baseline=0) == row
    )


@pytest.mark.parametrize("columns", [12, 14])
@pytest.mark.parametrize("drain", ["drain.example.com", "drain,quoted.example.com", 'drain"quoted.example.com'])
def test_syslog_unified_drain_selects_qname_and_transport_in_mixed_history(
    monkeypatch: pytest.MonkeyPatch, columns: int, drain: str
) -> None:
    def row(qname: str, *, width: int, transport: str = "UDP", qtype: str = "A") -> str:
        fields = [
            "DNSBL-python",
            "2026-08-01 12:00:00",
            qname,
            "192.168.1.10",
            "A",
            "VIP",
            "group",
            drain,
            "feed",
            "",
            qtype,
            transport,
        ]
        if width == 14:
            fields.extend(["192.0.2.1", 'LAN, "trusted"'])
        out = io.StringIO()
        csv.writer(out, lineterminator="").writerow(fields)
        return out.getvalue()

    historical = row(drain, width=12)
    wrong_name = row("other.example.com", width=14)
    wrong_columns = row(drain, width=14, qtype="UDP", transport="A")
    expected = row(drain, width=columns, transport="TCP")
    history = "\n".join([historical, wrong_name, wrong_columns, expected])
    monkeypatch.setattr(syslog.h, "read_log_file", lambda *_args, **_kwargs: history)
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: 2)

    def observe_once(predicate: Callable[[], bool], **_kwargs: Any) -> bool:
        assert predicate()
        return True

    monkeypatch.setattr(syslog.h, "wait_until", observe_once)
    result = syslog._wait_for_unified_dnsbl(cast(syslog.SmokeVM, object()), drain, baseline_len=1, dnsbl_baseline=1)

    assert result == expected
    fields = next(csv.reader([result]))
    assert fields[2:4] == [drain, "192.168.1.10"]
    assert fields[7] == drain
    assert fields[10:12] == ["A", "TCP"]
    assert fields[12:] == (["192.0.2.1", 'LAN, "trusted"'] if columns == 14 else [])


@pytest.mark.parametrize(
    ("row", "marker_count"),
    [
        ("DNSBL-python,time,other.example.com,192.168.1.10,A,VIP,group,drain.example.com,feed,,A,UDP", 2),
        ("DNSBL-python,time,drain.example.com,192.168.1.10,A,VIP,group,other,feed,,UDP,A", 2),
        ("DNSBL-python,time,drain.example.com,192.168.1.10,A,VIP,group,other,feed,,A,UDP,192.0.2.1", 2),
        ("DNSBL-python,time,drain.example.com,192.168.1.10,A,VIP,group,other,feed,,A,UDP", 1),
    ],
)
def test_syslog_unified_drain_rejects_wrong_fields_and_requires_a_later_input_marker(
    monkeypatch: pytest.MonkeyPatch, row: str, marker_count: int
) -> None:
    monkeypatch.setattr(syslog.h, "read_log_file", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: marker_count)

    def observe_once(predicate: Callable[[], bool], **_kwargs: Any) -> bool:
        assert not predicate()
        raise RuntimeError("condition not met before timeout")

    monkeypatch.setattr(syslog.h, "wait_until", observe_once)
    with pytest.raises(RuntimeError, match="salvage cap expired"):
        syslog._wait_for_unified_dnsbl(
            cast(syslog.SmokeVM, object()), "drain.example.com", baseline_len=0, dnsbl_baseline=1
        )
