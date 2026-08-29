"""Green-only coverage for the unified DNSBL drain row schema."""

from __future__ import annotations

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
    row = f"DNSBL-python,2026-08-01 12:00:00,{encoded_drain},192.168.1.10,A,VIP,group,{encoded_drain},feed,,A"
    monkeypatch.setattr(syslog.h, "read_log_file", lambda *_args, **_kwargs: row)
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: 1)

    def observe_once(predicate: Callable[[], bool], **_kwargs: Any) -> bool:
        assert predicate()
        return True

    monkeypatch.setattr(syslog.h, "wait_until", observe_once)

    assert (
        syslog._wait_for_unified_dnsbl(cast(syslog.SmokeVM, object()), drain, baseline_len=0, dnsbl_baseline=0) == row
    )
