"""Red canaries for the smoke absence controls' causal barriers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Callable

import pytest

from tests.smoke import helpers as h
from tests.smoke import test_smoke_upstream_block as upstream
from tests.smoke import test_syslog_export as syslog


class _DelayedUpstreamStub:
    def __init__(self) -> None:
        self.rcode = "NOERROR"

    def register_nxdomain(self, name: str, **_: Any) -> None:
        self.rcode = "NXDOMAIN"


def _upstream_case(monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]) -> None:
    vm = SimpleNamespace(_pfb_upstream_barrier="barrier.example.com")
    cvm = object()
    stub = _DelayedUpstreamStub()
    lines: list[str] = []
    counts: dict[str, int] = {}

    def probe(_: object, name: str, *_args: Any, **_kwargs: Any) -> h.DnsAnswer:
        if name == vm._pfb_upstream_barrier:
            lines.extend(
                (
                    f"DNSBL-python, DNSBL, barrier={name}",
                    f"DNSBL-python, Upstream_Block, qname={_subject}, barrier={name}",
                )
            )
            return h.DnsAnswer(rcode="NOERROR", records=[h.DEFAULT_DNSBL_VIP4])
        if stub.rcode == "NXDOMAIN":
            return h.DnsAnswer(rcode="NXDOMAIN", records=[])
        return h.DnsAnswer(rcode="NOERROR", records=[h.STUB_DNS_A])

    def count_marker(_: object, _path: str, marker: str, **_kwargs: Any) -> int:
        counts[marker] = sum(marker in line for line in lines)
        return counts[marker]

    _subject = "unset"
    monkeypatch.setattr(upstream.h, "dns_probe_client", probe)
    monkeypatch.setattr(upstream.h, "count_log_marker", count_marker)
    monkeypatch.setattr(upstream.h, "flush_unbound_name", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(upstream, "_read_dnsbl_log", lambda *_args, **_kwargs: "\n".join(lines))
    monkeypatch.setattr(upstream.time, "sleep", lambda *_args, **_kwargs: None)

    def run(deployed_vm: tuple[object, object], stub_dns: _DelayedUpstreamStub) -> None:
        nonlocal _subject
        _subject = method.__name__
        method(deployed_vm, stub_dns)

    with pytest.raises(AssertionError, match="Upstream_Block appeared before the absence assertion barrier"):
        run((vm, cvm), stub)


@pytest.mark.parametrize(
    ("method",),
    [
        (upstream.TestUpstreamBlockAuthoritativeControl().test_authoritative_nxdomain_not_logged,),
        (upstream.TestUpstreamBlockForwarderNaturalControl().test_forwarder_natural_nxdomain_not_logged,),
        (upstream.TestUpstreamBlockNormalControl().test_normal_resolution_not_logged,),
    ],
)
def test_upstream_absence_controls_consume_a_later_barrier(
    monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]
) -> None:
    _upstream_case(monkeypatch, method)


def _syslog_case(
    monkeypatch: pytest.MonkeyPatch,
    method: Callable[..., None],
    *,
    history_visible: bool = True,
    match: str | None = None,
) -> None:
    vm = SimpleNamespace(
        _pfb_dnsbl_domain="subject.example.com",
        _pfb_dnsbl_domain_on="barrier-on.example.com",
        _pfb_syslog_seed="seed.example.com",
        _pfb_syslog_drain="drain-off.example.com",
        _pfb_syslog_barrier="barrier-off.example.com",
        _pfb_civm_ip="192.168.1.10",
    )
    events: list[str] = []
    counts: dict[str, int] = {}

    def probe(_: object, name: str, *_args: Any, **_kwargs: Any) -> h.DnsAnswer:
        if name in (vm._pfb_dnsbl_domain_on, vm._pfb_syslog_barrier):
            subject = (
                vm._pfb_dnsbl_domain
                if method.__name__ == "test_syslog_on_dnsbl_event_exported"
                else vm._pfb_dnsbl_domain_on
            )
            events.append(f"act=dnsbl qname={subject} qip={vm._pfb_civm_ip}")
            events.append(f"act=dnsbl qname={name} qip={vm._pfb_civm_ip}")
        counts[name] = counts.get(name, 0) + 1
        return h.DnsAnswer(rcode="NOERROR", records=[h.DEFAULT_DNSBL_VIP4])

    def count_marker(_: object, _path: str, marker: str, **_kwargs: Any) -> int:
        return counts.get(marker, 0)

    monkeypatch.setattr(syslog.h, "dns_probe_client", probe)
    monkeypatch.setattr(syslog.h, "flush_unbound_name", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(syslog.h, "count_log_marker", count_marker)
    monkeypatch.setattr(syslog.h, "is_vip", lambda answer: True)
    monkeypatch.setattr(syslog.h, "config_get", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(syslog, "_set_syslog_enabled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        syslog,
        "_pfb_event_lines",
        lambda *_args, **_kwargs: [event for event in events if f"qname={vm._pfb_syslog_barrier}" in event],
    )
    monkeypatch.setattr(
        syslog,
        "_pfb_event_history_lines",
        lambda *_args, **_kwargs: list(events) if history_visible else [],
        raising=False,
    )
    monkeypatch.setattr(syslog, "_unified_dnsbl_lines", lambda *_args, **_kwargs: list(events), raising=False)
    monkeypatch.setattr(syslog, "_system_log_export_leaks", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(syslog, "syslog_export_state_snapshot", lambda *_args, **_kwargs: "fake state")
    monkeypatch.setattr(syslog, "_wait_for_event", lambda *_args, **_kwargs: "act=dnsbl qname=barrier")
    monkeypatch.setattr(syslog, "_wait_for_unified_dnsbl", lambda *_args, **_kwargs: None, raising=False)
    monkeypatch.setattr(syslog.time, "sleep", lambda *_args, **_kwargs: None)

    with pytest.raises(AssertionError, match=match):
        method(vm, object())


@pytest.mark.parametrize(
    ("method",),
    [
        (syslog.test_syslog_on_dnsbl_event_exported,),
        (syslog.test_syslog_off_no_new_records,),
    ],
)
def test_syslog_absence_controls_consume_a_later_barrier(
    monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]
) -> None:
    _syslog_case(monkeypatch, method, match="appeared in syslog after its unified row was consumed")


@pytest.mark.parametrize(
    ("method",),
    [
        (syslog.test_syslog_on_dnsbl_event_exported,),
        (syslog.test_syslog_off_no_new_records,),
    ],
)
def test_syslog_absence_controls_reject_empty_history(
    monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]
) -> None:
    _syslog_case(monkeypatch, method, history_visible=False, match="history.*barrier")


def _syslog_drain_order_case(monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]) -> None:
    vm = SimpleNamespace(
        _pfb_dnsbl_domain="seed-or-subject.example.com",
        _pfb_dnsbl_domain_on="subject-or-drain.example.com",
        _pfb_syslog_seed="seed.example.com",
        _pfb_syslog_drain="drain.example.com",
        _pfb_syslog_barrier="barrier.example.com",
        _pfb_civm_ip="192.168.1.10",
    )
    probes: list[str] = []
    unified_waits: list[str] = []
    events: list[str] = []
    enabled = [False]

    def probe(_: object, name: str, *_args: Any, **_kwargs: Any) -> h.DnsAnswer:
        probes.append(name)
        if enabled[0]:
            events.append(f"act=dnsbl qname={name} qip={vm._pfb_civm_ip}")
        return h.DnsAnswer(rcode="NOERROR", records=[h.DEFAULT_DNSBL_VIP4])

    def wait_unified(_: object, domain: str, **_kwargs: Any) -> str:
        unified_waits.append(domain)
        return f"act=dnsbl qname={domain}"

    monkeypatch.setattr(syslog.h, "dns_probe_client", probe)
    monkeypatch.setattr(syslog.h, "flush_unbound_name", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(syslog.h, "count_log_marker", lambda *_args, **_kwargs: len(probes))
    monkeypatch.setattr(syslog.h, "is_vip", lambda answer: True)
    monkeypatch.setattr(syslog, "_set_syslog_enabled", lambda _vm, *, on, **_kwargs: enabled.__setitem__(0, on))
    monkeypatch.setattr(syslog, "_pfb_event_lines", lambda *_args, **_kwargs: list(events))
    monkeypatch.setattr(syslog, "_pfb_event_history_lines", lambda *_args, **_kwargs: list(events), raising=False)
    monkeypatch.setattr(syslog, "_unified_dnsbl_lines", lambda *_args, **_kwargs: list(events), raising=False)
    monkeypatch.setattr(syslog, "_system_log_export_leaks", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(syslog, "_wait_for_event", lambda *_args, **_kwargs: "act=dnsbl qname=barrier")
    monkeypatch.setattr(syslog, "_wait_for_unified_dnsbl", wait_unified, raising=False)

    method(vm, object())

    if method.__name__ == "test_syslog_on_dnsbl_event_exported":
        assert probes == [vm._pfb_dnsbl_domain, vm._pfb_dnsbl_domain_on, vm._pfb_syslog_barrier]
        assert unified_waits == [vm._pfb_dnsbl_domain_on]
    else:
        assert probes == [
            vm._pfb_syslog_seed,
            vm._pfb_dnsbl_domain_on,
            vm._pfb_syslog_drain,
            vm._pfb_syslog_barrier,
        ]
        assert unified_waits == [vm._pfb_syslog_drain]


@pytest.mark.parametrize(
    ("method",),
    [
        (syslog.test_syslog_on_dnsbl_event_exported,),
        (syslog.test_syslog_off_no_new_records,),
    ],
)
def test_syslog_absence_controls_emit_a_distinct_off_state_drain_before_the_on_barrier(
    monkeypatch: pytest.MonkeyPatch, method: Callable[..., None]
) -> None:
    _syslog_drain_order_case(monkeypatch, method)
