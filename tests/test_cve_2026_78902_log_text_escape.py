"""Log writers escape HTML and control characters in attacker-controlled fields.

CVE-2026-78902 (NetSPI): a TXT reply carrying ``"><script ...>`` reached
dns_reply.log raw and ran as stored XSS in the Reports page, which admin-session
JS then turned into RCE through diag_command.php. The PHP pages in v4 escape
every log field on output, which closes the bug. ``_log_text()`` is a second
layer: the four writers rewrite ``< > " ' &``, C0/C1 controls and DEL to the
DNS presentation escape ``\\DDD`` before the row is written, so a new reader
that forgets to escape cannot reopen it.

Fields that are escaped: query name, reply data, evaluated name, EDE provider
text. Fields left alone: admin-set feed and group names, which the Alerts page
matches against config.
"""

from __future__ import annotations

import csv
import types
from typing import Any

import pytest

import pfb_unbound
from pfb_unbound import UpstreamBlock, _log_idn_alert, _log_upstream_block

PAYLOAD = "\"><script src='//x.example/a.js'></script>&"
PAYLOAD_ESCAPED = "\\034\\062\\060script src=\\039//x.example/a.js\\039\\062\\060/script\\062\\038"
HTML_CHARS = set("<>\"'&")


def _capture_log(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
    return lines


def _row(lines: list[tuple[str, str]], log: str) -> list[str]:
    (raw,) = [line for path, line in lines if path.endswith(log)]
    assert not HTML_CHARS & set(raw), f"HTML-significant character reached {log}: {raw!r}"
    return next(csv.reader([raw]))


def _txt_rdata(*strings: bytes) -> bytes:
    # unbound rr_data: 2-byte RDATA length, then length-prefixed character-strings.
    body = b"".join(bytes([len(s)]) + s for s in strings)
    return len(body).to_bytes(2, "big") + body


def _txt_reply(*strings: bytes) -> Any:
    data = types.SimpleNamespace(count=1, rr_data=[_txt_rdata(*strings)])
    rrset = types.SimpleNamespace(rk=types.SimpleNamespace(type_str="TXT"), entry=types.SimpleNamespace(data=data))
    return types.SimpleNamespace(an_numrrsets=1, rrsets=[rrset], ttl=300)


class TestLogTextHelper:
    def test_html_payload_is_escaped(self) -> None:
        assert pfb_unbound._log_text(PAYLOAD) == PAYLOAD_ESCAPED

    @pytest.mark.parametrize(
        ("raw", "escaped"),
        [
            ("a\x1b[31mb", "a\\027[31mb"),  # ESC: terminal escape in `tail -f`
            ("a\x00b", "a\\000b"),
            ("a\tb", "a\\009b"),
            ("a\x7fb", "a\\127b"),
            ("a\x9bb", "a\\155b"),  # C1 CSI, reachable via latin-1 decode in convert_other
            ("x\\", "x\\092"),  # a trailing backslash would escape a syslog closing quote
            ("back\\slash\\046", "back\\092slash\\092046"),  # so \\DDD stays unambiguous
            ("a\u2028b", "a\\226\\128\\168b"),  # line/paragraph separators split rows
            ("a\u2029b", "a\\226\\128\\169b"),
            ("a\u202eb", "a\\226\\128\\174b"),  # RLO: the bidi set pfb_hsc() strips
            ("a\u061cb", "a\\216\\156b"),
            ("a\u200bb", "a\\226\\128\\139b"),  # zero-width space
            ("a\u2066b", "a\\226\\129\\166b"),
        ],
    )
    def test_control_characters_are_escaped(self, raw: str, escaped: str) -> None:
        assert pfb_unbound._log_text(raw) == escaped

    @pytest.mark.parametrize(
        "value",
        [
            "www.example.com",
            "a,b.example.com",  # commas are _csv_row's job (issue #1648)
            "a b",
            "a\r\nb",  # CR/LF are folded to a space by _csv_row
            "xn--80ak6aa92e.com [аррӏе.com] Cyrillic",  # decoded IDN stays readable
            "a\u00a0b",  # U+00A0 is the first code point past the C1 range; it stays
            "café.example",  # Latin-1 letters above U+009F stay
            "192.0.2.1",
            "2001:db8::1",
            "a\u200cb\u200dc",  # ZWNJ/ZWJ are legitimate in some IDN scripts; they stay
        ],
    )
    def test_ordinary_values_are_unchanged(self, value: str) -> None:
        assert pfb_unbound._log_text(value) == value


class TestDnsReplyWriter:
    def test_txt_reply_payload_is_escaped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given reply logging on, and a TXT reply carrying the NetSPI-style payload
        monkeypatch.setitem(pfb_unbound.pfb, "python_reply", True)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "python_maxmind", False)
        lines = _capture_log(monkeypatch)
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="evil.example.", qtype_str="TXT"),
            return_msg=None,
            return_rcode=0,
        )

        # When the reply is logged
        pfb_unbound.get_details_reply(
            "reply", None, qstate, _txt_reply(PAYLOAD.encode("latin-1")), {"pfb_addr": "192.0.2.7"}
        )

        # Then r_addr holds the escaped payload in its own column
        fields = _row(lines, "dns_reply.log")
        assert len(fields) == 10, fields
        assert fields[6] == "evil.example"
        assert fields[8] == PAYLOAD_ESCAPED

    def test_html_in_query_name_is_escaped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(pfb_unbound.pfb, "python_reply", True)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "python_maxmind", False)
        lines = _capture_log(monkeypatch)
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="<b>.example.", qtype_str="A"),
            return_msg=None,
            return_rcode=0,
        )

        pfb_unbound.get_details_reply("reply", None, qstate, None, {"pfb_addr": "192.0.2.7"})

        fields = _row(lines, "dns_reply.log")
        assert fields[6] == "\\060b\\062.example"


class TestDnsblWriters:
    def test_block_escapes_qname_and_b_eval_not_feed_or_group(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)
        decision = pfb_unbound.DnsblDecision(
            is_found=True,
            in_whitelist=False,
            in_hsts=False,
            null_blocking=False,
            nxdomain=False,
            log_type="1",
            b_type="DNSBL_Python",
            p_type="Python",
            feed="Tom's_feed",
            group="Tom's_group",
            b_eval="<i>.example",
        )
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str="a.<i>.example.", qtype_str="A"),
            return_msg=None,
        )

        pfb_unbound.get_details_dnsbl("dnsbl", None, qstate, {"pfb_addr": "192.0.2.7"}, decision)

        # Parsed directly: the admin-set feed and group keep their apostrophe by design.
        (raw,) = [line for path, line in lines if path.endswith("dnsbl.log")]
        fields = next(csv.reader([raw]))
        assert fields[2] == "a.\\060i\\062.example"
        assert fields[6] == "Tom's_group"
        assert fields[7] == "\\060i\\062.example"
        assert fields[8] == "Tom's_feed"

    def test_feed_and_group_names_are_not_rewritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Admin-set names are matched against config by the Alerts page; an
        # apostrophe in one must survive the write.
        lines = _capture_log(monkeypatch)

        _log_idn_alert("plain.example", "192.0.2.7", ("Tom's_feed", "Tom's_group", "xn--eval"), "A")

        (raw,) = [line for path, line in lines if path.endswith("dnsbl.log")]
        fields = next(csv.reader([raw]))
        assert fields[6] == "Tom's_group"
        assert fields[8] == "Tom's_feed"

    def test_idn_alert_escapes_qname_and_b_eval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        lines = _capture_log(monkeypatch)

        _log_idn_alert("<x>.example", "192.0.2.7", ("feed", "group", "xn--a [<x>] Latin"), "A")

        fields = _row(lines, "dnsbl.log")
        assert fields[2] == "\\060x\\062.example"
        assert fields[7] == "xn--a [\\060x\\062] Latin"

    def test_upstream_block_escapes_ede_provider_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # EDE EXTRA-TEXT comes off the wire, so it is attacker-controlled.
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)

        _log_upstream_block(
            "blocked.example",
            "192.0.2.7",
            UpstreamBlock(signal="EDE15", label="EDE15 (Blocked)", provider="<img src=x onerror=alert(1)>"),
            "A",
        )

        fields = _row(lines, "dnsbl.log")
        assert fields[8] == "\\060img src=x onerror=alert(1)\\062"

    def test_upstream_block_escapes_qname_and_label(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The classifier's labels are literals today; the column is escaped like every other b_eval.
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)

        _log_upstream_block(
            "a<b>.example", "192.0.2.7", UpstreamBlock(signal="EDE15", label="EDE15 <x>", provider="p"), "A"
        )

        fields = _row(lines, "dnsbl.log")
        assert fields[2] == "a\\060b\\062.example"
        assert fields[7] == "EDE15 \\060x\\062"

    def test_upstream_block_trailing_backslash_in_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Left raw, the backslash escapes the closing quote pfb_syslog_escape() adds.
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)

        _log_upstream_block(
            "blocked.example",
            "192.0.2.7",
            UpstreamBlock(signal="EDE15", label="EDE15 (Blocked)", provider="Filtered by x\\"),
            "A",
        )

        fields = _row(lines, "dnsbl.log")
        assert fields[8] == "Filtered by x\\092"

    def test_upstream_block_empty_provider_still_logs_external(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)

        _log_upstream_block(
            "blocked.example", "192.0.2.7", UpstreamBlock(signal="NXRA", label="NXRA", provider=""), "A"
        )

        fields = _row(lines, "dnsbl.log")
        assert fields[8] == "External"
