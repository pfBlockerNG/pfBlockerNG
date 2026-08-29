"""DNSBL/DNS-reply log writers must CSV-quote attacker-influenced fields — issue #1648.

``q_name`` (the queried DNS name) may legally contain a comma: ``0x2C`` is
``isgraph`` and the sldns presentation encoding leaves it unescaped. The log
writers historically built each row with a plain ``",".join(...)``, so an
embedded comma shifted every downstream column when the PHP readers
(``fgetcsv($h, 0, ',', '"', '')`` in pfblockerng_alerts.php) parsed the line —
forging the Group / Feed / Evaluated-Domain attribution shown in Alerts and
Reports.

These tests round-trip each writer's output through ``csv.reader`` (the
"excel" dialect: ``,`` delimiter, ``"`` quote, RFC4180 double-quote doubling —
the exact grammar the PHP readers parse) and assert the columns do NOT shift
when the queried name embeds a comma.

Writers under test (all four emitters of these logs):
- ``get_details_dnsbl``   -> dnsbl.log     (11 columns)
- ``_log_idn_alert``      -> dnsbl.log     (11 columns)
- ``_log_upstream_block`` -> dnsbl.log     (11 columns)
- ``get_details_reply``   -> dns_reply.log (10 columns)
"""

from __future__ import annotations

import csv
import json
import subprocess
import types
from typing import Any

import pytest

import pfb_unbound
from pfb_unbound import UpstreamBlock, _log_idn_alert, _log_upstream_block

# A DNS name whose presentation form legally embeds a comma. If the writer
# joins raw fields with "," this injects a phantom column.
COMMA_NAME = "a,forged-feed.example.com"


def _capture_log(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
    return lines


def _parse(line: str) -> list[str]:
    # Same grammar as the PHP read side: fgetcsv($h, 0, ',', '"', '') —
    # RFC4180 quoting, no escape char (csv "excel" dialect).
    return next(csv.reader([line]))


def _parse_with_php(line: str) -> list[str]:
    """Parse one row with the exact PHP reader grammar used by log consumers."""
    script = (
        "$row = fgetcsv(STDIN, 0, ',', '\"', '');"
        "if ($row === false) { fwrite(STDERR, 'fgetcsv failed'); exit(1); }"
        "echo json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);"
    )
    result = subprocess.run(
        ["php", "-r", script],
        input=f"{line}\n",
        capture_output=True,
        check=True,
        text=True,
    )
    fields = json.loads(result.stdout)
    assert isinstance(fields, list), f"PHP fgetcsv returned unexpected JSON: {result.stdout!r}"
    return fields


def _dnsbl_lines(lines: list[tuple[str, str]]) -> list[str]:
    return [line for path, line in lines if path.endswith("dnsbl.log")]


class TestDnsblBlockWriterCommaInQName:
    """A comma-bearing queried name must not shift the dnsbl.log columns."""

    @staticmethod
    def _decision() -> Any:
        return pfb_unbound.DnsblDecision(
            is_found=True,
            in_whitelist=False,
            in_hsts=False,
            null_blocking=False,
            nxdomain=False,
            log_type="1",
            b_type="DNSBL_Python",
            p_type="Python",
            feed="real_feed",
            group="real_group",
            b_eval="example.com",
        )

    def test_comma_qname_keeps_columns_aligned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given DNSBL logging enabled and no SQLite sinks
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str=COMMA_NAME + ".", qtype_str="A"),
            return_msg=None,
        )

        # When a block for a comma-bearing name is logged
        pfb_unbound.get_details_dnsbl("dnsbl", None, qstate, {"pfb_addr": "192.0.2.7"}, self._decision())

        # Then the row round-trips with the queried name intact in ITS column
        # and the attribution columns unshifted.
        (raw,) = _dnsbl_lines(lines)
        fields = _parse(raw)
        assert len(fields) == 11, f"expected 11 columns, got {len(fields)}: {fields!r}"
        assert fields[2] == COMMA_NAME, f"q_name column forged: expected {COMMA_NAME!r}, got {fields[2]!r}"
        assert fields[6] == "real_group", f"group column forged: expected 'real_group', got {fields[6]!r}"
        assert fields[8] == "real_feed", f"feed column forged: expected 'real_feed', got {fields[8]!r}"
        assert fields[10] == "A", f"q_type column forged: expected 'A', got {fields[10]!r}"


class TestIdnAlertWriterCommaInQName:
    def test_comma_qname_keeps_columns_aligned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        lines = _capture_log(monkeypatch)

        _log_idn_alert(COMMA_NAME, "192.0.2.7", ("real_feed", "real_group", "xn--eval"), "A")

        (raw,) = _dnsbl_lines(lines)
        fields = _parse(raw)
        assert len(fields) == 11, f"expected 11 columns, got {len(fields)}: {fields!r}"
        assert fields[2] == COMMA_NAME, f"q_name column forged: expected {COMMA_NAME!r}, got {fields[2]!r}"
        assert fields[5] == "Homoglyph_Alert", f"b_type column forged: got {fields[5]!r}"
        assert fields[8] == "real_feed", f"feed column forged: expected 'real_feed', got {fields[8]!r}"


class TestUpstreamBlockWriterCommaInQName:
    def test_comma_qname_keeps_columns_aligned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
        lines = _capture_log(monkeypatch)

        _log_upstream_block(COMMA_NAME, "192.0.2.7", UpstreamBlock(signal="NXRA", label="NXRA", provider=""), "A")

        (raw,) = _dnsbl_lines(lines)
        fields = _parse(raw)
        assert len(fields) == 11, f"expected 11 columns, got {len(fields)}: {fields!r}"
        assert fields[2] == COMMA_NAME, f"q_name column forged: expected {COMMA_NAME!r}, got {fields[2]!r}"
        assert fields[5] == "Upstream_Block", f"b_type column forged: got {fields[5]!r}"
        assert fields[8] == "External", f"feed column forged: expected 'External', got {fields[8]!r}"


class TestDnsReplyWriterCommaInQName:
    def test_comma_qname_keeps_columns_aligned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Given reply logging enabled, no resolver counter, no MaxMind
        monkeypatch.setitem(pfb_unbound.pfb, "python_reply", True)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "python_maxmind", False)
        lines = _capture_log(monkeypatch)
        qstate = types.SimpleNamespace(
            qinfo=types.SimpleNamespace(qname_str=COMMA_NAME + ".", qtype_str="A"),
            return_msg=None,
            return_rcode=0,
        )

        # When a reply for a comma-bearing name is logged (rep=None -> the
        # empty reply address renders as is_unknown('') == 'Unknown')
        rcd = pfb_unbound.get_details_reply("reply", None, qstate, None, {"pfb_addr": "192.0.2.7"})
        assert rcd is True, f"expected True, got {rcd!r}"

        # Then the dns_reply.log row round-trips with q_name in ITS column (index 6)
        # and the reply-address column unshifted.
        (raw,) = [line for path, line in lines if path.endswith("dns_reply.log")]
        fields = _parse(raw)
        assert len(fields) == 10, f"expected 10 columns, got {len(fields)}: {fields!r}"
        assert fields[6] == COMMA_NAME, f"q_name column forged: expected {COMMA_NAME!r}, got {fields[6]!r}"
        assert fields[8] == "Unknown", f"r_addr column forged: expected 'Unknown', got {fields[8]!r}"


class TestPlainNameRowStaysBareCsv:
    """Comma-free rows must stay byte-identical to the historical format.

    QUOTE_MINIMAL preserves the historical bare row for ordinary names while
    still producing valid input for the daemon's str_getcsv() and the Alerts
    page's fgetcsv() readers. That byte compatibility is the pinned contract.
    """

    def test_plain_fields_are_not_quoted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        lines = _capture_log(monkeypatch)

        _log_idn_alert("plain.example.com", "192.0.2.7", ("feedX", "groupY", "evalZ"), "A")

        (raw,) = _dnsbl_lines(lines)
        assert '"' not in raw, f"comma-free row must stay unquoted, got {raw!r}"
        assert raw.split(",")[2] == "plain.example.com", f"unexpected row shape: {raw!r}"


@pytest.mark.parametrize(
    ("label", "hostile_name"),
    [
        ("quote-doubling", 'a,"quoted".example.com'),
        ("crlf-normalization", "a\r\nquoted.example.com"),
        ("cr-normalization", "a\rquoted.example.com"),
        ("lf-normalization", "a\nquoted.example.com"),
    ],
)
def test_hostile_qname_is_one_php_csv_row(
    label: str,
    hostile_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quotes and line breaks cannot forge columns or split a physical log row."""
    lines = _capture_log(monkeypatch)

    _log_idn_alert(hostile_name, "192.0.2.7", ("real_feed", "real_group", "xn--eval"), "A")

    (raw,) = _dnsbl_lines(lines)
    expected_name = hostile_name.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    assert raw.count("\n") == 0, f"{label}: row contains a physical newline: {raw!r}"
    assert raw.count("\r") == 0, f"{label}: row contains a carriage return: {raw!r}"
    if label == "quote-doubling":
        assert '""' in raw, f"{label}: embedded quote was not doubled: {raw!r}"

    expected = _parse(raw)
    actual = _parse_with_php(raw)
    assert actual == expected, f"{label}: PHP/Python CSV parsers disagree: {actual!r} != {expected!r}"
    assert actual == [
        "DNSBL-python",
        actual[1],
        expected_name,
        "192.0.2.7",
        "Python",
        "Homoglyph_Alert",
        "real_group",
        "xn--eval",
        "real_feed",
        "+",
        "A",
    ], f"{label}: PHP fgetcsv fields shifted or changed: {actual!r}"
