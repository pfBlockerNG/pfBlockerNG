"""issue #1083 Phase 2 -- NDJSON interchange schema-v1 strict parse primitive.

Python never writes these files (PHP is the sole emitter); this pins
``_dnsbl_parse_ndjson_row()``, the read-side twin of PHP's
``pfb_dnsbl_ndjson_parse_row()`` (see its docblock in pfblockerng.inc for the full
schema contract). The hostile-input matrix here mirrors
tests/php/PfbNdjsonInterchangeTest.php row-for-row to prove both languages agree on
every reject/accept boundary; the byte-exact section at the bottom hardcodes actual
PHP emit() output (verified via a bare json_encode() probe with the same flags before
this file was written) to prove cross-language agreement, not just same-shaped intent.
"""

from __future__ import annotations

import pytest

import pfb_unbound as P

# --------------------------------------------------------------------------- #
# Hostile-input matrix -- mirrors PfbNdjsonInterchangeTest::rejectedLineProvider()
# row-for-row (the PHP-only invalid-UTF-8-byte row has no Python analogue -- a
# Python str can't carry an unpaired invalid byte the same way; the Python-only
# malformed-escape row below is this language's equivalent "undecodable" case).
# --------------------------------------------------------------------------- #

_REJECTED_LINES = {
    "empty string": "",
    "whitespace-only line": "   ",
    "truncated open brace": "{",
    "truncated partial object": '{"kind":"domain"',
    "json array (non-object)": "[]",
    "json string (non-object)": '"str"',
    "json number (non-object)": "42",
    "json null (non-object)": "null",
    "json true (non-object)": "true",
    "unknown kind": '{"kind":"bogus","domain":"a.com","log":"1","feed":"f","group":"g"}',
    "missing kind": '{"domain":"a.com","log":"1","feed":"f","group":"g"}',
    "domain: missing domain field": '{"kind":"domain","log":"1","feed":"f","group":"g"}',
    "domain: empty domain": '{"kind":"domain","domain":"","log":"1","feed":"f","group":"g"}',
    "domain: non-string domain": '{"kind":"domain","domain":123,"log":"1","feed":"f","group":"g"}',
    "domain: non-string log": '{"kind":"domain","domain":"a.com","log":1,"feed":"f","group":"g"}',
    "abp: missing raw": '{"kind":"abp"}',
    "abp: empty raw": '{"kind":"abp","raw":""}',
    # BOM (U+FEFF) is not part of the JSON grammar -- json.loads() refuses it.
    "BOM-prefixed valid object": "﻿" + '{"kind":"domain","domain":"a.com","log":"1","feed":"f","group":"g"}',
    # The migration's generation discriminator: a legacy positional-CSV line is
    # simply not valid JSON, so it rejects for free -- no special-casing needed.
    "legacy CSV line": ",a.com,,1,f,g",
    # Python-only undecodable case: an invalid \escape sequence (verified via a
    # bare json.loads() probe to raise json.JSONDecodeError, a ValueError subclass).
    "malformed escape sequence": '{"kind":"domain","domain":"\\q","log":"1","feed":"f","group":"g"}',
    # Python's json.loads accepts the NaN/Infinity extension PHP's json_decode refuses;
    # OUTCOME parity still holds because the non-string value fails the field type check.
    "NaN constant (type-check rejected)": '{"kind":"domain","domain":NaN,"log":"1","feed":"f","group":"g"}',
    "Infinity constant (py-accepted, type-check rejected)": '{"kind":"abp","raw":Infinity}',
}


@pytest.mark.parametrize("line", _REJECTED_LINES.values(), ids=list(_REJECTED_LINES.keys()))
def test_rejected_lines_return_none(line: str) -> None:
    assert P._dnsbl_parse_ndjson_row(line) is None


def test_extra_unknown_key_alongside_valid_domain_row_is_ignored_incidentally() -> None:
    # Incidental behaviour of json.loads() -- NOT a forward-compatibility promise
    # (schema v1 has none); pinned so a future parser change shows up here first.
    row = P._dnsbl_parse_ndjson_row(
        '{"kind":"domain","domain":"a.com","log":"1","feed":"f","group":"g","extra":"ignored-me"}'
    )
    assert row is not None
    assert row["domain"] == "a.com"


def test_duplicate_key_last_value_wins_incidentally() -> None:
    # Pins json.loads()'s actual last-wins duplicate-key behaviour (verified via a
    # bare json.loads() probe before this test was written) -- not a contract.
    line = '{"kind":"domain","domain":"a.com","domain":"b.com","log":"1","feed":"f","group":"g"}'
    row = P._dnsbl_parse_ndjson_row(line)
    assert row is not None
    assert row["domain"] == "b.com"


def test_oversized_domain_value_parses_shape_only_syntax_is_not_validated() -> None:
    # The helper validates the interchange SHAPE, not domain syntax -- that stays
    # with the existing validators downstream of parsing.
    huge = "a" * 100_000 + ".com"
    row = P._dnsbl_parse_ndjson_row(f'{{"kind":"domain","domain":"{huge}","log":"1","feed":"f","group":"g"}}')
    assert row is not None
    assert row["domain"] == huge


def test_deeply_nested_hostile_line_does_not_raise_recursion_error() -> None:
    # issue #1083 review: json.loads() on a sufficiently deep nested-array value
    # raises RecursionError (verified in-session: depth 200_000 reliably triggers it
    # on CPython's C-accelerated scanner too, not just the pure-Python fallback) --
    # PHP's json_decode() has a fixed depth cap and returns NULL instead, so an
    # unguarded RecursionError here is a PHP/Python asymmetry: one hostile line
    # would escape _dnsbl_parse_ndjson_row() uncaught and abort a per-line caller's
    # WHOLE file load if its try/except wraps the entire for-loop.
    depth = 300_000
    hostile = '{"kind":"domain","domain":' + "[" * depth + "]" * depth + ',"log":"1","feed":"f","group":"g"}'
    assert P._dnsbl_parse_ndjson_row(hostile) is None


# --------------------------------------------------------------------------- #
# Accepted shapes -- both kinds, all required fields present.
# --------------------------------------------------------------------------- #


def test_valid_domain_row_parses_every_field() -> None:
    line = '{"kind":"domain","domain":"example.com","log":"1","feed":"feedA","group":"groupA"}'
    row = P._dnsbl_parse_ndjson_row(line)
    assert row == {"kind": "domain", "domain": "example.com", "log": "1", "feed": "feedA", "group": "groupA"}


def test_valid_abp_row_parses_raw() -> None:
    row = P._dnsbl_parse_ndjson_row('{"kind":"abp","raw":"||example.com^"}')
    assert row == {"kind": "abp", "raw": "||example.com^"}


# --------------------------------------------------------------------------- #
# Cross-language byte-exact fixtures -- these literals are ACTUAL PHP
# pfb_dnsbl_ndjson_emit_domain_row()/pfb_dnsbl_ndjson_emit_abp_row() output
# (verified via a bare php -r json_encode() probe with the identical flags,
# byte-for-byte, before this file was written -- see PfbNdjsonInterchangeTest's
# matching testEmit*ByteExactOutput() assertions in the PHP twin).
# --------------------------------------------------------------------------- #

_PHP_EMITTED_PLAIN_DOMAIN_ROW = '{"kind":"domain","domain":"example.com","log":"1","feed":"feedA","group":"groupA"}\n'
_PHP_EMITTED_ESCAPED_DOMAIN_ROW = (
    '{"kind":"domain","domain":"ex\\"a\\\\mple.com","log":"1","feed":"feedA","group":"groupA"}\n'
)
_PHP_EMITTED_ABP_REGEX_ROW = '{"kind":"abp","raw":"/^ad[0-9]+\\\\./"}\n'


def test_parses_php_emitted_plain_domain_row_byte_exact() -> None:
    row = P._dnsbl_parse_ndjson_row(_PHP_EMITTED_PLAIN_DOMAIN_ROW.rstrip("\n"))
    assert row is not None
    assert row["domain"] == "example.com"
    assert row["log"] == "1"
    assert row["feed"] == "feedA"
    assert row["group"] == "groupA"


def test_parses_php_emitted_escaped_domain_row_recovers_quote_and_backslash() -> None:
    row = P._dnsbl_parse_ndjson_row(_PHP_EMITTED_ESCAPED_DOMAIN_ROW.rstrip("\n"))
    assert row is not None
    assert row["domain"] == 'ex"a\\mple.com'


def test_parses_php_emitted_abp_regex_row_recovers_single_backslash() -> None:
    row = P._dnsbl_parse_ndjson_row(_PHP_EMITTED_ABP_REGEX_ROW.rstrip("\n"))
    assert row is not None
    assert row["raw"] == "/^ad[0-9]+\\./"
