import pytest
import pfb_unbound
from pfb_unbound import (
    convert_ipv4,
    convert_ipv6,
    convert_other,
    is_unknown,
    python_control_duration,
)


class TestIsUnknown:
    def test_none_returns_unknown(self):
        assert is_unknown(None) == 'Unknown'

    def test_empty_string_returns_unknown(self):
        assert is_unknown('') == 'Unknown'

    def test_zero_returns_unknown(self):
        assert is_unknown(0) == 'Unknown'

    def test_false_returns_unknown(self):
        assert is_unknown(False) == 'Unknown'

    def test_nonempty_string_returned_as_is(self):
        assert is_unknown('example.com') == 'example.com'

    def test_ip_string_returned_as_is(self):
        assert is_unknown('192.168.1.1') == '192.168.1.1'

    def test_string_zero_returned_as_is(self):
        # '0' is a non-empty string, so it is not unknown
        assert is_unknown('0') == '0'

    def test_nonzero_int_returned_as_is(self):
        assert is_unknown(42) == 42


class TestConvertIPv4:
    # x[2], x[3], x[4], x[5] are the four octets; x[0] and x[1] are ignored

    def test_standard_address(self):
        assert convert_ipv4(bytes([0, 0, 192, 168, 1, 1])) == '192.168.1.1'

    def test_loopback(self):
        assert convert_ipv4(bytes([0, 0, 127, 0, 0, 1])) == '127.0.0.1'

    def test_broadcast(self):
        assert convert_ipv4(bytes([0, 0, 255, 255, 255, 255])) == '255.255.255.255'

    def test_all_zeros(self):
        assert convert_ipv4(bytes([0, 0, 0, 0, 0, 0])) == '0.0.0.0'

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv4(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_ipv4(None) == 'Unknown'


class TestConvertIPv6:
    # x[2] through x[17] are the 16 address bytes; x[0] and x[1] are ignored

    def test_loopback(self):
        x = bytes([0, 0] + [0] * 15 + [1])
        assert convert_ipv6(x) == '0000:0000:0000:0000:0000:0000:0000:0001'

    def test_known_prefix(self):
        # 2001:0db8::1
        x = bytes([0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        assert convert_ipv6(x) == '2001:0db8:0000:0000:0000:0000:0000:0001'

    def test_all_zeros_not_unknown(self):
        # All-zeros IPv6 address is a valid (if unusual) value
        x = bytes([0, 0] + [0] * 16)
        assert convert_ipv6(x) == '0000:0000:0000:0000:0000:0000:0000:0000'

    def test_empty_bytes_returns_unknown(self):
        assert convert_ipv6(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_ipv6(None) == 'Unknown'


class TestConvertOther:
    # x[0:3] are ignored; x[3:] is the payload
    # Encoding rules:
    #   val == 0          → '|'
    #   1 <= val <= 12    → '.'
    #   val == 13         → stop
    #   val == 32         → ' '
    #   val == 58         → ':'
    #   val <= 33 or > 126 → skip
    #   else              → chr(val)
    # Leading/trailing '.' and '|' are stripped from the result.

    def test_printable_ascii(self):
        x = bytes([0, 0, 0, ord('A'), ord('B'), ord('C')])
        assert convert_other(x) == 'ABC'

    def test_null_becomes_pipe(self):
        x = bytes([0, 0, 0, ord('A'), 0, ord('B')])
        assert convert_other(x) == 'A|B'

    def test_low_byte_becomes_dot(self):
        x = bytes([0, 0, 0, ord('A'), 1, ord('B')])
        assert convert_other(x) == 'A.B'

    def test_carriage_return_stops_processing(self):
        x = bytes([0, 0, 0, ord('A'), 13, ord('B')])
        assert convert_other(x) == 'A'

    def test_space_preserved(self):
        x = bytes([0, 0, 0, ord('A'), 32, ord('B')])
        assert convert_other(x) == 'A B'

    def test_colon_preserved(self):
        x = bytes([0, 0, 0, ord('h'), 58, ord('1')])
        assert convert_other(x) == 'h:1'

    def test_control_chars_skipped(self):
        # val 14..31 (excluding 13) and 33 are skipped
        x = bytes([0, 0, 0, ord('A'), 14, ord('B')])
        assert convert_other(x) == 'AB'

    def test_high_bytes_skipped(self):
        x = bytes([0, 0, 0, ord('A'), 200, ord('B')])
        assert convert_other(x) == 'AB'

    def test_leading_trailing_stripped(self):
        # Result '.A.' → strip('.|') → 'A'
        x = bytes([0, 0, 0, ord('.'), ord('A'), ord('.')])
        assert convert_other(x) == 'A'

    def test_empty_payload_returns_unknown(self):
        # x[3:] is empty
        x = bytes([0, 0, 0])
        assert convert_other(x) == 'Unknown'

    def test_empty_bytes_returns_unknown(self):
        assert convert_other(b'') == 'Unknown'

    def test_none_returns_unknown(self):
        assert convert_other(None) == 'Unknown'


class TestPythonControlDuration:
    def test_valid_duration(self):
        assert python_control_duration('60') == 60

    def test_minimum_valid(self):
        assert python_control_duration('1') == 1

    def test_maximum_valid(self):
        assert python_control_duration('3600') == 3600

    def test_zero_rejected(self):
        assert python_control_duration('0') is False

    def test_above_maximum_rejected(self):
        assert python_control_duration('3601') is False

    def test_non_numeric_rejected(self):
        assert python_control_duration('abc') is False

    def test_negative_rejected(self):
        # isnumeric() returns False for strings with a leading '-'
        assert python_control_duration('-1') is False

    def test_empty_string_rejected(self):
        assert python_control_duration('') is False

    def test_none_rejected(self):
        # AttributeError on None.isnumeric() is caught internally
        assert python_control_duration(None) is False
