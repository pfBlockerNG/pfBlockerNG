// Tests of ipaddress.IPv4Address, IPv6Address and ip_address as the Go port reimplements them; their expectations
// (packed values and error text) were produced by running Python 3.13.

package pysem

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestIPv4AddressMatchesPython(t *testing.T) {
	for in, want := range map[string]uint32{"0.0.0.0": 0, "1.2.3.4": 0x01020304, "255.255.255.255": 0xffffffff, "10.0.0.1": 0x0a000001} {
		if got, err := IPv4Address(in); err != nil || got != want {
			t.Errorf("IPv4Address(%q) = %#x, %v; want %#x, nil", in, got, err, want)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"", "Address cannot be empty"},
		{"999.1.1.1", "Octet 999 (> 255) not permitted in '999.1.1.1'"},
		{"256.0.0.1", "Octet 256 (> 255) not permitted in '256.0.0.1'"},
		{"1.2.3", "Expected 4 octets in '1.2.3'"},
		{"255", "Expected 4 octets in '255'"},
		{"1.2.3.4.5", "Expected 4 octets in '1.2.3.4.5'"},
		{"01.2.3.4", "Leading zeros are not permitted in '01' in '01.2.3.4'"},
		{"0.0.0.00", "Leading zeros are not permitted in '00' in '0.0.0.00'"},
		{"1.2.3.x", "Only decimal digits permitted in 'x' in '1.2.3.x'"},
		{"1.2.3.-4", "Only decimal digits permitted in '-4' in '1.2.3.-4'"},
		{"\u0661.2.3.4", "Only decimal digits permitted in '\u0661' in '\u0661.2.3.4'"},
		{"1.2.3.4 ", "Only decimal digits permitted in '4 ' in '1.2.3.4 '"},
		{"1.2.3.4\u0085z", "Only decimal digits permitted in '4\\x85z' in '1.2.3.4\\x85z'"},
		{"1..3.4", "Empty octet not permitted in '1..3.4'"},
		{"1.2.3.4/8", "Unexpected '/' in '1.2.3.4/8'"},
		{"1.2.3.1234", "At most 3 characters permitted in '1234' in '1.2.3.1234'"},
	} {
		if got, err := IPv4Address(c.in); err == nil || err.Error() != c.want {
			t.Errorf("IPv4Address(%q) = %#x, %v; want error %q", c.in, got, err, c.want)
		}
	}
}

// the longest text Python's IPv6 length cap lets through: 45 characters
const ipv6At45 = "0000:0000:0000:0000:0000:ffff:255.255.255.255"

func TestIPv6AddressMatchesPython(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"::", "00000000000000000000000000000000"},
		{"::1", "00000000000000000000000000000001"},
		{"1::", "00010000000000000000000000000000"},
		{"ffff::", "ffff0000000000000000000000000000"},
		{"ABCD::EF", "abcd00000000000000000000000000ef"},
		{"2001:db8::1", "20010db8000000000000000000000001"},
		{"1:2:3:4:5:6:7:8", "00010002000300040005000600070008"},
		{"1:2:3:4:5:6:7::", "00010002000300040005000600070000"},
		{"::2:3:4:5:6:7:8", "00000002000300040005000600070008"},
		{"::ffff:1.2.3.4", "00000000000000000000ffff01020304"},
		{"0001:0002:0003:0004:0005:0006:1.2.3.4", "00010002000300040005000601020304"},
		{ipv6At45, "00000000000000000000ffffffffffff"},
		{"fe80::1%eth0", "fe800000000000000000000000000001"}, // the scope id is validated and dropped
		{"1:2:3:4:5:6:7:8%z", "00010002000300040005000600070008"},
	} {
		if got, err := IPv6Address(c.in); err != nil || hex.EncodeToString(got) != c.want {
			t.Errorf("IPv6Address(%q) = %x, %v; want %s, nil", c.in, got, err, c.want)
		}
	}
	chars100, chars101 := strings.Repeat("1", 100), strings.Repeat("1", 101)
	for _, c := range []struct{ in, want string }{
		{"", "Address cannot be empty"},
		{"%eth0", "Address cannot be empty"},
		{"10.0.0.1", "At least 3 parts expected in '10.0.0.1'"},
		{"1:2", "At least 3 parts expected in '1:2'"},
		{"::1::", "At most one '::' permitted in '::1::'"},
		{":::", "At most one '::' permitted in ':::'"},
		{"1::2::3", "At most one '::' permitted in '1::2::3'"},
		{"1:2:3:4:5:6:7:8:9", "Exactly 8 parts expected without '::' in '1:2:3:4:5:6:7:8:9'"},
		{"1:2:3:4:5:6:7", "Exactly 8 parts expected without '::' in '1:2:3:4:5:6:7'"},
		{"1:2:3:4:5:6:7:8:", "Exactly 8 parts expected without '::' in '1:2:3:4:5:6:7:8:'"},
		{"12345::", "At most 4 characters permitted in '12345' in '12345::'"},
		{"::12345", "At most 4 characters permitted in '12345' in '::12345'"},
		{"fe80::1%", "Invalid IPv6 address: \"'fe80::1%'\""},
		{"fe80::1%a%b", "Invalid IPv6 address: \"'fe80::1%a%b'\""},
		{"::1.2.3", "Expected 4 octets in '1.2.3' in '::1.2.3'"},
		{"1::1.2.3.4.5", "Expected 4 octets in '1.2.3.4.5' in '1::1.2.3.4.5'"},
		{":1:2:3:4:5:6:7", "Leading ':' only permitted as part of '::' in ':1:2:3:4:5:6:7'"},
		{"1:2:3:4:5:6:7:", "Trailing ':' only permitted as part of '::' in '1:2:3:4:5:6:7:'"},
		{"1:2:3:4:5:6::7:8", "Expected at most 7 other parts with '::' in '1:2:3:4:5:6::7:8'"},
		{"1:g::", "Only hex digits permitted in 'g' in '1:g::'"},
		{"::g", "Only hex digits permitted in 'g' in '::g'"},
		{"1:2:3:4:5:6:7:8/64", "Unexpected '/' in '1:2:3:4:5:6:7:8/64'"},
		{"::%/64", "Unexpected '/' in '::%/64'"},
		{"1:2:3:4:5:6:7:8:9:1:2:3", "At most 8 colons permitted in '1:2:3:4:5:6:7:8:9:1:2:3'"},
		{"::1:2:3:4:5:6:7:8", "At most 8 colons permitted in '::1:2:3:4:5:6:7:8'"},
		{"0" + ipv6At45, "At most 45 characters expected in '0" + ipv6At45 + "'"},
		// past 100 characters the message elides the middle: the first 45, the count, the last 45
		{chars100, "At most 45 characters expected in '" + chars100 + "'"},
		{chars101, "At most 45 characters expected in '" + strings.Repeat("1", 45) + "(11 chars elided)" + strings.Repeat("1", 45) + "'"},
	} {
		if got, err := IPv6Address(c.in); err == nil || err.Error() != c.want {
			t.Errorf("IPv6Address(%q) = %x, %v; want error %q", c.in, got, err, c.want)
		}
	}
}

func TestIPAddressTriesIPv4ThenIPv6LikePythonsIPAddress(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"192.0.2.10", "c000020a"},
		{"255.255.255.255", "ffffffff"},
		{"::1", "00000000000000000000000000000001"},
		{"fe80::1%eth0", "fe800000000000000000000000000001"},
		{"::ffff:1.2.3.4", "00000000000000000000ffff01020304"},
	} {
		if got, err := IPAddress(c.in); err != nil || hex.EncodeToString(got) != c.want {
			t.Errorf("IPAddress(%q) = %x, %v; want %s, nil", c.in, got, err, c.want)
		}
	}
	// Python's ipaddress refuses a second '%' and any '/' in an IPv6 text; net/netip takes both.
	for _, in := range []string{"", "host.example", "256.0.0.1", "010.0.0.1", "1.2.3.4/8", "1.2.3.4%x", "::1/128", "fe80::1%a%b", "::%/64", "fe80::1%"} {
		want := "'" + in + "' does not appear to be an IPv4 or IPv6 address"
		if got, err := IPAddress(in); err == nil || err.Error() != want {
			t.Errorf("IPAddress(%q) = %x, %v; want error %q", in, got, err, want)
		}
	}
}
