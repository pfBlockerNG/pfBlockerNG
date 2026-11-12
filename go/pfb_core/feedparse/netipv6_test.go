package feedparse

import (
	"reflect"
	"strings"
	"testing"
)

// The appliance's IPv6 helpers (util.inc over PEAR Net_IPv6 1.3.0b4 with pfSense's patch). Every expectation is what the
// real code returned on PHP 8.4; the doubles' filter_var answers several of them differently.

// is_ipaddrv6(): Net_IPv6::checkIPv6() reads a group with hexdec(), which skips what is not a digit, and compares it
// with ==, so a trailing blank or newline passes; a %zone is dropped for the check. An address Net_IPv6 cannot uncompress
// (`1:2:3:4:5:6:7:8::9`) makes it throw, which util.inc turns into false.
func TestIsIPAddrV6IsNetIPv6(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:0db8::1", true},
		{"2001:db8::1 ", true},
		{"2001:db8::1\t", true},
		{"2001:db8::1\n", true},
		{" 2001:db8::1", false},
		{"1:2:3:4:5:6:7:8", true},
		{"1:2:3:4:5:6:7:8 ", true},
		{"1:2:3:4:5:6:7:8:9", false},
		{"1:2:3:4:5:6:7", false},
		{"::", true},
		{"::1", true},
		{"1::", true},
		{"1::2::3", false},
		{":::", false},
		{"1:2:3:4:5:6:1.2.3.4", true},
		{"::ffff:1.2.3.4", true},
		{"::1.2.3.04", true},
		{"::1.2.3.256", false},
		{"::1.2.3", false},
		{"1:2:3:4:5:6:7:1.2.3.4", false},
		{"00001::", false},
		{"0001::", true},
		{"000a::", true},
		{"00a::", true},
		{"0x1::", false},
		{"1x::", false},
		{"g::1", false},
		{"1:g:3:4:5:6:7:8", false},
		{":1:2:3:4:5:6:7", false},
		{"1:2:3:4:5:6:7:", false},
		{"fe80::1%eth0", true},
		{"FE80::1%eth0", true},
		{"febf::1%eth0", true},
		{"fec0::1%eth0", true},
		{"2606:4700::1111%eth0", true},
		{"2606:4700::1111%", true},
		{"2606:4700::1111%1", true},
		{"::%a", true},
		{"%eth0", false},
		{"fe80::1%eth0%x", true},
		{"fe80::1%a::2", true},
		{"fec0::1%a::2", false},
		{"1::2%a::3", false},
		{"2001:db8::1/64", false},
		{"", false},
		{"0", false},
		{"::0", true},
		{"1:2:3:4:5:6:7:8%eth0", true},
		{" ", false},
		{"1::2 3", false},
		{"1 ::2", true},
		{"1: :2", false},
		{"a:b:c:d:e:f:0:0", true},
		{"A:B:C:D:E:F:0:0", true},
		{"12345::1", false},
		{"1::12345", false},
		{"1e1::1", true},
		{"1e1:2:3:4:5:6:7:8", true},
		{"+1::1", true},
		{"-1::1", false},
		{"1::-1", false},
		{". ::1", false},
		{"::1.2.3.4.5", false},
		{"1.2.3.4", false},
		{"1.2.3.4:5", false},
		{"a.b.c.d", false},
		{"::ffff:1.2.3.4%eth0", true},
		{"fe80::1.2.3.4", true},
		{"1:2:3:4:5:6:7:8::9", false},
		{"1:2:3:4:5:6::7:8", false},
		{"1::2%a%b", true},
		{"fe80::1%a%b", true},
		{"1:2:3:4:5:6:7::8", false},
		{"::1:2:3:4:5:6:7:8", false},
	} {
		if got := isIPAddrV6(c.in); got != c.want {
			t.Errorf("isIPAddrV6(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// is_subnet(): 4, 6 or 0 from the regex, the address check and the bit count.
func TestPfSenseIsSubnet(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int
	}{
		{"1.2.3.4/24", 4},
		{"1.2.3.4/32", 4},
		{"1.2.3.4/33", 0},
		{"1.2.3.4/024", 4},
		{"1.2.3.4/0", 4},
		{"1.2.3.4/", 0},
		{"1.2.3.4", 0},
		{"1.2.3.4/24\n", 4},
		{"1.2.3.4/24 ", 0},
		{"999.1.1.1/24", 0},
		{"1.2.3/24", 0},
		{"1.2.3.04/24", 0},
		{"2001:db8::/32", 6},
		{"2001:db8::/128", 6},
		{"2001:db8::/129", 0},
		{"2001:db8::/0129", 0},
		{"2001:db8::/1234", 0},
		{"2001:db8::1/64\n", 6},
		{"2001:DB8::/32", 6},
		{"::/0", 6},
		{"::ffff:1.2.3.4/96", 6},
		{"1:2:3:4:5:6:1.2.3.4/96", 6},
		{"0000:0000:0000:0000:0000:ffff:255.255.255.255/96", 6},
		{"fe80::1%eth0/64", 0},
		{"2001:db8::1 /64", 0},
		{"2001:db8::1/64/1", 0},
		{"/24", 0},
		{"1.2.3.4//24", 0},
		{"1:2/3", 0},
		{"12/3", 0},
		{"1234567/24", 0},
		{"::g/64", 0},
		{"1.2.3.4.5/24", 0},
		{"255.255.255.255/32", 4},
		{"0.0.0.0/0", 4},
		{"::1/128", 6},
		{"1.2.3.4/x", 0},
	} {
		if got := pfSenseIsSubnet(c.in); got != c.want {
			t.Errorf("pfSenseIsSubnet(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// ip_range_to_subnet_array(): ip6_to_bin() reads each group with base_convert() (blanks skipped, a zone's letters and an
// IPv4 tail's digits read as hex) and bin_to_compressed_ip6() writes Net_IPv6::compress() forms, never an IPv4 tail.
func TestIPRangeToSubnetsIsNetIPv6(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want []string
	}{
		{"2606:4700::1", "2606:4700::3", []string{"2606:4700::1/128", "2606:4700::2/127"}},
		{"2606:4700::1", "2606:4700::3 ", []string{"2606:4700::1/128", "2606:4700::2/127"}},
		{"2606:4700::3 ", "2606:4700::1", []string{"2606:4700::1/128", "2606:4700::2/127"}},
		{"::ffff:0:0", "::ffff:0:3", []string{"::ffff:0:0/126"}},
		{"::1", "::3", []string{"::1/128", "::2/127"}},
		{"::", "::ffff", []string{"::/112"}},
		{"::ffff:0:0", "::ffff:0:0", []string{"::ffff:0:0/128"}},
		{"2001:db8::", "2001:db8::ffff", []string{"2001:db8::/112"}},
		{"2001:db8::1", "2001:db8::1", []string{"2001:db8::1/128"}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0/124"}},
		{"0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:ff", []string{"::1/128", "::2/127", "::4/126", "::8/125", "::10/124", "::20/123", "::40/122", "::80/121"}},
		{"1::", "1:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"1::/16"}},
		{"fe80::1%eth0", "fe80::5%eth0", []string{"fe80::1e0/123", "fe80::200/119", "fe80::400/120", "fe80::500/121", "fe80::580/122", "fe80::5c0/123", "fe80::5e0/128"}},
		{"2606:4700::1\t", "2606:4700::9", []string{"2606:4700::1/128", "2606:4700::2/127", "2606:4700::4/126", "2606:4700::8/127"}},
		{"2606:4700::fffe", "2606:4701::1", []string{"2606:4700::fffe/127", "2606:4700::1:0/112", "2606:4700::2:0/111", "2606:4700::4:0/110", "2606:4700::8:0/109", "2606:4700::10:0/108", "2606:4700::20:0/107", "2606:4700::40:0/106", "2606:4700::80:0/105", "2606:4700::100:0/104", "2606:4700::200:0/103", "2606:4700::400:0/102", "2606:4700::800:0/101", "2606:4700::1000:0/100", "2606:4700::2000:0/99", "2606:4700::4000:0/98", "2606:4700::8000:0/97", "2606:4700::1:0:0/96", "2606:4700::2:0:0/95", "2606:4700::4:0:0/94", "2606:4700::8:0:0/93", "2606:4700::10:0:0/92", "2606:4700::20:0:0/91", "2606:4700::40:0:0/90", "2606:4700::80:0:0/89", "2606:4700::100:0:0/88", "2606:4700::200:0:0/87", "2606:4700::400:0:0/86", "2606:4700::800:0:0/85", "2606:4700::1000:0:0/84", "2606:4700::2000:0:0/83", "2606:4700::4000:0:0/82", "2606:4700::8000:0:0/81", "2606:4700:0:0:1::/80", "2606:4700:0:0:2::/79", "2606:4700:0:0:4::/78", "2606:4700:0:0:8::/77", "2606:4700:0:0:10::/76", "2606:4700:0:0:20::/75", "2606:4700:0:0:40::/74", "2606:4700:0:0:80::/73", "2606:4700:0:0:100::/72", "2606:4700:0:0:200::/71", "2606:4700:0:0:400::/70", "2606:4700:0:0:800::/69", "2606:4700:0:0:1000::/68", "2606:4700:0:0:2000::/67", "2606:4700:0:0:4000::/66", "2606:4700:0:0:8000::/65", "2606:4700:0:1::/64", "2606:4700:0:2::/63", "2606:4700:0:4::/62", "2606:4700:0:8::/61", "2606:4700:0:10::/60", "2606:4700:0:20::/59", "2606:4700:0:40::/58", "2606:4700:0:80::/57", "2606:4700:0:100::/56", "2606:4700:0:200::/55", "2606:4700:0:400::/54", "2606:4700:0:800::/53", "2606:4700:0:1000::/52", "2606:4700:0:2000::/51", "2606:4700:0:4000::/50", "2606:4700:0:8000::/49", "2606:4700:1::/48", "2606:4700:2::/47", "2606:4700:4::/46", "2606:4700:8::/45", "2606:4700:10::/44", "2606:4700:20::/43", "2606:4700:40::/42", "2606:4700:80::/41", "2606:4700:100::/40", "2606:4700:200::/39", "2606:4700:400::/38", "2606:4700:800::/37", "2606:4700:1000::/36", "2606:4700:2000::/35", "2606:4700:4000::/34", "2606:4700:8000::/33", "2606:4701::/127"}},
		{"::2", "::1", []string{"::1/128", "::2/128"}},
		{"1.2.3.4", "1.2.3.9", []string{"1.2.3.4/30", "1.2.3.8/31"}},
		{"1.2.3.4", "2606:4700::1", []string{}},
		{"a::", "a::", []string{"a::/128"}},
		{"::1:0:0:0", "::1:ffff:ffff:ffff", []string{"::1:0:0:0/80"}},
		{"::1:0:0:0:0", "::1:0:0:0:3", []string{"0:0:0:1::/126"}},
		{"0:0:0:1::", "0:0:0:1:ffff:ffff:ffff:ffff", []string{"0:0:0:1::/64"}},
		{"fe80::1%a%b", "fe80::5%a%b", []string{"fe80::1b/128", "fe80::1c/126", "fe80::20/123", "fe80::40/124", "fe80::50/125", "fe80::58/126"}},
		{"1:0:0:2:0:0:3:0", "1:0:0:2:0:0:3:1", []string{"1::2:0:0:3:0/127"}},
		{"0:0:0:0:0:0:1:0", "0:0:0:0:0:0:1:3", []string{"::1:0/126"}},
		{"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:a", []string{"1:2:3:4:5:6:7:8/127", "1:2:3:4:5:6:7:a/128"}},
		{"::1.2.3.4", "::1.2.3.9", []string{"::1234/126", "::1238/127"}},
		{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:1.2.3.9", []string{"0:1:2:3:4:5:6:1234/126", "0:1:2:3:4:5:6:1238/127"}},
		// A zone's hex letters join the last group, which then outgrows an int and is converted as a float (53 bits of it).
		{"::256%eth0.fd0000.8832ffff", "::256%eth0.fd0000.8832ffff", []string{"::256%eth0.fd0000.8832ffff/128"}},
		{"::1%ffffffffffffffffffff", "::1%fffffffffffffffffffe", []string{"::1%ffffffffffffffffffff/128"}},
		{"::1%1234567890abcdef12", "::1%1234567890abcdef13", []string{"::1%1234567890abcdef12/128"}},
		{"::1%123456789abcdef0", "::1%123456789abcdef1", []string{"::1%123456789abcdef0/128"}},
		{"::1%7fffffffffffffff", "::1%8000000000000000", []string{"::1%7fffffffffffffff/128"}},
	} {
		got := ipRangeToSubnets(c.a, c.b)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ipRangeToSubnets(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// Inputs on which the old path dies (PHP throws a ValueError out of ip_range_to_subnet_array(): an IPv4 tail or a zone's
// letters make a group longer than sixteen bits and str_repeat() gets a negative count, or base_convert() an infinite
// value); Core yields no subnets.
func TestIPRangeToSubnetsGivesNothingWhereThePHPOneThrows(t *testing.T) {
	for _, c := range [][2]string{{"::ffff:246.253.38.88", "::ffff:246.253.38.99"}, {"1:2:3:4:5:6:7:8%12345", "1:2:3:4:5:6:7:9"},
		{"::1%" + strings.Repeat("f", 300), "::2%" + strings.Repeat("f", 300)}} {
		if got := ipRangeToSubnets(c[0], c[1]); len(got) != 0 {
			t.Errorf("ipRangeToSubnets(%q, %q) = %q, want none", c[0], c[1], got)
		}
	}
}
