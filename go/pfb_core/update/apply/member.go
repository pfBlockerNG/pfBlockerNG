package apply

import (
	"fmt"
	"net/netip"
	"strings"
)

// Member is how Core publishes one row of an ip-set or ip-aggregate of family ("ipv4" or "ipv6"): one address or one prefix
// of the family, in one spelling per network, what netip.Prefix.Masked() prints (a bare address for a host, address/length
// without host bits for a prefix). A row that is not one address or prefix of the family (a range, a netmask, a host name, a
// zone, white space) is refused, and so is one the address guard refuses: today's rule of pfb_sanitize_ipaddr() and
// pfb_sanitize_ipaddr_v6() (pfblockerng.inc, issue #1922), judged on the network pf loads, so an IPv4 network whose first
// octet is 0, the IPv6 network ::, and a prefix length of 0 are left out. A prefix length with leading zeros (/024), which
// today's parser publishes and pf reads as decimal, is its decimal number (/24): pfctl takes the length with strtonum(), which
// is decimal (FreeBSD sbin/pfctl/pfctl_parser.c host(), checked on main and releng/14.2 in the review of #4185), so /024 is
// /24, not octal. The caller files an issue for a refused row.
func Member(row, family string) (string, error) {
	var p netip.Prefix
	if addr, bits, ok := strings.Cut(row, "/"); ok {
		if bits != "" && strings.Trim(bits, "0123456789") == "" {
			bits = strings.TrimLeft(bits[:len(bits)-1], "0") + bits[len(bits)-1:] // the last digit stays: /00 is /0
		}
		var err error
		if p, err = netip.ParsePrefix(addr + "/" + bits); err != nil {
			return "", fmt.Errorf("%+q is not one address or prefix", row)
		}
	} else {
		a, err := netip.ParseAddr(row)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("%+q is not one address or prefix", row)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4() != (family == "ipv4") || (family != "ipv4" && family != "ipv6") {
		return "", fmt.Errorf("%+q is not of the family %+q", row, family)
	}
	p = p.Masked()
	a := p.Addr() // a prefix length of 0 masks to 0.0.0.0 or ::
	if a.Is4() && a.As4()[0] == 0 || a.IsUnspecified() {
		return "", fmt.Errorf("%+q is refused by the address guard: 0.x, :: and a prefix length of 0 are never published", row)
	}
	if p.IsSingleIP() {
		return a.String(), nil
	}
	return p.String(), nil
}
