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
// octet is 0, the IPv6 network ::, and a prefix length of 0 are left out. The caller files an issue for a refused row.
func Member(row, family string) (string, error) {
	var p netip.Prefix
	if strings.Contains(row, "/") {
		var err error
		if p, err = netip.ParsePrefix(row); err != nil {
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
