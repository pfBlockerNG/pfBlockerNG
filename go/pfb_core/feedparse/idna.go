package feedparse

import (
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile is pslIdna of go/pfb_dns_gateway/decider/pfb_unbound_psl.go: UTS #46 non-transitional mapping and validation
// with the bidi rule and the DNS length checks (owner decision, #3906; #3813 for feed hosts in feedfetch). It differs from
// PHP's idn_to_ascii() where testdata/README.md lists old_expect lines.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false), idna.CheckHyphens(false), idna.VerifyDNSLength(true))

// IDNToASCII is idn_to_ascii(), the one IDN conversion of Core (feed lines here, feed host names in feedfetch); ok is false
// where the conversion fails. ICU accepts one root dot, ASCII or a UTS #46 full stop, the profile does not (Unicode >= 16
// with VerifyDNSLength), so it is set aside and put back as ".".
func IDNToASCII(s string) (string, bool) {
	host, root := s, false
	for _, dot := range []string{".", "\u3002", "\uff0e", "\uff61"} {
		if host, root = strings.CutSuffix(s, dot); root {
			break
		}
	}
	out, err := idnaProfile.ToASCII(host)
	if err != nil {
		return "", false
	}
	if root {
		out += "."
	}
	return out, true
}
