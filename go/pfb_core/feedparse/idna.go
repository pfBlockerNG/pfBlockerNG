package feedparse

import (
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile is pslIdna of go/pfb_dns_gateway/decider/pfb_unbound_psl.go: UTS #46 non-transitional mapping and validation
// with the bidi rule and the DNS length checks (owner decision, #3906). It differs from PHP's idn_to_ascii() where
// testdata/README.md lists old_expect lines.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false), idna.CheckHyphens(false), idna.VerifyDNSLength(true))

// idnToASCII is idn_to_ascii(); ok is false where the conversion fails. ICU accepts one root dot, the profile does not
// (Unicode >= 16 with VerifyDNSLength), so it is set aside and put back.
func idnToASCII(s string) (string, bool) {
	host, root := strings.CutSuffix(s, ".")
	out, err := idnaProfile.ToASCII(host)
	if err != nil {
		return "", false
	}
	if root {
		out += "."
	}
	return out, true
}
