package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// issue #3694: a DDR query that arrives on a public IPv6 address gets no designations, as if no encrypted transport listened
// there: a global prefix changes (SLAAC, DHCPv6, a delegated prefix), so no certificate can keep an IP SAN for it, and a client
// whose lease or RA still names the address would be handed records it cannot verify. An IPv4 address, an IPv4-mapped one (its
// IPv4 address decides) and a non-public IPv6 address (a ULA such as the automatic Resolver VIP, link-local, documentation) are
// designated as ever.
//
// "Public" is PHP's: the IPv6 ranges of PFB_DNS_PROXY_NON_PUBLIC. The addresses and the ranges are the shared fixture
// tests/fixtures/ddr_public_ipv6.json, which tests/php/DdrPublicIpv6ParityTest.php holds against PHP's own list and predicate,
// so a range changed on one side fails the test of the other.

type ddrIPv6Fixture struct {
	Ranges    []string `json:"ranges"`
	Addresses []struct {
		Address string `json:"address"`
		Public  bool   `json:"public"`
		DDR     bool   `json:"ddr"`
	} `json:"addresses"`
}

func loadDDRIPv6Fixture(t *testing.T) ddrIPv6Fixture {
	t.Helper()
	raw, err := os.ReadFile("../../tests/fixtures/ddr_public_ipv6.json")
	if err != nil {
		t.Fatalf("the shared PHP/Go fixture: %v", err)
	}
	var f ddrIPv6Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("the shared PHP/Go fixture does not parse: %v", err)
	}
	if len(f.Ranges) == 0 || len(f.Addresses) == 0 {
		t.Fatalf("the shared PHP/Go fixture is empty: %+v", f)
	}
	return f
}

// The fixture's flags are derived here from its ranges by prefix containment, never from the code under test, so a wrong row
// cannot make the gateway test agree with a gateway that shares the mistake.
func TestDDRPublicIPv6FixtureFollowsItsRanges(t *testing.T) {
	f := loadDDRIPv6Fixture(t)
	var ranges []netip.Prefix
	for _, r := range f.Ranges {
		ranges = append(ranges, netip.MustParsePrefix(r))
	}
	for _, a := range f.Addresses {
		addr := netip.MustParseAddr(a.Address)
		if addr.Is4() || addr.Is4In6() {
			if !a.DDR {
				t.Errorf("%s is IPv4: its IPv4 address decides, and an IPv4 address is designated", a.Address)
			}
			continue
		}
		inside := false
		for _, r := range ranges {
			inside = inside || r.Contains(addr)
		}
		if a.Public == inside || a.DDR == a.Public {
			t.Errorf("%s: fixture says public=%v ddr=%v, but it is %v the non-public ranges, and DDR is withheld exactly on a public IPv6 address",
				a.Address, a.Public, a.DDR, map[bool]string{true: "inside", false: "outside"}[inside])
		}
	}
}

func TestDDRDesignatesOnEveryQueriedAddressButAPublicIPv6One(t *testing.T) {
	f := loadDDRIPv6Fixture(t)
	certs := ddrLoaded(t)
	for _, a := range f.Addresses {
		t.Run(a.Address, func(t *testing.T) {
			local := netip.MustParseAddr(a.Address)
			d := mustDDR(t, ddrTarget, false, certs, ddrAt(a.Address, 853), ddrAt(a.Address, 4443), ddrAt(a.Address, 853))
			hint := local.Unmap().String()
			want := ddrNODATA
			if a.DDR {
				want = ddrWant{
					svcb:       []ddrSVCB{ddrDoHRec(ddrFQDN, 4443, hint, ddrDoHPath), ddrDoTRec(ddrFQDN, 0, hint), ddrDoQRec(ddrFQDN, 0, hint)},
					additional: []string{ddrAddrRR(ddrFQDN, hint)},
				}
			}
			query := ddrQuery(t, 0x3694, ddrAsk, dnsmessage.TypeSVCB, 0)
			for _, udp := range []bool{true, false} {
				requireDDR(t, query, d.answer(query, local, udp), want)
			}
		})
	}
}

// A listener added live on a public IPv6 address is not designated either, and one on a ULA is: the withholding is the
// queried address's, whichever way the listener came.
func TestDDRPublicIPv6WithholdingAlsoHoldsForAListenerAddedLive(t *testing.T) {
	d := mustDDR(t, ddrTarget, false, ddrLoaded(t), nil, nil, nil)
	public, ula := netip.MustParseAddr("2606:4700::1"), netip.MustParseAddr("fd00:53:53:53:53:53:53:53")
	d.change(true, "dot", netip.AddrPortFrom(public, 853))
	d.change(true, "dot", netip.AddrPortFrom(ula, 853))
	query := ddrQuery(t, 0x3695, ddrAsk, dnsmessage.TypeSVCB, 0)
	requireDDR(t, query, d.answer(query, public, true), ddrNODATA)
	requireDDR(t, query, d.answer(query, ula, true), ddrWant{
		svcb:       []ddrSVCB{ddrDoTRec(ddrFQDN, 0, ula.String())},
		additional: []string{ddrAddrRR(ddrFQDN, ula.String())},
	})
}
