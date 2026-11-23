package update

// The hand-over from the DNSBL build (sub-slice 9g) to the IP sets (9h): DNSBLOut.DNSBLIP is IPInput.DNSBLIP as it stands.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// WHEN the DNSBL build's DNSBLIP is handed to the IP sets THEN they publish ip-set/DNSBLIP/<family> with DNSBLIP's action
// and the side lists' addresses, and write its list in the action's class folder; WHEN DNSBL is then not active THEN the
// empty DNSBLIP removes both resources and the lists.
func TestTheDNSBLBuildsDNSBLIPFeedsTheIPSets(t *testing.T) {
	d, settings := sideListTree(t) // DNSBLIP Deny_Both over feed A's side lists: 192.0.2.1 and 2001:db8::1
	s := ipTree(t)
	out, err := d.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	ip := build(t, s, IPInput{Settings: ipSettings(nil, nil), DNSBLIP: out.DNSBLIP})
	for id, members := range map[string][]string{"ip-set/DNSBLIP/ipv4": {"192.0.2.1"}, "ip-set/DNSBLIP/ipv6": {"2001:db8::1"}} {
		r, ok := resourceOf(ip, id)
		if !ok || r.Action != "deny" || !slices.Equal(r.Direction, []string{"egress", "ingress"}) || r.Entries != 1 {
			t.Errorf("%s = %+v (published %v), want deny, both directions, 1 entry", id, r, ok)
		}
		if got := body(t, s.Store, id); !slices.Equal(got, members) {
			t.Errorf("%s body = %q, want %q", id, got, members)
		}
	}
	for _, v := range []string{"v4", "v6"} {
		if _, err := os.Stat(filepath.Join(s.Folders["deny"], "DNSBLIP_"+v+".txt")); err != nil {
			t.Errorf("deny/DNSBLIP_%s.txt: %v, want written", v, err)
		}
	}

	settings["dns"]["pfbDnsEnabled"] = false
	if out, err = d.Build(context.Background(), DNSBLInput{Settings: settings}); err != nil {
		t.Fatal(err)
	}
	ip = build(t, s, IPInput{Settings: ipSettings(nil, nil), DNSBLIP: out.DNSBLIP})
	for _, id := range []string{"ip-set/DNSBLIP/ipv4", "ip-set/DNSBLIP/ipv6"} {
		if _, ok := resourceOf(ip, id); ok || !slices.Contains(ip.Removed, id) {
			t.Errorf("%s with DNSBL not active: published %v, removed %q; want removed", id, ok, ip.Removed)
		}
	}
	for _, v := range []string{"v4", "v6"} {
		if _, err := os.Stat(filepath.Join(s.Folders["deny"], "DNSBLIP_"+v+".txt")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("deny/DNSBLIP_%s.txt with DNSBL not active: %v, want pruned", v, err)
		}
	}
}
