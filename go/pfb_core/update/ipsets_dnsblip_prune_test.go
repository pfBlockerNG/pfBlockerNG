package update

import (
	"os"
	"path/filepath"
	"testing"
)

// WHEN DNSBLIP is not supplied (sub-slice 9g fills IPInput.DNSBLIP) THEN the prune leaves the DNSBLIP lists of every class
// folder alone, so a wired Build never deletes the lists today's pass writes there.
func TestThePruneLeavesDNSBLIPListsAloneWhileDNSBLIPIsNotSupplied(t *testing.T) {
	s := ipTree(t)
	parsed(t, s, "A_v4", "192.0.2.1\n")
	var lists []string
	for _, class := range []string{"deny", "native"} {
		for _, name := range []string{"DNSBLIP_v4.txt", "DNSBLIP_v6.txt"} {
			p := filepath.Join(s.Folders[class], name)
			touch(t, p, "198.51.100.1\n")
			lists = append(lists, p)
		}
	}
	build(t, s, IPInput{Settings: ipSettings([]any{group("A", "Deny_Both", "deny", "A")}, nil)})
	for _, p := range lists {
		if b, err := os.ReadFile(p); err != nil || string(b) != "198.51.100.1\n" {
			t.Errorf("%s = %q (%v), want it kept as it was", p, b, err)
		}
	}
}
