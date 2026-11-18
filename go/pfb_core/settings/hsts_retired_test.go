package settings

import "testing"

// issue #4053 slice 3: the HSTS list is gone, so Core's dns settings carry no HSTS switch.
func TestTheDnsProjectionHasNoHstsField(t *testing.T) {
	for _, p := range Production().Projections {
		if p.ID != "dns" {
			continue
		}
		for _, f := range p.Fields {
			if f.Name == "hstsNullBlocking" {
				t.Fatalf("settings/dns still publishes %q", f.Name)
			}
		}
		return
	}
	t.Fatal("no dns projection")
}
