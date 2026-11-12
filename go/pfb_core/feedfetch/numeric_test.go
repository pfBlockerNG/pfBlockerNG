package feedfetch

import (
	"encoding/json"
	"os"
	"testing"
)

// The non-canonical IPv4 refusal decodes a host the way libcurl does; the decoder must agree with pfb_ipv4_numeric_host()
// on the shared table (tests/fixtures/ipv4_numeric_host.json: null = not numeric-shaped, false = numeric-shaped but
// invalid, a quad = what it decodes to).
func TestIPv4NumericHostMatchesTheSharedTable(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/fixtures/ipv4_numeric_host.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases [][2]any `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("the shared table has no case")
	}
	for _, c := range table.Cases {
		host := c[0].(string)
		shaped, ip := ipv4Numeric(host)
		var got any
		switch {
		case !shaped:
			got = nil
		case ip == "":
			got = false
		default:
			got = ip
		}
		if got != c[1] {
			t.Errorf("ipv4Numeric(%q) = %v, want %v", host, got, c[1])
		}
	}
}
