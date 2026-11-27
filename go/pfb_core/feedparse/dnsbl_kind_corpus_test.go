package feedparse

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Replays testdata/dnsbl_kind.json (schema: testdata/README.md): whether a feed is an Adblock feed (issue #4272), as a
// downloaded feed and as a custom list. The PHP runner is tests/php/FeedParseDnsblKindCorpusTest.php.
func TestDNSBLFeedKindCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/dnsbl_kind.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema *int `json:"schema"`
		Cases  []struct {
			ID          string  `json:"id"`
			Description string  `json:"description"`
			Input       *string `json:"input"`
			InputHex    *string `json:"input_hex"`
			Expect      *struct {
				Feed   *bool `json:"feed"`
				Custom *bool `json:"custom"`
			} `json:"expect"`
		} `json:"cases"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Schema == nil || *doc.Schema != 1 || len(doc.Cases) == 0 {
		t.Fatalf("dnsbl_kind.json: schema 1 and a non-empty case list expected: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if c.ID == "" || c.Description == "" || seen[c.ID] || (c.Input == nil) == (c.InputHex == nil) || c.Expect == nil ||
			c.Expect.Feed == nil || c.Expect.Custom == nil {
			t.Fatalf("case %q: a unique id, a description, one of input and input_hex and both expectations are required", c.ID)
		}
		seen[c.ID] = true
		input := ""
		if c.Input != nil {
			input = *c.Input
		} else {
			b, err := hex.DecodeString(*c.InputHex)
			if err != nil {
				t.Fatalf("case %s: input_hex: %v", c.ID, err)
			}
			input = string(b)
		}
		for _, k := range []struct {
			custom bool
			want   bool
		}{{false, *c.Expect.Feed}, {true, *c.Expect.Custom}} {
			got, err := DNSBLFeedIsABP(strings.NewReader(input), k.custom)
			if err != nil || got != k.want {
				t.Errorf("case %s (custom %v): got %v, %v; want %v", c.ID, k.custom, got, err, k.want)
			}
		}
	}
}
