package feedparse

import (
	"encoding/hex"
	"testing"
)

// The NDJSON row the decider reads is what pfb_dnsbl_ndjson_emit_row() writes: json_encode() with JSON_UNESCAPED_SLASHES |
// JSON_UNESCAPED_UNICODE. Each row below is that function's answer (PHP 8.4.27, hex) for a text of one kind of character.
var ndjsonRows = []struct{ name, text, abp, domain string }{
	{"quote", "612262", "5b2261222c22615c2262225d0a", "5b2264222c22615c2262225d0a"},
	{"backslash", "615c62", "5b2261222c22615c5c62225d0a", "5b2264222c22615c5c62225d0a"},
	{"slash", "612f62", "5b2261222c22612f62225d0a", "5b2264222c22612f62225d0a"},
	{"html", "3c613e2627", "5b2261222c223c613e2627225d0a", "5b2264222c223c613e2627225d0a"},
	{"tab", "610962", "5b2261222c22615c7462225d0a", "5b2264222c22615c7462225d0a"},
	{"lf", "610a62", "5b2261222c22615c6e62225d0a", "5b2264222c22615c6e62225d0a"},
	{"cr", "610d62", "5b2261222c22615c7262225d0a", "5b2264222c22615c7262225d0a"},
	{"bs", "610862", "5b2261222c22615c6262225d0a", "5b2264222c22615c6262225d0a"},
	{"ff", "610c62", "5b2261222c22615c6662225d0a", "5b2264222c22615c6662225d0a"},
	{"ctl01", "610162", "5b2261222c22615c753030303162225d0a", "5b2264222c22615c753030303162225d0a"},
	{"ctl1f", "611f62", "5b2261222c22615c753030316662225d0a", "5b2264222c22615c753030316662225d0a"},
	{"nul", "610062", "5b2261222c22615c753030303062225d0a", "5b2264222c22615c753030303062225d0a"},
	{"del", "617f62", "5b2261222c22617f62225d0a", "5b2264222c22617f62225d0a"},
	{"ls", "61e280a862", "5b2261222c22615c753230323862225d0a", "5b2264222c22615c753230323862225d0a"},
	{"ps", "61e280a962", "5b2261222c22615c753230323962225d0a", "5b2264222c22615c753230323962225d0a"},
	{"e-acute", "c3a9", "5b2261222c22c3a9225d0a", "5b2264222c22c3a9225d0a"},
	{"euro", "e282ac", "5b2261222c22e282ac225d0a", "5b2264222c22e282ac225d0a"},
	{"emoji", "f09f9880", "5b2261222c22f09f9880225d0a", "5b2264222c22f09f9880225d0a"},
	{"bom", "efbbbf", "5b2261222c22efbbbf225d0a", "5b2264222c22efbbbf225d0a"},
	{"nbsp", "c2a0", "5b2261222c22c2a0225d0a", "5b2264222c22c2a0225d0a"},
	{"noncharacter", "efbfbf", "5b2261222c22efbfbf225d0a", "5b2264222c22efbfbf225d0a"},
	{"u0080", "c280", "5b2261222c22c280225d0a", "5b2264222c22c280225d0a"},
	{"u007f", "7f", "5b2261222c227f225d0a", "5b2264222c227f225d0a"},
}

func TestAppendRowMatchesJSONEncode(t *testing.T) {
	for _, c := range ndjsonRows {
		text, err := hex.DecodeString(c.text)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []struct {
			abp  bool
			want string
		}{{true, c.abp}, {false, c.domain}} {
			if got := hex.EncodeToString(appendRow(nil, DNSBLRow{ABP: kind.abp, Text: string(text)})); got != kind.want {
				t.Errorf("%s (abp=%v): row %s, want %s", c.name, kind.abp, got, kind.want)
			}
		}
	}
}
