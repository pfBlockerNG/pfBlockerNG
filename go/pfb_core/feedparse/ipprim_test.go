package feedparse

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// inet_ntop() as glibc and FreeBSD print it: the longest zero run compressed, `::a.b.c.d` for the ::/96 and
// ::ffff:0:0/96 tails. Expectations are PHP's own inet_ntop().
func TestPhpInetNtop(t *testing.T) {
	for _, c := range [][2]string{
		{"00000000000000000000000000000000", "::"},
		{"00000000000000000000000000000001", "::1"},
		{"00000000000000000000ffff01020304", "::ffff:1.2.3.4"},
		{"00000000000000000000000001020304", "::1.2.3.4"},
		{"00000000000000000000000000010000", "::0.1.0.0"},
		{"00000000000000000000000000000002", "::2"},
		{"00000000000000000000ffff00000000", "::ffff:0.0.0.0"},
		{"0000000000000000ffff000001020304", "::ffff:0:102:304"},
		{"20010db8000000000000000000000001", "2001:db8::1"},
		{"20010db8000000010000000000000001", "2001:db8:0:1::1"},
		{"20010db8000000000001000000000001", "2001:db8::1:0:0:1"},
		{"20010db8000100000000000100000000", "2001:db8:1::1:0:0"},
		{"00010000000000000000000000000000", "1::"},
		{"00010000000000000000000000000001", "1::1"},
		{"00000000000100000000000000000001", "0:0:1::1"},
		{"00000001000000000000000000000000", "0:1::"},
		{"fe800000000000000000000000000001", "fe80::1"},
		{"ff02000000000000000000000000000b", "ff02::b"},
		{"0001000200030004000500060007000a", "1:2:3:4:5:6:7:a"},
		{"00000000000000000000ffff0a000001", "::ffff:10.0.0.1"},
		{"00000000000000000001ffff01020304", "::1:ffff:102:304"},
		{"0064ff9b0000000000000000c0000201", "64:ff9b::c000:201"},
		{"20010db8000000000000000000000000", "2001:db8::"},
		{"00000000000000000000fffe01020304", "::fffe:102:304"},
	} {
		raw, _ := hex.DecodeString(c[0])
		if got := phpInetNtop(raw); got != c[1] {
			t.Errorf("phpInetNtop(%s) = %q, want %q", c[0], got, c[1])
		}
	}
}

// The numeric-host table shared with the DNS gateway's dnsblIsNumericHost(): null = not numeric-shaped, a quad = valid,
// false = numeric-shaped but invalid.
func TestIPv4NumericHostSharedTable(t *testing.T) {
	data, err := os.ReadFile("../../../tests/fixtures/ipv4_numeric_host.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases [][2]any `json:"cases"`
	}
	if err := json.Unmarshal(data, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) < 60 {
		t.Fatalf("shared table has %d cases", len(table.Cases))
	}
	for _, c := range table.Cases {
		host := c[0].(string)
		ip, numeric, valid := ipv4NumericHost(host)
		switch want := c[1].(type) {
		case nil:
			if numeric {
				t.Errorf("%.40q: numeric, want not numeric-shaped", host)
			}
		case bool:
			if !numeric || valid {
				t.Errorf("%.40q: numeric=%v valid=%v, want numeric and invalid", host, numeric, valid)
			}
		case string:
			if !numeric || !valid || ip != want {
				t.Errorf("%.40q: (%q, %v, %v), want %q", host, ip, numeric, valid, want)
			}
		}
	}
}
