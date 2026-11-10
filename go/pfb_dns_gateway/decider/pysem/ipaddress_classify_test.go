package pysem

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The classification and the text of an address, against what ipaddress (Python 3.11.15) says for every address in the
// log-rows oracle (decider/testdata, gen_pfb_unbound_log_rows_oracle.py).
func TestAddressClassificationMatchesPython(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "pfb_unbound_log_rows_oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oracle struct {
		Tables struct {
			Ipaddress []struct {
				In          string
				Version     int
				Private     bool
				Loopback    bool
				Unspecified bool
				Compressed  string
				Str         string
				Mapped      *string
			}
		}
	}
	if err := json.Unmarshal(data, &oracle); err != nil {
		t.Fatal(err)
	}
	if len(oracle.Tables.Ipaddress) < 100 {
		t.Fatalf("the oracle holds %d addresses, want the full table", len(oracle.Tables.Ipaddress))
	}
	for _, c := range oracle.Tables.Ipaddress {
		packed, err := IPAddress(c.In)
		if c.Version == 0 {
			if err == nil {
				t.Errorf("IPAddress(%q) accepted it; Python refuses it", c.In)
			}
			continue
		}
		if err != nil {
			t.Errorf("IPAddress(%q) = %v; Python parses it as IPv%d", c.In, err, c.Version)
			continue
		}
		if got := IsPrivate(packed); got != c.Private {
			t.Errorf("IsPrivate(%q) = %v, want %v", c.In, got, c.Private)
		}
		if got := IsLoopback(packed); got != c.Loopback {
			t.Errorf("IsLoopback(%q) = %v, want %v", c.In, got, c.Loopback)
		}
		if got := IsUnspecified(packed); got != c.Unspecified {
			t.Errorf("IsUnspecified(%q) = %v, want %v", c.In, got, c.Unspecified)
		}
		// the packed value carries no %scope id, which Python's text keeps
		if got := Compressed(packed); !strings.Contains(c.In, "%") && (got != c.Compressed || got != c.Str) {
			t.Errorf("Compressed(%q) = %q, want %q (str %q)", c.In, got, c.Compressed, c.Str)
		}
		mapped := IPv4Mapped(packed)
		switch {
		case c.Mapped == nil && mapped != nil:
			t.Errorf("IPv4Mapped(%q) = %v, want none", c.In, mapped)
		case c.Mapped != nil && (mapped == nil || Compressed(mapped) != *c.Mapped):
			t.Errorf("IPv4Mapped(%q) = %v, want %s", c.In, mapped, *c.Mapped)
		}
	}
}
