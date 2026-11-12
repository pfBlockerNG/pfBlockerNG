package feedparse

import (
	"testing"

	"golang.org/x/net/idna"
)

// The IDN rows of testdata/dnsbl.json (U+180E among them) were frozen against x/net's Unicode 17 tables, which x/net
// selects by Go toolchain (go1.27 and later); an older toolchain builds other answers.
func TestIDNTablesAreTheOnesTheCorpusWasFrozenAgainst(t *testing.T) {
	if idna.UnicodeVersion != "17.0.0" {
		t.Fatalf("x/net/idna Unicode tables = %s, want 17.0.0 (the corpus's IDN rows assume them)", idna.UnicodeVersion)
	}
}
