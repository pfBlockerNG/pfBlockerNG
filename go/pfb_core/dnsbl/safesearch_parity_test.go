package dnsbl_test

// The SafeSearch corpus of sub-slice 9g (issue #4038): tests/core/fixtures/dnsbl_safesearch_parity.json, frozen against
// today's SafeSearch stage by tests/php/DnsblSafeSearchParityTest.php. Each case's lists are written to a folder and read
// by SafeSearchTable, which resolves nothing: the fixture resolver is today's PHP's alone (owner, 2026-11-23: pfB-DNS
// resolves a CNAME row's fallback addresses). Its rows are written as the decider's CSV, as pfb_ss_csv_rows() writes them,
// and compared with expect.csv, the hosts it leaves out with expect.refused.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
)

type safeSearchCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Policy      struct {
		SafeSearch        bool     `json:"safeSearch"`
		SafeSearchYoutube string   `json:"safeSearchYoutube"`
		SafeSearchDoh     bool     `json:"safeSearchDoh"`
		SafeSearchDohList []string `json:"safeSearchDohList"`
	} `json:"policy"`
	Files    map[string]string    `json:"files"`
	Resolver map[string][2]string `json:"resolver"`
	Expect   struct {
		CSV     string   `json:"csv"`
		Refused []string `json:"refused"`
	} `json:"expect"`
	OldExpect *struct {
		CSV string `json:"csv"`
	} `json:"old_expect"`
}

// csvOf writes rows as the decider's SafeSearch CSV (pfb_ss_csv_rows()): a CNAME row with its baked addresses, any other
// with its A and AAAA.
func csvOf(rows []dnsbl.SafeSearch) string {
	var b strings.Builder
	for _, r := range rows {
		if r.A == "cname" {
			b.WriteString(strings.Join([]string{r.Host, r.A, r.AAAA, r.V4, r.V6}, ",") + "\n")
		} else {
			b.WriteString(strings.Join([]string{r.Host, r.A, r.AAAA}, ",") + "\n")
		}
	}
	return b.String()
}

func TestSafeSearchTableMatchesTheParityFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "dnsbl_safesearch_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      int              `json:"schema"`
		Description string           `json:"description"`
		Cases       []safeSearchCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Schema != 1 || len(doc.Cases) < 10 {
		t.Fatalf("fixture: err %v, schema %d, %d cases", err, doc.Schema, len(doc.Cases))
	}
	shipped := filepath.Join("..", "..", "..", "src", "usr", "local", "pkg", "pfblockerng")
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.OldExpect != nil && c.OldExpect.CSV == c.Expect.CSV {
				t.Fatal("old_expect equals expect: not a departure")
			}
			dir := t.TempDir()
			for name, text := range c.Files {
				if text == "shipped" {
					b, err := os.ReadFile(filepath.Join(shipped, "pfb_dnsbl."+name+".conf"))
					if err != nil {
						t.Fatal(err)
					}
					text = string(b)
				}
				if err := os.WriteFile(filepath.Join(dir, "pfb_dnsbl."+name+".conf"), []byte(text), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			p := dnsbl.SafeSearchPolicy{Enable: c.Policy.SafeSearch, YouTube: c.Policy.SafeSearchYoutube, DoH: c.Policy.SafeSearchDoh,
				DoHList: c.Policy.SafeSearchDohList}
			rows, refused := dnsbl.SafeSearchTable(dir, p)
			if got := csvOf(rows); got != c.Expect.CSV {
				t.Errorf("SafeSearch CSV\n got %q\nwant %q", got, c.Expect.CSV)
			}
			if !slices.Equal(refused, c.Expect.Refused) && (len(refused) > 0 || len(c.Expect.Refused) > 0) {
				t.Errorf("refused = %q, want %q", refused, c.Expect.Refused)
			}
			if c.Expect.CSV == "" && rows != nil {
				t.Errorf("rows = %v, want nil: no host publishes no SafeSearch body", rows)
			}
			for _, r := range rows {
				if r.V4 != "" || r.V6 != "" {
					t.Errorf("row %+v carries a fallback address: Core resolves nothing", r)
				}
			}
		})
	}
}
