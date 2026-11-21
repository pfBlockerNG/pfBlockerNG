package geoip

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// catalogRows is the published generation's catalog, one decoded row a line.
func catalogRows(t *testing.T, c Conversion) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.CCDir, ".geo_catalog"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("catalog line %q: %v", line, err)
		}
		rows = append(rows, row)
	}
	return rows
}

// A name is data in the catalog: a quote or a "|" in it, which today's PHP writes into the generated page's source (where
// a quote ends the string and a "|" cuts the sort key it is split back from), is carried as it is.
func TestTheCatalogCarriesANameAsData(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	locations := strings.Replace(testLocations, `"United States"`, `"Uni""ted | States"`, 1)
	if err := os.WriteFile(filepath.Join(c.Share, "GeoLite2-Country-Locations-en.csv"), []byte(locations), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.Run(context.Background()) {
		t.Fatal("the conversion failed")
	}
	want := map[string]bool{
		`{"country":"Uni\"ted | States [6252001]","family":4,"iso":"US","kind":"country","networks":1,"page":"North_America"}`: false,
		`{"country":"Uni\"ted | States [6252001]","iso":"US","kind":"reputation","networks":1}`:                                false,
	}
	for _, row := range catalogRows(t, c) {
		delete(row, "position")   // where the name sorts among the table's other countries
		b, _ := json.Marshal(row) // map keys in order
		if _, ok := want[string(b)]; ok {
			want[string(b)] = true
		}
	}
	for row, seen := range want {
		if !seen {
			t.Errorf("no catalog row %s", row)
		}
	}
}

// The catalog is part of the generation: a conversion that fails after the catalog is built, when its generation cannot be
// linked into place, leaves the previous one.
func TestAFailedConversionKeepsThePreviousCatalog(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	if err := os.WriteFile(filepath.Join(filepath.Dir(c.CCDir), previousGeneration, ".geo_catalog"), []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rename = func(string, string) error { return syscall.EIO }
	defer func() { rename = os.Rename }()
	if c.Run(context.Background()) {
		t.Fatal("published without its rename")
	}
	if b, err := os.ReadFile(filepath.Join(c.CCDir, ".geo_catalog")); err != nil || string(b) != "previous\n" {
		t.Fatalf("catalog = %q, %v; want the previous one", b, err)
	}
}

// Every catalog line is a member the resource store takes (docs/misc/core-api-protocol.md, "Body and digest"): a control
// character in a name, which JSON may carry as it is (DEL, the C1 controls), is escaped.
func TestACatalogLineIsAResourceMember(t *testing.T) {
	c, _ := conversionRoot(t, testBlocks)
	locations := strings.Replace(testLocations, `"United States"`, "\"Uni\x7fted\u0085 States\"", 1)
	if err := os.WriteFile(filepath.Join(c.Share, "GeoLite2-Country-Locations-en.csv"), []byte(locations), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.Run(context.Background()) {
		t.Fatal("the conversion failed")
	}
	b, err := os.ReadFile(filepath.Join(c.CCDir, ".geo_catalog"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if _, err := resources.Canonical(lines); err != nil {
		t.Fatalf("the catalog is not a resource body: %v", err)
	}
	found := false
	for _, row := range catalogRows(t, c) {
		found = found || row["country"] == "Uni\x7fted\u0085 States [6252001]"
	}
	if !found {
		t.Error("no row carries the name as it is")
	}
}
