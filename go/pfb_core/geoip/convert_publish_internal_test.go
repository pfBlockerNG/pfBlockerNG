package geoip

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Readers refuse a half-swapped generation by the swap marker (pfb_geoip_generation_ready()): it stands while every
// file moves, and is gone once the generation is published.
func TestTheSwapMarkerStandsWhileFilesMove(t *testing.T) {
	c, log := conversionRoot(t, testBlocks)
	marker := filepath.Join(c.CCDir, ".pfb_generation_swapping")
	moves, unmarked := 0, 0
	rename = func(from, to string) error {
		moves++
		if _, err := os.Stat(marker); err != nil {
			unmarked++
		}
		return os.Rename(from, to)
	}
	defer func() { rename = os.Rename }()
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	if moves == 0 || unmarked != 0 {
		t.Errorf("%d of %d moves ran without the swap marker", unmarked, moves)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the swap marker outlived the publication")
	}
}

// A forged "# ISO Code: *" header removes nothing: today's PHP hands it to unlink_if_exists(), which globs, and loses
// almost every staged list while still succeeding (#4127).
func TestAForgedGlobHeaderRemovesNothing(t *testing.T) {
	c, log := conversionRoot(t, testBlocks+"\"4.0.0.0/8\n# ISO Code: *\",6252001,6252001,,0,0,\n")
	if !c.Run(context.Background()) {
		t.Fatalf("conversion failed:\n%s", log)
	}
	for _, name := range []string{"Africa_v4.txt", "Asia_v4.txt", "US_v4.txt", "CN_v6.txt", "AD_v4.txt"} {
		if _, err := os.Stat(filepath.Join(c.CCDir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A MaxMind CSV path that is a directory reads as a failed read: nothing is converted. Today's PHP opens it, reads
// nothing, and publishes a generation without MaxMind's data.
func TestADirectoryForACSVConvertsNothing(t *testing.T) {
	for _, name := range []string{"GeoLite2-Country-Locations-en.csv", "GeoLite2-Country-Blocks-IPv4.csv"} {
		t.Run(name, func(t *testing.T) {
			c, _ := conversionRoot(t, testBlocks)
			path := filepath.Join(c.Share, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if c.Run(context.Background()) {
				t.Fatal("converted from a directory")
			}
			assertPrevious(t, c)
		})
	}
}
