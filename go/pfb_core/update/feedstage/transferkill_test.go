package feedstage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// Scenario: KILL inside the transfer.
// Given a published baseline and the download's journal set open as Run opens it before the transfer, when a KILL inside
// feedfetch's publication leaves the new download without its digest (the digests dropped, the body renamed in), or the
// old download beside a new digest, then Recover puts the old download and its digest back together, and the next run
// publishes the change. feedfetch replaces these files by rename or by remove and create, never in place, as here.
func TestKillInsideTheTransferIsRolledBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		leave func(t *testing.T, orig, sum string)
	}{
		{"new download without its digest", func(t *testing.T, orig, sum string) {
			if err := os.Remove(sum); err != nil {
				t.Fatal(err)
			}
			replaceFile(t, orig, "198.51.100.2\n")
		}},
		{"old download beside a new digest", func(t *testing.T, _, sum string) {
			if err := os.Remove(sum); err != nil {
				t.Fatal(err)
			}
			writeFile(t, sum, digest.Bytes([]byte("198.51.100.2\n")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := killRoot(t, "198.51.100.1\n")
			dir := filepath.Join(root, "orig")
			feed := feedfetch.Feed{Dir: dir, Name: "Feed_v4"}
			orig, sum := feedPath(feed, ".orig"), feedPath(feed, ".orig.xxhash128")
			baselineSum := readFile(t, sum)
			if _, err := snapshotPaths(feedStatePaths(feed)); err != nil {
				t.Fatal(err)
			}
			tc.leave(t, orig, sum)
			if err := Recover(dir); err != nil {
				t.Fatalf("Recover: %v", err)
			}
			if got, gotSum := readFile(t, orig), readFile(t, sum); got != "198.51.100.1\n" || gotSum != baselineSum {
				t.Errorf("after Recover the download is %q with digest %q, want the baseline %q with its digest %q", got,
					gotSum, "198.51.100.1\n", baselineSum)
			}
			noLeftovers(t, dir)
			writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
			stage, f := killStage(root)
			if r := run(stage, f, "none"); r.Disposition != "changed" {
				t.Fatalf("the next run = %+v, want the change published", r)
			}
			if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
				t.Errorf("the next run published %q, want the changed source", got)
			}
		})
	}
}
