package feedstage

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Scenario: a DNSBL feed parses to no domain over rows it published before.
// Given a DNSBL feed with published rows, when its source changes to one that holds no domain, then the run never creates
// rows in its run folder (creating them would fail here) and publishes the feed as empty: the last rows stay.
func TestADNSBLRunWithoutADomainNeverCreatesItsRows(t *testing.T) {
	root := t.TempDir()
	sc := matrixScenario{"dnsbl", "none"}
	for _, d := range []string{"orig", "db", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "old.example\n")
	stage, feed := matrixStage(root, sc)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	rows := filepath.Join(root, "orig", "Feed.parsed.ndjson")
	before := readFile(t, rows)
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	withFault(t, func(op, path string) error {
		if op == "create" && path == filepath.Join(root, "orig", ".pfbrun-Feed", "Feed.parsed.ndjson") {
			return syscall.EIO
		}
		return nil
	})
	r := run(stage, feed, "none")
	fault = noFault
	if r.Disposition != "empty" {
		t.Fatalf("the run = %+v, want empty", r)
	}
	if got := readFile(t, rows); got != before {
		t.Errorf("the rows are %q, want the last ones %q", got, before)
	}
}

// Scenario: the record of the lists' input cannot be written.
// Given a published baseline and a changed source, when creating the record of the input the new list stands for fails,
// then the run fails at publish with parsed_publish_failed and the feed folder keeps the baseline: a list is never
// published without its record.
func TestAListWithoutItsRecordIsNeverPublished(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	withFault(t, func(op, path string) error {
		if op == "create" && strings.HasSuffix(path, ".parsed.src.xxhash128") {
			return syscall.EIO
		}
		return nil
	})
	stage, feed := killStage(root)
	r := run(stage, feed, "none")
	fault = noFault
	if r.Disposition != "failed" || r.Stage != "publish" || r.Reason != "parsed_publish_failed" {
		t.Errorf("the run = %+v, want failed at publish with parsed_publish_failed", r)
	}
	for _, name := range []string{"Feed_v4.orig", "Feed_v4.parsed.ip"} {
		if got := readFile(t, filepath.Join(dir, name)); got != "198.51.100.1\n" {
			t.Errorf("%s = %q, want the baseline", name, got)
		}
	}
	runLeftovers(t, dir, "after the failed run")
}
