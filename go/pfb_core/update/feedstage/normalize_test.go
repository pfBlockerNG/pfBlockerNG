package feedstage

import (
	"os"
	"path/filepath"
	"testing"
)

// Scenario: a feed fails after its changed download was normalized.
// Given a published baseline and a changed source, when the publication fails after the post-script (the new download is
// already normalized), then the download stays the baseline, and the next run parses the change instead of reusing the
// baseline's list because the normalization cache still describes the abandoned download.
func TestFailureAfterNormalizeLeavesNoStaleReuse(t *testing.T) {
	root := killRoot(t, "198.51.100.1\n")
	stage, feed := killStage(root)
	source := filepath.Join(root, "db", "feed.txt")
	orig, parsed := filepath.Join(root, "orig", "Feed_v4.orig"), filepath.Join(root, "orig", "Feed_v4.parsed.ip")

	writeFile(t, source, "198.51.100.2\n")
	if err := os.WriteFile(filepath.Join(root, "scripts", "post.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	saved := step
	t.Cleanup(func() { step = saved })
	step = func(name string) {
		if name == "post-script" { // a list that cannot be replaced fails the publication
			if err := os.Remove(parsed); err != nil || os.Mkdir(parsed, 0o700) != nil {
				t.Errorf("replacing the list by a folder: %v", err)
			}
		}
	}
	scripted := feed
	scripted.PostScript = "post.sh"
	if r := run(stage, scripted, "none"); r.Disposition != "failed" || r.Stage != "publish" {
		t.Fatalf("the run whose publication fails = %+v, want failed at publish", r)
	}
	step = saved
	if got := readFile(t, orig); got != "198.51.100.1\n" {
		t.Fatalf("after the failure the download is %q, want the baseline kept", got)
	}
	if err := os.Remove(parsed); err != nil {
		t.Fatal(err)
	}
	writeFile(t, parsed, "198.51.100.1\n")

	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the next run = %+v, want the change parsed, not the baseline's list reused", r)
	}
	if got := readFile(t, parsed); got != "198.51.100.2\n" {
		t.Fatalf("the next run published %q, want the changed source", got)
	}
}
