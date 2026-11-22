package feedstage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Scenario: an IP post-script rewrites a download whose file the transfer kept.
// Given a published download and a server that answers 304, so that the transfer leaves the download's file in place,
// when the IP post-script rewrites the download in place and the publication then fails, then the download is put back
// as it was before the run: its backup never shares the file the script wrote.
func TestInPlacePostScriptNeverReachesTheBackup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	stage := testStage(t)
	scripts := t.TempDir()
	stage.Paths.ScriptDirs = []string{scripts}
	if err := os.WriteFile(filepath.Join(scripts, "post.sh"), []byte("#!/bin/sh\nprintf '10.9.9.9\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := stage.Paths.FeedDir
	orig := filepath.Join(dir, "feed_v4.orig")
	writeFile(t, orig, "203.0.113.1\n")
	// A folder where the list goes fails the publication.
	if err := os.Mkdir(filepath.Join(dir, "feed_v4.parsed.ip"), 0o700); err != nil {
		t.Fatal(err)
	}
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	feed.PostScript = "post.sh"
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	if got.Disposition != "failed" || got.Stage != "publish" {
		t.Fatalf("the run whose publication fails = %+v, want failed at publish", got)
	}
	if body := readFile(t, orig); body != "203.0.113.1\n" {
		t.Fatalf("after the failed run the download is %q, want the download before the run", body)
	}
	journalLeftovers(t, dir, "after the failed run")
}
