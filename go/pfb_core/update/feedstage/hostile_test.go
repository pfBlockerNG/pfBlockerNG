package feedstage

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// A feed folder that is a symbolic link is refused, and neither the run nor the recovery touches what the link points at.
func TestFeedDirectoryThatIsALinkIsRefused(t *testing.T) {
	target, sourceDir := t.TempDir(), t.TempDir()
	link := filepath.Join(t.TempDir(), "orig")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"feed_v4.orig": "198.51.100.1\n", "feed_v4.parsed.ip": "198.51.100.1\n", "feed_v4.orig.post": "kept\n"}
	for name, body := range files {
		writeFile(t, filepath.Join(target, name), body)
	}
	source := filepath.Join(sourceDir, "feed.txt")
	writeFile(t, source, "198.51.100.2\n")
	stage := &Stage{Paths: Paths{FeedDir: link}, Fetcher: &feedfetch.Fetcher{Policy: feedfetch.Policy{LocalDirs: []string{sourceDir}}}}

	got := run(stage, Feed{ID: "ipv4:feed_v4", Kind: "ipv4", Name: "feed_v4", State: "enabled",
		Format: "auto", Source: "file://" + source}, "download")
	if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != "feed_directory_unavailable" {
		t.Fatalf("run through a linked feed folder = %+v; want failed/settings/feed_directory_unavailable", got)
	}
	if err := Recover(link); err == nil {
		t.Fatal("recovery of a linked feed folder succeeded; want it refused")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != len(files) {
		t.Fatalf("the link's target holds %d entries (%v), want the %d it had", len(entries), err, len(files))
	}
	for name, want := range files {
		if body := readFile(t, filepath.Join(target, name)); body != want {
			t.Errorf("%s behind the link = %q, want %q untouched", name, body, want)
		}
	}
}

// Scenario: an Update was killed in the middle of a feed.
// Given leftovers of each kind in the feed folder, when the next Update recovers the folder before its first feed, then a
// regular IP restore point is put back, a journal set without its commit marker is rolled back (each backup put back, each
// file recorded absent removed), a set with its marker is finished (its new files stay), and the staged files go.
func TestRecoverPutsBackTheBaseline(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a_v4.orig":                             "post-script output\n",
		"a_v4.orig.post":                        "download of a\n",
		"b_v4.orig":                             "new download of b\n",
		".b_v4.orig.pfbbackup-123":              "baseline of b\n",
		"b_v4.orig.etag":                        `"new"`,
		".b_v4.orig.etag.pfbabsent-123":         "",
		"b_v4.orig.lastmod":                     "today",
		".b_v4.orig.lastmod.pfbabsent-123":      "",
		".b_v4.orig.xxhash128.pfbbackup-123":    "baseline digest of b\n",
		"b_v4.orig.xxhash128":                   "new digest of b\n",
		"e.parsed.ndjson":                       "[\"d\",\"new.example\"]\n",
		".e.parsed.ndjson.pfbbackup-456":        "[\"d\",\"old.example\"]\n",
		"e.parsed.src.xxhash128":                "new record\n",
		".e.parsed.src.xxhash128.pfbabsent-456": "",
		".pfbcommit-456":                        "",
		"c.pre":                                 "staged pre-script copy\n",
		"c.post":                                "staged post-script copy\n",
		".pfbstage-777":                         "staged parse output\n",
		"c.orig":                                "untouched download of c\n",
		"c.orig.etag":                           `"c"`,
		"c.parsed.ndjson":                       "[\"domain\",\"c.example\"]\n",
	} {
		writeFile(t, filepath.Join(dir, name), body)
	}
	if err := os.Mkdir(filepath.Join(dir, "d_v6.orig.post"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "d_v6.orig"), "download of d\n")

	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	want := map[string]string{
		"a_v4.orig":              "download of a\n",
		"b_v4.orig":              "baseline of b\n",
		"b_v4.orig.xxhash128":    "baseline digest of b\n",
		"c.orig":                 "untouched download of c\n",
		"c.orig.etag":            `"c"`,
		"c.parsed.ndjson":        "[\"domain\",\"c.example\"]\n",
		"d_v6.orig":              "download of d\n",
		"e.parsed.ndjson":        "[\"d\",\"new.example\"]\n",
		"e.parsed.src.xxhash128": "new record\n",
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			t.Errorf("%s is left a %v", e.Name(), e.Type())
			continue
		}
		got[e.Name()] = readFile(t, filepath.Join(dir, e.Name()))
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s = %q, want %q", name, got[name], body)
		}
		delete(got, name)
	}
	for name := range got {
		t.Errorf("recovery left %s", name)
	}
}

const killChildEnv = "PFB_FEEDSTAGE_KILL_CHILD"

// killStage is the stage and feed both sides of the kill test use, over the folders below root.
func killStage(root string) (*Stage, Feed) {
	stage := &Stage{
		Paths:   Paths{FeedDir: filepath.Join(root, "orig"), ScriptDirs: []string{filepath.Join(root, "scripts")}},
		Fetcher: &feedfetch.Fetcher{Policy: feedfetch.Policy{LocalDirs: []string{filepath.Join(root, "db")}}},
	}
	return stage, Feed{ID: "ipv4:Feed_v4", Kind: "ipv4", Name: "Feed_v4", State: "enabled", Format: "auto",
		Source: "file://" + filepath.Join(root, "db", "feed.txt")}
}

// killChild runs the feed in a child process that announces on fd 3 when its post-script has succeeded, before the
// restore point is put back, and then waits on stdin for the KILL. It never returns.
func killChild(root string) {
	step = func(name string) {
		if name != "post-script" {
			return
		}
		event := os.NewFile(3, "event")
		_, _ = event.Write([]byte("ready"))
		_ = event.Close()
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(3) // the parent went away without the KILL
	}
	stage, feed := killStage(root)
	feed.PostScript = "post.sh"
	run(stage, feed, "none")
	os.Exit(2) // the boundary was never reached
}

// Scenario: KILL between a successful IP post-script and its restore.
// Given a published baseline and a changed source with a post-script that rewrites the download, when the Updater is
// killed after the script and before the restore point is renamed back, then the next entry's recovery puts the baseline
// back (the script's output is never kept as a download), and the next run publishes the change.
func TestKillBetweenPostScriptAndRestoreIsRecovered(t *testing.T) {
	if root := os.Getenv(killChildEnv); root != "" {
		killChild(root)
	}
	root := t.TempDir()
	for _, d := range []string{"orig", "db", "scripts"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stage, feed := killStage(root)
	source := filepath.Join(root, "db", "feed.txt")
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	writeFile(t, source, "198.51.100.2\n")
	if err := os.WriteFile(filepath.Join(root, "scripts", "post.sh"), []byte("#!/bin/sh\nprintf 'script output\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	events, eventWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	hold, holdWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdWriter.Close()
	// The cap only fails a hung run: on expiry the child is killed, which ends the read below with EOF.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKillBetweenPostScriptAndRestoreIsRecovered$", "-test.count=1")
	child.Env = append(os.Environ(), killChildEnv+"="+root)
	child.ExtraFiles = []*os.File{eventWriter}
	child.Stdin = hold
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	eventWriter.Close()
	hold.Close()
	buf := make([]byte, len("ready"))
	if _, err := io.ReadFull(events, buf); err != nil {
		werr := child.Wait()
		t.Fatalf("the child never reached the post-script boundary: %v (child: %v)", err, werr)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()

	orig := filepath.Join(root, "orig", "Feed_v4.orig")
	if got := readFile(t, orig); got != "script output\n" {
		t.Fatalf("at the KILL the download holds %q, want the script's output (the window was not hit)", got)
	}
	if got := readFile(t, orig+".post"); got != "198.51.100.2\n" {
		t.Fatalf("at the KILL the restore point holds %q, want the download", got)
	}

	if err := Recover(filepath.Join(root, "orig")); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got := readFile(t, orig); got != "198.51.100.1\n" {
		t.Fatalf("after recovery the download is %q, want the baseline the published list was parsed from", got)
	}
	if got := readFile(t, filepath.Join(root, "orig", "Feed_v4.parsed.ip")); got != "198.51.100.1\n" {
		t.Fatalf("after recovery the list is %q, want the baseline's", got)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "orig"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".orig.post") || strings.Contains(e.Name(), ".pfb") {
			t.Errorf("recovery left %s", e.Name())
		}
	}

	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the run after recovery = %+v, want the change published", r)
	}
	if got := readFile(t, filepath.Join(root, "orig", "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Fatalf("the run after recovery published %q, want the changed source", got)
	}
}
