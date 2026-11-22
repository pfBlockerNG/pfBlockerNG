package feedstage

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

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

// killStage is the stage and feed both sides of the kill test use, over the folders below root.
func killStage(root string) (*Stage, Feed) {
	stage := &Stage{
		Paths:   Paths{FeedDir: filepath.Join(root, "orig"), ScriptDirs: []string{filepath.Join(root, "scripts")}},
		Fetcher: &feedfetch.Fetcher{Policy: feedfetch.Policy{LocalDirs: []string{filepath.Join(root, "db")}}},
	}
	return stage, Feed{ID: "ipv4:Feed_v4", Kind: "ipv4", Name: "Feed_v4", State: "enabled", Format: "auto",
		Source: "file://" + filepath.Join(root, "db", "feed.txt")}
}

// Scenario: KILL right after a successful IP post-script.
// Given a published baseline and a changed source with a post-script that rewrites its file, when the Updater is killed
// right after the script, then the feed folder is the baseline byte for byte (the script's output and the new download
// never reached it), the next entry's recovery leaves the baseline, and the next run publishes the change.
func TestKillAfterThePostScriptIsRecovered(t *testing.T) {
	if boundary := os.Getenv(killAtEnv); boundary != "" {
		killChildAt(os.Getenv(killRootEnv), boundary)
	}
	root := killRoot(t, "198.51.100.1\n")
	dir := filepath.Join(root, "orig")
	baseline := publishedState(t, dir)
	writeFile(t, filepath.Join(root, "db", "feed.txt"), "198.51.100.2\n")
	killScript(t, root, "post.sh", `printf 'script output\n' > "$1"`)
	killAt(t, "TestKillAfterThePostScriptIsRecovered", root, "post-script")
	if got := publishedState(t, dir); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("at the KILL the feed folder is\n %q\nwant the baseline byte for byte\n %q", got, baseline)
	}

	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.orig")); got != "198.51.100.1\n" {
		t.Fatalf("after recovery the download is %q, want the baseline the published list was parsed from", got)
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.1\n" {
		t.Fatalf("after recovery the list is %q, want the baseline's", got)
	}
	journalLeftovers(t, dir, "after recovery")

	stage, feed := killStage(root)
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the run after recovery = %+v, want the change published", r)
	}
	if got := readFile(t, filepath.Join(dir, "Feed_v4.parsed.ip")); got != "198.51.100.2\n" {
		t.Fatalf("the run after recovery published %q, want the changed source", got)
	}
}
