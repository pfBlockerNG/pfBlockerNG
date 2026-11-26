package update

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The PHP DNSBL downloads of a box before the cutover (issue #4258): dnsblorig holds each feed's .orig with its validators
// and digests; dnsbl holds PHP's parsed lists, the fail markers, and for D a copy the Core Updater already published.
func dnsblOrigFixture(t *testing.T) string {
	t.Helper()
	db := t.TempDir()
	files := map[string]string{
		"dnsblorig/A.orig":           "a.example\n",
		"dnsblorig/A.orig.etag":      `"etag-a"`,
		"dnsblorig/A.orig.lastmod":   "1700000000",
		"dnsblorig/A.orig.xxhash128": "aaaa",
		"dnsblorig/B_2.orig":         "b.example\n",
		"dnsblorig/B_2.orig.md5":     "bbbb",
		"dnsblorig/C.orig":           "c.example\n",
		"dnsblorig/D.orig":           "php's older d.example\n",
		"dnsblorig/D.orig.etag":      `"etag-d-php"`,
		"dnsblorig/E.orig.post":      "a post script's staging copy",
		"dnsblorig/bad-name.orig":    "not a feed name",
		"dnsblorig/notes.txt":        "not a download",
		"dnsbl/A.txt":                "php's parsed list",
		"dnsbl/C.fail":               "",
		"dnsbl/D.orig":               "the Core Updater's d.example\n",
		"dnsbl/D.orig.xxhash128":     "dddd",
	}
	for name, body := range files {
		p := filepath.Join(db, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// a link is never a feed's download: it stays where it is
	if err := os.Symlink("/etc/passwd", filepath.Join(db, "dnsblorig", "L.orig")); err != nil {
		t.Fatal(err)
	}
	return db
}

// tree is every entry under db: a file's content, a link's target.
func tree(t *testing.T, db string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(db, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(db, p)
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			out[rel] = "-> " + target
			return err
		}
		b, err := os.ReadFile(p)
		out[rel] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wantMoved() map[string]string {
	return map[string]string{
		"dnsbl/A.orig":            "a.example\n",
		"dnsbl/A.orig.etag":       `"etag-a"`,
		"dnsbl/A.orig.lastmod":    "1700000000",
		"dnsbl/A.orig.xxhash128":  "aaaa",
		"dnsbl/B_2.orig":          "b.example\n",
		"dnsbl/B_2.orig.md5":      "bbbb",
		"dnsbl/C.orig":            "c.example\n",
		"dnsbl/A.txt":             "php's parsed list",
		"dnsbl/C.fail":            "",
		"dnsbl/D.orig":            "the Core Updater's d.example\n",
		"dnsbl/D.orig.xxhash128":  "dddd",
		"dnsblorig/D.orig":        "php's older d.example\n",
		"dnsblorig/D.orig.etag":   `"etag-d-php"`,
		"dnsblorig/E.orig.post":   "a post script's staging copy",
		"dnsblorig/bad-name.orig": "not a feed name",
		"dnsblorig/notes.txt":     "not a download",
		"dnsblorig/L.orig":        "-> /etc/passwd",
	}
}

func TestEveryDNSBLDownloadMovesWithItsValidatorsAndDigests(t *testing.T) {
	db := dnsblOrigFixture(t)

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got, want := tree(t, db), wantMoved(); !maps.Equal(got, want) {
		t.Fatalf("after the move:\n got %v\nwant %v", got, want)
	}
}

func TestTheMoveKeepsEachDownloadsModificationTime(t *testing.T) {
	// the Core Updater sends a Last-Modified from the published copy's time, as PHP did
	testTime := time.Unix(1700000000, 0)
	db := dnsblOrigFixture(t)
	if err := os.Chtimes(filepath.Join(db, "dnsblorig", "A.orig"), testTime, testTime); err != nil {
		t.Fatal(err)
	}

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(db, "dnsbl", "A.orig"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(testTime) {
		t.Fatalf("A.orig's time is %v, want %v", fi.ModTime(), testTime)
	}
}

func TestASecondMoveChangesNothing(t *testing.T) {
	db := dnsblOrigFixture(t)
	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}
	before := tree(t, db)

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got := tree(t, db); !maps.Equal(got, before) {
		t.Fatalf("the second move changed the files:\n got %v\nwant %v", got, before)
	}
}

func TestAMoveCutShortAtAnyStepCompletesOnTheNext(t *testing.T) {
	for step := 1; ; step++ {
		db := dnsblOrigFixture(t)
		renames := 0
		dnsblOrigRename = func(from, to string) error {
			if renames++; renames == step {
				return errors.New("cut short")
			}
			return os.Rename(from, to)
		}
		err := MoveDNSBLOrig(db)
		dnsblOrigRename = os.Rename
		if err == nil {
			if step == 1 {
				t.Fatal("the move made no rename")
			}
			return // every step was cut once
		}
		cut := tree(t, db)
		for name := range cut {
			// never a download the Core Updater would trust beside sidecars that do not describe it
			if base, ok := strings.CutSuffix(name, ".orig"); ok && strings.HasPrefix(base, "dnsbl/") {
				for _, s := range []string{".etag", ".lastmod", ".xxhash128", ".md5"} {
					if _, left := cut["dnsblorig/"+strings.TrimPrefix(base, "dnsbl/")+".orig"+s]; left {
						t.Fatalf("step %d: %s moved while its %s did not", step, name, s)
					}
				}
			}
		}

		if err := MoveDNSBLOrig(db); err != nil {
			t.Fatalf("step %d: the next move: %v", step, err)
		}

		if got, want := tree(t, db), wantMoved(); !maps.Equal(got, want) {
			t.Fatalf("step %d: after the next move:\n got %v\nwant %v", step, got, want)
		}
	}
}

func TestNoDNSBLDownloadsNoMove(t *testing.T) {
	db := t.TempDir()

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got := tree(t, db); len(got) != 0 {
		t.Fatalf("a box with no dnsblorig got %v", got)
	}
	if _, err := os.Lstat(filepath.Join(db, "dnsbl")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no dnsbl folder is made for nothing to move: %v", err)
	}
}
