package update

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// The PHP DNSBL downloads of a box before the cutover (issue #4258): dnsblorig holds each feed's .orig with its validators
// and digests; dnsbl holds PHP's parsed lists, the fail markers, for D a copy the Core Updater already published (PHP's older
// one is superseded: it goes, so that no later move brings it back), and for B_2 a digest left with no copy beside it, which
// describes nothing the move brings.
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
		"dnsblorig/L.orig.etag":      `"etag-l"`,
		"dnsbl/A.txt":                "php's parsed list",
		"dnsbl/C.fail":               "",
		"dnsbl/D.orig":               "the Core Updater's d.example\n",
		"dnsbl/D.orig.xxhash128":     "dddd",
		"dnsbl/B_2.orig.xxhash128":   "a stale digest",
		"dnsbl/B_2.orig.size":        "123",
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
	// a link is never a feed's download, nor a sidecar: it stays where it is, and so does a link's sidecar
	for link, target := range map[string]string{"L.orig": "/etc/passwd", "C.orig.etag": "/etc/hostname"} {
		if err := os.Symlink(target, filepath.Join(db, "dnsblorig", link)); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// filesUnder is every entry under db: a file's content, a link's target.
func filesUnder(t *testing.T, db string) map[string]string {
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
		"dnsblorig/E.orig.post":   "a post script's staging copy",
		"dnsblorig/bad-name.orig": "not a feed name",
		"dnsblorig/notes.txt":     "not a download",
		"dnsblorig/L.orig":        "-> /etc/passwd",
		"dnsblorig/L.orig.etag":   `"etag-l"`,
		"dnsblorig/C.orig.etag":   "-> /etc/hostname",
	}
}

func TestEveryDNSBLDownloadMovesWithItsValidatorsAndDigests(t *testing.T) {
	db := dnsblOrigFixture(t)

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got, want := filesUnder(t, db), wantMoved(); !maps.Equal(got, want) {
		t.Fatalf("after the move:\n got %v\nwant %v", got, want)
	}
}

func TestTheMoveMakesTheCoreUpdatersFolder(t *testing.T) {
	db := t.TempDir()
	if err := os.MkdirAll(filepath.Join(db, "dnsblorig"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "dnsblorig", "A.orig"), []byte("a.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got, want := filesUnder(t, db), map[string]string{"dnsbl/A.orig": "a.example\n"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestASecondMoveChangesNothing(t *testing.T) {
	db := dnsblOrigFixture(t)
	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}
	before := filesUnder(t, db)

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got := filesUnder(t, db); !maps.Equal(got, before) {
		t.Fatalf("the second move changed the files:\n got %v\nwant %v", got, before)
	}
}

// cutAt makes the move's step-th write (a link or a removal) fail, for the rest of the test.
func cutAt(t *testing.T, step int) {
	t.Helper()
	writes := 0
	cut := func() error {
		if writes++; writes == step {
			return errors.New("cut short")
		}
		return nil
	}
	dnsblOrigLink = func(from, to string) error {
		if err := cut(); err != nil {
			return err
		}
		return os.Link(from, to)
	}
	dnsblOrigRemove = func(name string) error {
		if err := cut(); err != nil {
			return err
		}
		return os.Remove(name)
	}
	t.Cleanup(func() { dnsblOrigLink, dnsblOrigRemove = os.Link, os.Remove })
}

func TestAMoveCutShortAtAnyStepCompletesOnTheNext(t *testing.T) {
	want := wantMoved()
	for step := 1; ; step++ {
		db := dnsblOrigFixture(t)
		cutAt(t, step)
		err := MoveDNSBLOrig(db)
		dnsblOrigLink, dnsblOrigRemove = os.Link, os.Remove
		if err == nil {
			if step == 1 {
				t.Fatal("the move made no write")
			}
			return // every step was cut once
		}
		cut := filesUnder(t, db)
		for _, feed := range []string{"A", "B_2", "C"} {
			// a moved download the Core Updater would trust has exactly the sidecars that describe it
			if _, moved := cut["dnsbl/"+feed+".orig"]; !moved {
				continue
			}
			for _, s := range dnsblOrigSidecars {
				name := "dnsbl/" + feed + s
				wantBody, wantOK := want[name]
				if got, ok := cut[name]; ok != wantOK || got != wantBody {
					t.Fatalf("step %d: %s.orig is in dnsbl beside %s = %q (present %v), want %q (present %v)", step, feed, name, got, ok, wantBody, wantOK)
				}
			}
		}

		if err := MoveDNSBLOrig(db); err != nil {
			t.Fatalf("step %d: the next move: %v", step, err)
		}

		if got := filesUnder(t, db); !maps.Equal(got, want) {
			t.Fatalf("step %d: after the next move:\n got %v\nwant %v", step, got, want)
		}
	}
}

func TestNoDNSBLDownloadsNoMove(t *testing.T) {
	db := t.TempDir()

	if err := MoveDNSBLOrig(db); err != nil {
		t.Fatal(err)
	}

	if got := filesUnder(t, db); len(got) != 0 {
		t.Fatalf("a box with no dnsblorig got %v", got)
	}
	if _, err := os.Lstat(filepath.Join(db, "dnsbl")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no dnsbl folder is made for nothing to move: %v", err)
	}
}
