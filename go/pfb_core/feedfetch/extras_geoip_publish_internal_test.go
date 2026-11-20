package feedfetch

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// writeEntries is an extraction that writes the named files with their contents.
func writeEntries(files map[string]string) func(string) error {
	return func(dir string) error {
		for name, content := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
}

func assertEntry(t *testing.T, share, name, want string) {
	t.Helper()
	if got, err := os.ReadFile(filepath.Join(share, name)); err != nil || string(got) != want {
		t.Errorf("%s = (%q, %v), want %q", name, got, err, want)
	}
}

// assertShare checks the share holds exactly the named visible entries (dot names aside).
func assertShare(t *testing.T, share string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(share)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			got = append(got, e.Name())
		}
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the share holds %v, want %v", got, want)
	}
}

// generations is the archive's generation folders in the share.
func generations(t *testing.T, share, archive string) []string {
	t.Helper()
	found, _ := filepath.Glob(filepath.Join(share, ".."+archive+".*.*"))
	var gens []string
	for _, g := range found {
		if info, err := os.Lstat(g); err == nil && info.IsDir() {
			gens = append(gens, filepath.Base(g))
		}
	}
	return gens
}

// An archive's entries are fixed links through one link per archive (#4142): every entry names
// .<archive>/<entry>, and a publication switches them all by one rename onto that link, so a reader never sees entries of
// two generations.
func TestAnArchiveIsPublishedByOneLinkRename(t *testing.T) {
	share := t.TempDir()
	const archive = "GeoLite2-Country.tar.gz"
	if !mergeIntoDir(share, archive, writeEntries(map[string]string{"GeoLite2-Country.mmdb": "v1", "LICENSE.txt": "l1"})) {
		t.Fatal("the first publication failed")
	}
	for _, name := range []string{"GeoLite2-Country.mmdb", "LICENSE.txt"} {
		if to, err := os.Readlink(filepath.Join(share, name)); err != nil || to != "."+archive+"/"+name {
			t.Errorf("%s links to %q, %v; want .%s/%s", name, to, err, archive, name)
		}
	}
	var onto []string
	real := rename
	rename = func(from, to string) error {
		onto = append(onto, to)
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	if !mergeIntoDir(share, archive, writeEntries(map[string]string{"GeoLite2-Country.mmdb": "v2", "LICENSE.txt": "l2"})) {
		t.Fatal("the second publication failed")
	}
	if want := []string{filepath.Join(share, "."+archive)}; !slices.Equal(onto, want) {
		t.Errorf("renames onto %v, want %v", onto, want)
	}
	assertEntry(t, share, "GeoLite2-Country.mmdb", "v2")
	assertEntry(t, share, "LICENSE.txt", "l2")
	assertShare(t, share, "GeoLite2-Country.mmdb", "LICENSE.txt")
	if gens := generations(t, share, archive); len(gens) != 2 {
		t.Errorf("generations %v, want the current and the previous", gens)
	}
}

// A live entry that is still a real file (from before #4142) is replaced by its link with one rename.
func TestARealShareFileBecomesItsLink(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "GeoLite2-Country.mmdb"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !mergeIntoDir(share, "GeoLite2-Country.tar.gz", writeEntries(map[string]string{"GeoLite2-Country.mmdb": "new"})) {
		t.Fatal("the publication failed")
	}
	assertEntry(t, share, "GeoLite2-Country.mmdb", "new")
	if info, err := os.Lstat(filepath.Join(share, "GeoLite2-Country.mmdb")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the entry is not a link: %v", err)
	}
}

// Two archives that ship an entry of the same name take turns at it: the later publication's copy is live.
func TestAnEntryTwoArchivesShipFollowsTheLaterOne(t *testing.T) {
	share := t.TempDir()
	if !mergeIntoDir(share, "GeoLite2-Country.tar.gz", writeEntries(map[string]string{"COPYRIGHT.txt": "country"})) ||
		!mergeIntoDir(share, "GeoLite2-ASN.tar.gz", writeEntries(map[string]string{"COPYRIGHT.txt": "asn"})) {
		t.Fatal("a publication failed")
	}
	assertEntry(t, share, "COPYRIGHT.txt", "asn")
}

// A publication that is refused or fails leaves the share as it was: no entry changes and no generation stays.
func TestARefusedArchivePublicationChangesNothing(t *testing.T) {
	seed := func(t *testing.T) string {
		share := t.TempDir()
		if !mergeIntoDir(share, "GeoLite2-Country.tar.gz", writeEntries(map[string]string{"GeoLite2-Country.mmdb": "old"})) {
			t.Fatal("the seed publication failed")
		}
		return share
	}
	cases := map[string]struct {
		prepare func(t *testing.T, share string)
		entries map[string]string
		extract func(string) error
	}{
		"a dot member":         {entries: map[string]string{"GeoLite2-Country.mmdb": "new", ".cc.lock": "x"}},
		"the country folder":   {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "cc": "x"}, prepare: linkedCC},
		"a live folder":        {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: liveDir("LICENSE.txt")},
		"a folder over a file": {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "sub/notes.txt": "x"}, prepare: liveFile("sub")},
		"a foreign link":       {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: foreignLink("LICENSE.txt")},
		"a failed extraction":  {extract: func(string) error { return os.ErrInvalid }},
		"a failed link rename": {entries: map[string]string{"GeoLite2-Country.mmdb": "new"}, prepare: failRenames},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			share := seed(t)
			before := generations(t, share, "GeoLite2-Country.tar.gz")
			if c.prepare != nil {
				c.prepare(t, share)
			}
			extract := c.extract
			if extract == nil {
				extract = writeEntries(c.entries)
			}
			if mergeIntoDir(share, "GeoLite2-Country.tar.gz", extract) {
				t.Fatal("published")
			}
			assertEntry(t, share, "GeoLite2-Country.mmdb", "old")
			if got := generations(t, share, "GeoLite2-Country.tar.gz"); !slices.Equal(got, before) {
				t.Errorf("generations %v, want %v", got, before)
			}
		})
	}
}

func linkedCC(t *testing.T, share string) {
	if err := os.Mkdir(filepath.Join(share, ".cc.1.00000000"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".cc.1.00000000", filepath.Join(share, "cc")); err != nil {
		t.Fatal(err)
	}
}

func liveDir(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		if err := os.MkdirAll(filepath.Join(share, name, "keep"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func liveFile(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		if err := os.WriteFile(filepath.Join(share, name), []byte("live"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func foreignLink(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		if err := os.Symlink(t.TempDir(), filepath.Join(share, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func failRenames(t *testing.T, _ string) {
	real := rename
	rename = func(string, string) error { return syscall.EIO }
	t.Cleanup(func() { rename = real })
}
