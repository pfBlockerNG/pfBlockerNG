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
		"a dot member":                      {entries: map[string]string{"GeoLite2-Country.mmdb": "new", ".cc.lock": "x"}},
		"the country folder":                {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "cc": "x"}, prepare: linkedCC},
		"a live folder":                     {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: liveDir("LICENSE.txt")},
		"a folder over a file":              {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "sub/notes.txt": "x"}, prepare: liveFile("sub")},
		"a dot-folder link to a folder":     {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: dotFolderLink("LICENSE.txt")},
		"a link to a folder of the archive": {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: ownFolderLink("LICENSE.txt")},
		"a folder over a dangling link":     {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "sub/notes.txt": "x"}, prepare: danglingLink("sub")},
		"an unresolvable link":              {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: loopLink("LICENSE.txt")},
		"a foreign link":                    {entries: map[string]string{"GeoLite2-Country.mmdb": "new", "LICENSE.txt": "x"}, prepare: foreignLink("LICENSE.txt")},
		"a failed extraction":               {extract: func(string) error { return os.ErrInvalid }},
		"a failed link rename":              {entries: map[string]string{"GeoLite2-Country.mmdb": "new"}, prepare: failRenames},
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

func dotFolderLink(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		theirs := t.TempDir() // .local is a link, but to no generation of this code
		if err := os.Mkdir(filepath.Join(theirs, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(theirs, filepath.Join(share, ".local")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(".local/"+name, filepath.Join(share, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func ownFolderLink(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		gens := generations(t, share, "GeoLite2-Country.tar.gz")
		if err := os.Mkdir(filepath.Join(share, gens[0], "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(".GeoLite2-Country.tar.gz/sub", filepath.Join(share, name)); err != nil {
			t.Fatal(err) // through the archive's own link, but to another entry: a folder
		}
	}
}

func danglingLink(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		if err := os.Symlink(filepath.Join(share, "gone"), filepath.Join(share, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func loopLink(name string) func(*testing.T, string) {
	return func(t *testing.T, share string) {
		if err := os.Symlink(name, filepath.Join(share, name)); err != nil {
			t.Fatal(err) // resolves to itself: whether it names a folder cannot be told
		}
	}
}

func failRenames(t *testing.T, _ string) {
	real := rename
	rename = func(string, string) error { return syscall.EIO }
	t.Cleanup(func() { rename = real })
}

// A link at an entry name that this code did not make is replaced like the file it stands for, as the merge did before
// #4142, unless it names a folder (the country folder, an administrator's directory): dangling, to a file, or through a
// dot folder that is no archive link of this code.
func TestALinkAtAnEntryNameIsReplacedUnlessItNamesAFolder(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, share string) string{
		"dangling": func(t *testing.T, share string) string { return filepath.Join(share, "gone", "LICENSE.txt") },
		"to a file": func(t *testing.T, share string) string {
			path := filepath.Join(t.TempDir(), "LICENSE.txt")
			if err := os.WriteFile(path, []byte("theirs"), 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"through a dot folder": func(t *testing.T, share string) string {
			if err := os.Mkdir(filepath.Join(share, ".local"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(share, ".local", "LICENSE.txt"), []byte("theirs"), 0o644); err != nil {
				t.Fatal(err)
			}
			return ".local/LICENSE.txt"
		},
	} {
		t.Run(name, func(t *testing.T) {
			share := t.TempDir()
			if err := os.Symlink(prepare(t, share), filepath.Join(share, "LICENSE.txt")); err != nil {
				t.Fatal(err)
			}
			if !mergeIntoDir(share, "GeoLite2-Country.tar.gz", writeEntries(map[string]string{"LICENSE.txt": "new"})) {
				t.Fatal("the publication failed")
			}
			assertEntry(t, share, "LICENSE.txt", "new")
			if to, _ := os.Readlink(filepath.Join(share, "LICENSE.txt")); to != ".GeoLite2-Country.tar.gz/LICENSE.txt" {
				t.Errorf("LICENSE.txt links to %q, want the archive's entry link", to)
			}
		})
	}
}

// An entry relink that fails after the archive link switched is reported as a failed publication (the conversion then
// waits), and the next publication finishes the switch.
func TestAFailedEntryRelinkIsReportedAndFinishedNextTime(t *testing.T) {
	share := t.TempDir()
	for _, name := range []string{"a.csv", "b.csv"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	real := rename
	failed := false
	rename = func(from, to string) error {
		if strings.HasSuffix(from, ".entry") && filepath.Base(to) == "b.csv" && !failed {
			failed = true
			return syscall.EIO
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	entries := writeEntries(map[string]string{"a.csv": "new", "b.csv": "new"})
	if mergeIntoDir(share, "GeoLite2-Country-CSV.zip", entries) || !failed {
		t.Fatal("a failed entry relink was not reported")
	}
	if _, err := os.Lstat(filepath.Join(share, ".GeoLite2-Country-CSV.zip.entry")); err == nil {
		t.Error("the temp entry link was left behind")
	}
	if !mergeIntoDir(share, "GeoLite2-Country-CSV.zip", entries) {
		t.Fatal("the next publication failed")
	}
	assertEntry(t, share, "a.csv", "new")
	assertEntry(t, share, "b.csv", "new")
}

// An archive whose entry is a folder republishes over its own link to that folder.
func TestAFolderEntryRepublishesOverItsOwnLink(t *testing.T) {
	share := t.TempDir()
	for _, content := range []string{"v1", "v2"} {
		if !mergeIntoDir(share, "GeoLite2-Country.tar.gz", writeEntries(map[string]string{"extra/notes.txt": content})) {
			t.Fatalf("publishing %s failed", content)
		}
	}
	assertEntry(t, share, "extra/notes.txt", "v2")
}

// The archive's link is named for its download, .<download>, without the transfer's .raw suffix.
func TestTheArchiveLinkIsNamedForTheDownload(t *testing.T) {
	share := t.TempDir()
	merge := archiveMerge(filepath.Join(share, "GeoLite2-Country.tar.gz.raw"))
	if !merge(share, writeEntries(map[string]string{"GeoLite2-Country.mmdb": "v1"})) {
		t.Fatal("the publication failed")
	}
	if to, err := os.Readlink(filepath.Join(share, "GeoLite2-Country.mmdb")); err != nil || to != ".GeoLite2-Country.tar.gz/GeoLite2-Country.mmdb" {
		t.Errorf("the entry links to %q, %v", to, err)
	}
}

// An archive name that would not name a link of its own beside the entries (empty, ".", "..", one with a slash, or one
// whose link would be another archive's temp entry link) refuses the publication and touches nothing.
func TestAnArchiveNameThatNamesNoLinkIsRefused(t *testing.T) {
	for _, archive := range []string{"", ".", "..", "a/b", "GeoLite2-Country.tar.gz.entry", ".GeoLite2-Country.tar.gz.lock"} {
		t.Run(archive, func(t *testing.T) {
			parent := t.TempDir()
			share := filepath.Join(parent, "share")
			if err := os.Mkdir(share, 0o755); err != nil {
				t.Fatal(err)
			}
			if mergeIntoDir(share, archive, writeEntries(map[string]string{"x.csv": "x"})) {
				t.Fatal("published")
			}
			for _, dir := range []string{parent, share} {
				if entries, _ := os.ReadDir(dir); len(entries) != map[string]int{parent: 1, share: 0}[dir] {
					t.Errorf("%s holds %d entries after the refusal", dir, len(entries))
				}
			}
		})
	}
}
