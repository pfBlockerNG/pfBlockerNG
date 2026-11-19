package feedfetch

import (
	"archive/zip"
	"bytes"
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// writeMember refuses a member name that would leave the staging directory, whatever checked the names before it
// (pfb_archive_unsafe_member is the first line; this is the last).
func TestWriteMemberRefusesANameThatLeavesTheDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "staged")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{}
	for _, name := range []string{"../escape", "a/../../escape", "/abs/escape"} {
		if err := f.writeMember(dir, name, false, true, strings.NewReader("x")); err == nil {
			t.Errorf("writeMember(%q) = nil, want a refusal", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); err == nil {
		t.Errorf("a member was written outside the staging directory")
	}
	if err := f.writeMember(dir, "ok/file", false, true, strings.NewReader("x")); err != nil {
		t.Errorf("writeMember(ok/file) = %v, want nil", err)
	}
}

// A merge whose later rename fails puts back every live file an earlier rename already replaced: the share holds the old
// generation whole, never a mix (PHP leaves the mix; CodeRabbit on #4059).
func TestAMergeThatFailsPartWayRestoresWhatItReplaced(t *testing.T) {
	share := t.TempDir()
	for name, content := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	real := rename
	rename = func(from, to string) error {
		if filepath.Dir(to) == share && filepath.Base(to) == "b.csv" && strings.Contains(from, ".pfbstagedir_") {
			calls++
			return os.ErrPermission
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	f := &Fetcher{}
	ok := f.mergeIntoDir(share, func(dir string) error {
		for name, content := range map[string]string{"a.csv": "new a\n", "b.csv": "new b\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if ok || calls == 0 {
		t.Fatalf("(merged, failed renames) = (%v, %d), want a failed merge", ok, calls)
	}
	for name, want := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		got, err := os.ReadFile(filepath.Join(share, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = (%q, %v), want %q", name, got, err, want)
		}
	}
	entries, _ := os.ReadDir(share)
	if len(entries) != 2 {
		t.Errorf("the share holds %d entries after the failed merge, want the 2 live files only", len(entries))
	}
}

// A rollback whose own rename fails keeps the backup: the old file is not lost with it (CodeRabbit on #4059).
func TestAFailedRollbackKeepsTheBackup(t *testing.T) {
	share := t.TempDir()
	for name, content := range map[string]string{"a.csv": "old a\n", "b.csv": "old b\n"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	real := rename
	rename = func(from, to string) error {
		if strings.Contains(from, ".pfbstagedir_") && filepath.Base(to) == "b.csv" {
			return os.ErrPermission // the publication fails part-way
		}
		if strings.Contains(from, ".pfbbackup_") {
			return os.ErrPermission // and so does putting a.csv back
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	f := &Fetcher{}
	ok := f.mergeIntoDir(share, func(dir string) error {
		for name, content := range map[string]string{"a.csv": "new a\n", "b.csv": "new b\n"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if ok {
		t.Fatal("the merge succeeded, want a failure")
	}
	kept, _ := filepath.Glob(filepath.Join(share, ".pfbbackup_*", "a.csv"))
	if len(kept) != 1 {
		t.Fatalf("backups of a.csv after the failed rollback: %v, want the one copy kept", kept)
	}
	if got, err := os.ReadFile(kept[0]); err != nil || string(got) != "old a\n" {
		t.Errorf("kept backup = (%q, %v), want the old a.csv", got, err)
	}
}

// freeBSDLink is link(2) as FreeBSD has it: it follows a symbolic link (Linux's links the link itself).
func freeBSDLink(t *testing.T) {
	real := link
	link = func(from, to string) error {
		p, err := filepath.EvalSymlinks(from)
		if err != nil {
			return err
		}
		return os.Link(p, to)
	}
	t.Cleanup(func() { link = real })
}

// A live symlink is backed up as the link it is: a dangling one does not refuse every later merge, and a rollback puts it
// back as a link, not as a copy of what it points at (#4059 review).
func TestALiveSymlinkIsBackedUpAsALink(t *testing.T) {
	t.Run("a dangling link is replaced", func(t *testing.T) {
		freeBSDLink(t)
		share := t.TempDir()
		if err := os.Symlink(filepath.Join(t.TempDir(), "gone.mmdb"), filepath.Join(share, "GeoLite2-Country.mmdb")); err != nil {
			t.Fatal(err)
		}
		ok := (&Fetcher{}).mergeIntoDir(share, func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "GeoLite2-Country.mmdb"), []byte("new"), 0o644)
		})
		got, err := os.ReadFile(filepath.Join(share, "GeoLite2-Country.mmdb"))
		if !ok || err != nil || string(got) != "new" {
			t.Errorf("(merged, database) = (%v, %q, %v), want the new database", ok, got, err)
		}
	})
	t.Run("a rollback restores the link", func(t *testing.T) {
		freeBSDLink(t)
		share := t.TempDir()
		elsewhere := filepath.Join(t.TempDir(), "a.csv")
		if err := os.WriteFile(elsewhere, []byte("old a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(share, "a.csv")); err != nil {
			t.Fatal(err)
		}
		real := rename
		rename = func(from, to string) error {
			if strings.Contains(from, ".pfbstagedir_") && filepath.Base(to) == "b.csv" {
				return os.ErrPermission
			}
			return real(from, to)
		}
		t.Cleanup(func() { rename = real })
		ok := (&Fetcher{}).mergeIntoDir(share, func(dir string) error {
			for _, name := range []string{"a.csv", "b.csv"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("new\n"), 0o644); err != nil {
					return err
				}
			}
			return nil
		})
		to, err := os.Readlink(filepath.Join(share, "a.csv"))
		if ok || err != nil || to != elsewhere {
			t.Errorf("(merged, a.csv link) = (%v, %q, %v), want a failed merge and the link to %s", ok, to, err, elsewhere)
		}
	})
}

// A TOP1M publication whose new list cannot be renamed into place, and whose old list then cannot be put back, still
// leaves the old list on disk beside the target, as PHP's ".pfbtop1m_active_" does (#3978 review).
func TestATop1MListThatCannotBePutBackStaysOnDisk(t *testing.T) {
	dir := t.TempDir()
	target, base := filepath.Join(dir, "top-1m.csv"), filepath.Join(dir, "top-1m.csv.zip")
	stage, raw := filepath.Join(dir, "stage"), filepath.Join(dir, "top-1m.csv.zip.raw")
	for path, content := range map[string]string{target: "old\n", stage: "new\n", raw: "raw"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	real := rename
	rename = func(from, to string) error {
		if to == target {
			return os.ErrPermission // neither the new list nor the old one reaches the target
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	if top1mCommit(stage, target, base, raw) {
		t.Fatal("the commit succeeded, want a failure")
	}
	var kept []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if b, _ := os.ReadFile(p); string(b) == "old\n" {
				kept = append(kept, p)
			}
		}
		return nil
	})
	if len(kept) == 0 {
		t.Error("no file holds the old list after the failed commit")
	}
}

// A TOP1M publication that succeeds leaves the list and its baseline, and nothing it set aside on the way.
func TestATop1MCommitLeavesNoResidue(t *testing.T) {
	dir := t.TempDir()
	target, base := filepath.Join(dir, "top-1m.csv"), filepath.Join(dir, "top-1m.csv.zip")
	stage, raw := filepath.Join(dir, "stage"), filepath.Join(dir, "raw")
	for path, content := range map[string]string{target: "old\n", stage: "new\n", raw: "raw", base + ".orig": "old raw"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !top1mCommit(stage, target, base, raw) {
		t.Fatal("the commit failed")
	}
	os.Remove(raw) // the caller's
	var names []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"top-1m.csv", "top-1m.csv.zip.orig", "top-1m.csv.zip.xxhash128"}
	if !slices.Equal(names, want) {
		t.Errorf("the directory holds %v, want %v", names, want)
	}
}

// After a 304 that reads changed, the list comes from a second, full download: the validators stored with it are that
// download's, not the 304's (#4066 review).
func TestATop1MFullDownloadAfterA304StoresItsOwnValidators(t *testing.T) {
	body := zipOf(t, "top-1m.csv", "1,google.com\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v2"`)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	dir := t.TempDir()
	url := "http://tranco-list.eu:" + port + "/top-1m.csv.zip"
	base := filepath.Join(dir, "top-1m.csv.zip")
	sum := digest.Bytes(body)
	for path, content := range map[string]string{ // a trusted baseline, but the published list is gone: reads changed
		base + ".orig": string(body), base + ".xxhash128": sum, base + ".orig.etag": `"v1"`,
		base + ".source": top1mIdentity("tranco", url, nil),
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.11")}, nil
	}
	res := f.DownloadExtras(context.Background(), ExtrasConfig{DBDir: dir, Detect: true},
		[]Extra{{Kind: "top1m", URL: url, Dir: dir, Download: "top-1m.csv.zip", File: "top-1m.csv", Provider: "tranco"}})
	etag, _ := os.ReadFile(base + ".orig.etag")
	if !res.OK || !res.Top1MChanged || string(etag) != `"v2"` {
		t.Errorf("(ok, changed, stored ETag) = (%v, %v, %s), want (true, true, \"v2\")", res.OK, res.Top1MChanged, etag)
	}
}

func zipOf(t *testing.T, name, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, err := zw.Create(name)
	if err == nil {
		_, err = w.Write([]byte(content))
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// A category folder whose swap fails after the live folder moved aside is put back whole, and nothing staged is left.
func TestACategorySwapThatFailsPutsTheFolderBack(t *testing.T) {
	db := t.TempDir()
	live := filepath.Join(db, "ut1")
	if err := os.Mkdir(live, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "ut1_adult"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	real := rename
	rename = func(from, to string) error {
		if to == live && strings.Contains(from, ".pfbstagedir_") {
			calls++
			return os.ErrPermission
		}
		return real(from, to)
	}
	t.Cleanup(func() { rename = real })
	ok := replaceDir(live, func(dir string) error {
		return os.WriteFile(filepath.Join(dir, "ut1_adult"), []byte("new\n"), 0o644)
	})
	if ok || calls == 0 {
		t.Fatalf("(replaced, failed swaps) = (%v, %d), want a failed swap", ok, calls)
	}
	if got, err := os.ReadFile(filepath.Join(live, "ut1_adult")); err != nil || string(got) != "old\n" {
		t.Errorf("ut1/ut1_adult = (%q, %v), want the old folder back", got, err)
	}
	if entries, _ := os.ReadDir(db); len(entries) != 1 {
		t.Errorf("the database folder holds %d entries after the failed swap, want the category folder only", len(entries))
	}
}
