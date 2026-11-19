package feedfetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
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

// A hard link whose target cannot be a file (its path runs through a file) is skipped like any target that was not
// extracted, not a refusal of the whole archive.
func TestAHardLinkThroughAFileIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ut1_adult"), []byte("adult.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := linkMember(dir, "ut1_adult/sub", "ut1_x"); err != nil {
		t.Fatalf("linkMember through a file = %v, want the link skipped", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "ut1_x")); !os.IsNotExist(err) {
		t.Errorf("ut1_x exists (%v), want nothing published", err)
	}
}

// A member whose name resolves to the extraction folder itself ("t/." once its top folder is stripped) writes nothing,
// and the folder stays a folder.
func TestAMemberNamingTheExtractionFolderWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "staged")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &Fetcher{}
	for _, isReg := range []bool{false, true} {
		if err := f.writeMember(dir, ".", false, isReg, strings.NewReader("x")); err != nil {
			t.Errorf("writeMember(.) regular=%v = %v, want nothing written", isReg, err)
		}
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			t.Fatalf("the extraction folder is gone or no longer a folder (%v, %v)", info, err)
		}
	}
}

// redact hides every URL query and every form a secret travels in, and leaves reason codes alone: a short secret is no
// reason to rewrite them.
func TestRedactHidesSecretsAndKeepsReasonCodes(t *testing.T) {
	cfg := ExtrasConfig{MaxMindAccount: "123456", MaxMindKey: "maxmind-key", ASNToken: "asn token+1"}
	row := Extra{Username: "user", Password: "p w+d~x"}
	short := Extra{Password: "a"}
	for _, tc := range []struct {
		in   string
		x    Extra
		gone []string
		want string
	}{
		{in: "staging_space_low", x: short, want: "staging_space_low"},
		{in: `Get "HTTP://lists.example/bl.tar.gz?key=v": refused`, x: row, gone: []string{"key=v"}},
		{in: "fetch 'ftp://lists.example/bl.tar.gz?key=v' failed", x: row, gone: []string{"key=v"}},
		{in: "sent p%20w+d~x and p+w%2Bd~x and p%20w%2Bd~x", x: row, gone: []string{"p%20w+d~x", "p+w%2Bd~x", "p%20w%2Bd~x"}},
		{in: "auth " + base64.StdEncoding.EncodeToString([]byte("user:p w+d~x")), x: row, gone: []string{"dXNlcjpw"}},
		{in: "auth " + base64.StdEncoding.EncodeToString([]byte("123456:maxmind-key")), x: row, gone: []string{"MTIzNDU2"}},
		{in: "token asn+token%2B1 and asn%20token%2B1", x: row, gone: []string{"asn+token%2B1", "asn%20token%2B1"}},
	} {
		got := cfg.redact(tc.in, tc.x)
		if tc.want != "" && got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
		for _, g := range tc.gone {
			if strings.Contains(got, g) {
				t.Errorf("redact(%q) = %q still holds %q", tc.in, got, g)
			}
		}
	}
}

// The same cause gets the same refusal wherever an extraction meets it, with the file it was found in.
func TestExtractRefusedNamesItsFile(t *testing.T) {
	for _, tc := range []struct {
		err                   error
		stage, reason, detail string
	}{
		{errNotADatabase, "structural", "not_a_maxmind_db", "x.raw"},
		{errTop1MArchive, "extract", errTop1MArchive.Error(), "x.raw"},
		{errUnsafeMember, "member", "unsafe_member_name", "x.raw"},
	} {
		r := extractRefused(mimeZip, tc.err, "x.raw")
		if r.Stage != tc.stage || r.Reason != tc.reason || r.Detected != tc.detail {
			t.Errorf("extractRefused(%v) = (%q, %q, %q), want (%q, %q, %q)", tc.err, r.Stage, r.Reason, r.Detected,
				tc.stage, tc.reason, tc.detail)
		}
	}
}

// Each Extra words an extraction failure as pfb_download() does for it: its own name, the tool that ran, and the
// ceiling's status 153.
func TestAnExtrasExtractionFailureIsWordedAsPHPWordsIt(t *testing.T) {
	failed := errors.New("unexpected EOF")
	for _, tc := range []struct {
		what string
		err  error
		want string
	}{
		{"asn", failed, "asn extraction failed (gunzip exit 1)"},
		{"asn", errCeiling, "asn extraction failed (gunzip exit 153) -- output exceeded the extraction size ceiling"},
		{"top1m gzip", failed, "top1m extraction failed (gunzip exit 1)"},
		{"top1m tar", failed, "top1m extraction failed (tar exit 1)"},
		{"top1m zip", failed, "top1m zip extraction failed (tar exit 1)"},
		{"geoip", failed, "geoip extraction failed (tar exit 1)"},
		{"geoip zip", errCeiling, "geoip zip extraction failed (tar exit 153) -- output exceeded the extraction size ceiling"},
		{"blacklist", failed, "blacklist extraction failed (tar exit 1)"},
		{"blacklist", errNoCategory, "blacklist extraction failed (tar exit 0)"},
		{mimeTar, failed, "tar extraction failed (tar exit 1)"},
	} {
		if r := extractRefused(tc.what, tc.err, ""); r.Stage != "extract" || r.Reason != tc.want {
			t.Errorf("extractRefused(%q, %v) = (%q, %q), want (extract, %q)", tc.what, tc.err, r.Stage, r.Reason, tc.want)
		}
	}
}

// A longer secret is hidden whole even when a shorter one is part of it, and a query quoted with escaped quotes is
// hidden to its end.
func TestRedactHidesALongerSecretWholeAndAQuotedQuery(t *testing.T) {
	cfg := ExtrasConfig{MaxMindKey: "abcdef", ASNToken: "abcdefSECRETTAIL"}
	for in, gone := range map[string]string{
		"sent abcdefSECRETTAIL": "SECRETTAIL",
		`Get "http://lists.example/bl.tar.gz?key=q\"tok en\"": dial`: "tok en",
	} {
		if got := cfg.redact(in, Extra{}); strings.Contains(got, gone) {
			t.Errorf("redact(%q) = %q still holds %q", in, got, gone)
		}
	}
}

// A Blacklist archive that cannot be kept beside its folder is a publication failure, named without a path.
func TestABlacklistArchiveThatCannotBeKeptIsAPublicationFailure(t *testing.T) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "bl/adult/domains", Mode: 0o644, Size: 14})
	tw.Write([]byte("adult.example\n"))
	tw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(tb.Bytes()) }))
	t.Cleanup(srv.Close)
	origRename := rename
	rename = func(from, to string) error {
		if strings.HasSuffix(from, ".raw") {
			return os.ErrPermission
		}
		return origRename(from, to)
	}
	t.Cleanup(func() { rename = origRename })
	f := &Fetcher{RetryDelay: 1}
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.9")}, nil
	}
	db := t.TempDir()
	feedURL := "http://bl.example:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:] + "/ut1.tar"
	res := f.DownloadExtras(context.Background(), ExtrasConfig{DBDir: db},
		[]Extra{{Kind: "blacklist", URL: feedURL, Dir: db, Download: "ut1.tar", File: "ut1.tar", Name: "UT1"}})
	if r := res.Rows[0]; res.OK || r.Stage != "publish" || r.Reason != "publication_failed" || strings.Contains(r.Reason, db) {
		t.Errorf("(ok, stage, reason) = (%v, %q, %q), want (false, publish, publication_failed)", res.OK, r.Stage, r.Reason)
	}
}

// An apostrophe in a URL's path or query does not stop the query being hidden, and a password sent without a user is
// hidden in the Basic authorization it makes.
func TestRedactHidesQueriesPastAnApostropheAndAUserlessAuthorization(t *testing.T) {
	cfg := ExtrasConfig{MaxMindKey: "maxmind-key"}
	for in, gone := range map[string]string{
		`Get "https://h/x?token=ab'SECRETVALUE": dial`:                   "SECRETVALUE",
		`Get "https://h/o'brien/list.tgz?key=PATHSECRET": dial`:          "PATHSECRET",
		"auth " + base64.StdEncoding.EncodeToString([]byte(":hunter22")): "Omh1bnRlcjIy",
	} {
		if got := cfg.redact(in, Extra{Password: "hunter22"}); strings.Contains(got, gone) {
			t.Errorf("redact(%q) = %q still holds %q", in, got, gone)
		}
	}
}

// A short password's Basic authorization is long enough to hide without touching reason codes.
func TestRedactHidesAShortPasswordsAuthorization(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("user:pw12"))
	if got := (ExtrasConfig{}).redact("auth "+auth+" staging_space_low", Extra{Username: "user", Password: "pw12"}); strings.Contains(got, auth) ||
		!strings.Contains(got, "staging_space_low") {
		t.Errorf("redact = %q, want the authorization hidden and the reason code kept", got)
	}
}

// A URL's userinfo is hidden like its query, and an escaped quote in its path does not stop the query being hidden.
func TestRedactHidesUserinfoAndAQueryPastAnEscapedQuote(t *testing.T) {
	for in, gone := range map[string]string{
		"fetch ftp://bl:Sup3rSecret@hostile.example/ut1.tar.gz failed": "Sup3rSecret",
		`Get "http://user:pw@h/x": dial`:                               "user:pw",
		`Get "https://h/a\"b?key=TOKENVALUE": dial`:                    "TOKENVALUE",
	} {
		if got := (ExtrasConfig{}).redact(in, Extra{}); strings.Contains(got, gone) {
			t.Errorf("redact(%q) = %q still holds %q", in, got, gone)
		}
	}
}

// A row's own query is hidden whole, past a space that ends the URL pattern (Go's client quotes a URL with %q, which keeps
// a space; PHP's FILTER_VALIDATE_URL would have refused the URL).
func TestRedactHidesARowsQueryPastASpace(t *testing.T) {
	const u = "http://127.0.0.1:1/ut1.tar?k=a SECRETSPACE"
	if got := (ExtrasConfig{}).redact(`Get "`+u+`": dial tcp`, Extra{URL: u}); strings.Contains(got, "SECRETSPACE") {
		t.Errorf("redact = %q still holds the query", got)
	}
}
