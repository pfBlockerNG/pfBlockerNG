package feedfetch

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// top1mWhitelistDir is a database folder holding the list, the previous whitelist and the update marker.
func top1mWhitelistDir(t *testing.T, list string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"top-1m.csv": list, "pfbalexawhitelist.txt": "old.com\n", "top-1m.update": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func top1mWhitelistEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The result counts the valid rows read and the domains written, as the "[ Parsed N lines | Found X of C ]" log line
// does.
func TestATop1MWhitelistCountsParsedRowsAndFoundDomains(t *testing.T) {
	dir := top1mWhitelistDir(t, "1,a.com\nx,bad.com\n2,b.org\n3,www.c.com\n4,d.com\n5,e.com\n")
	res := Top1MWhitelist(Top1MWhitelistConfig{DBDir: dir, Provider: "tranco", Inclusions: []string{"com"}, Count: 3})
	if res != (Top1MWhitelistResult{Parsed: 4, Found: 3, Published: true}) {
		t.Errorf("result = %+v, want Parsed 4, Found 3, Published", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "pfbalexawhitelist.txt")); string(b) != "a.com\nc.com\nd.com\n" {
		t.Errorf("whitelist = %q", b)
	}
	if got, want := top1mWhitelistEntries(t, dir), []string{"pfbalexawhitelist.txt", "top-1m.csv"}; !slices.Equal(got, want) {
		t.Errorf("dir holds %v, want %v", got, want)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// A build that cannot be written keeps the previous whitelist and leaves no staging file behind.
func TestATop1MWhitelistThatCannotBeWrittenKeepsThePrevious(t *testing.T) {
	saved := top1mWhitelistWriter
	t.Cleanup(func() { top1mWhitelistWriter = saved })
	top1mWhitelistWriter = func(*os.File) io.Writer { return failingWriter{} }

	dir := top1mWhitelistDir(t, "1,a.com\n")
	res := Top1MWhitelist(Top1MWhitelistConfig{DBDir: dir, Provider: "tranco", Inclusions: []string{"com"}, Count: 1000})
	if res.Published || res.Reason == "" {
		t.Errorf("result = %+v, want a refusal", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "pfbalexawhitelist.txt")); string(b) != "old.com\n" {
		t.Errorf("whitelist = %q, want the previous one", b)
	}
	if got, want := top1mWhitelistEntries(t, dir), []string{"pfbalexawhitelist.txt", "top-1m.csv"}; !slices.Equal(got, want) {
		t.Errorf("dir holds %v, want %v", got, want)
	}
}

// A build that cannot be published keeps the previous whitelist and leaves no staging file behind.
func TestATop1MWhitelistThatCannotBePublishedKeepsThePrevious(t *testing.T) {
	saved := rename
	t.Cleanup(func() { rename = saved })
	rename = func(string, string) error { return errors.New("cross-device") }

	dir := top1mWhitelistDir(t, "1,a.com\n")
	res := Top1MWhitelist(Top1MWhitelistConfig{DBDir: dir, Provider: "tranco", Inclusions: []string{"com"}, Count: 1000})
	if res.Published || res.Reason == "" || res.Parsed != 1 || res.Found != 1 {
		t.Errorf("result = %+v, want a refusal after one row", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "pfbalexawhitelist.txt")); string(b) != "old.com\n" {
		t.Errorf("whitelist = %q, want the previous one", b)
	}
	if got, want := top1mWhitelistEntries(t, dir), []string{"pfbalexawhitelist.txt", "top-1m.csv"}; !slices.Equal(got, want) {
		t.Errorf("dir holds %v, want %v", got, want)
	}
}

// partReader yields its rows, then fails the read.
type partReader struct{ rows string }

func (r *partReader) Read(p []byte) (int, error) {
	if r.rows == "" {
		return 0, errors.New("I/O error")
	}
	n := copy(p, r.rows)
	r.rows = r.rows[n:]
	return n, nil
}

// A list whose read fails part-way keeps the previous whitelist. Today's PHP publishes the rows read before the failure
// (fgets() returns FALSE as at the end of the list); Core refuses them (owner, 2026-11-19, #4067).
func TestATop1MListThatCannotBeReadKeepsThePrevious(t *testing.T) {
	saved := top1mWhitelistReader
	t.Cleanup(func() { top1mWhitelistReader = saved })
	top1mWhitelistReader = func(*os.File) io.Reader { return &partReader{rows: "1,a.com\n2,b.com\n"} }

	dir := top1mWhitelistDir(t, "1,a.com\n")
	res := Top1MWhitelist(Top1MWhitelistConfig{DBDir: dir, Provider: "tranco", Inclusions: []string{"com"}, Count: 1000})
	if res.Published || res.Reason == "" {
		t.Errorf("result = %+v, want a refusal", res)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "pfbalexawhitelist.txt")); string(b) != "old.com\n" {
		t.Errorf("whitelist = %q, want the previous one", b)
	}
	if got, want := top1mWhitelistEntries(t, dir), []string{"pfbalexawhitelist.txt", "top-1m.csv"}; !slices.Equal(got, want) {
		t.Errorf("dir holds %v, want %v", got, want)
	}
}
