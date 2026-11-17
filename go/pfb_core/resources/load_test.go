package resources

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The writer rebuilds the store only for an index it read and cannot use; every other load error leaves the store alone.
func TestLoadClassifiesContentFromReadErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	tests := []struct {
		name    string
		prepare func(dir string)
		corrupt bool
	}{
		{"garbage", func(d string) { os.WriteFile(filepath.Join(d, indexName), []byte("{"), 0o600) }, true},
		{"other version", func(d string) { os.WriteFile(filepath.Join(d, indexName), []byte(`{"version":9}`), 0o600) }, true},
		{"directory", func(d string) { os.Mkdir(filepath.Join(d, indexName), 0o700) }, true},
		{"symlink", func(d string) { os.Symlink(file, filepath.Join(d, indexName)) }, true},
		{"missing", func(string) {}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.prepare(dir)
			if _, err := Open(dir).load(); err == nil || errors.Is(err, errCorrupt) != tc.corrupt {
				t.Fatalf("load error = %v; want corrupt=%v", err, tc.corrupt)
			}
		})
	}
	if _, err := Open(filepath.Join(file, "sub")).load(); err == nil || errors.Is(err, errCorrupt) {
		t.Fatalf("a path under a file: error = %v; want a read error that is not corrupt", err)
	}
}
