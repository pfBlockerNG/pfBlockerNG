package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// The Core Updater folds a record only when there is one: no record is not a report of nothing, which would settle every
// removed dnsbl/* resource at once.
func TestNoRecordIsNotAnEmptyReport(t *testing.T) {
	state := t.TempDir()
	report, err := readApplied(state)
	if err != nil || report != nil {
		t.Fatalf("readApplied without a record = %v, %v; want nil, nil", report, err)
	}
	if err := writeApplied(state, map[string]resources.Cursor{}); err != nil {
		t.Fatal(err)
	}
	report, err = readApplied(state)
	if err != nil || report == nil || len(report) != 0 {
		t.Fatalf("readApplied of a report of nothing = %v (nil %t), %v; want an empty, non-nil report", report, report == nil, err)
	}
	want := map[string]resources.Cursor{"dnsbl/manifest": {Generation: 7, Digest: digestA}}
	if err := writeApplied(state, want); err != nil {
		t.Fatal(err)
	}
	if report, err = readApplied(state); err != nil || len(report) != 1 || report["dnsbl/manifest"] != want["dnsbl/manifest"] {
		t.Errorf("readApplied = %v, %v; want %v", report, err, want)
	}
}

// A record that is not a regular file, or not exactly one report ReportApplied would record, is refused whole.
func TestAnUnusableRecordIsRefused(t *testing.T) {
	valid := `{"format":1,"resources":{` + appliedEntry("dnsbl/manifest", "7", digestA) + `}}`
	for name, plant := range map[string]func(path string) error{
		// Opened without blocking though nothing writes to it: a FIFO is refused, not waited on
		"a FIFO":                func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"a directory":           func(path string) error { return os.Mkdir(path, 0o700) },
		"data after its record": func(path string) error { return os.WriteFile(path, []byte(valid+`{}`), 0o600) },
		"a field it does not know": func(path string) error {
			return os.WriteFile(path, []byte(strings.Replace(valid, `"format":1`, `"format":1,"extra":true`, 1)), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			if err := plant(filepath.Join(state, "applied.json")); err != nil {
				t.Fatal(err)
			}
			if report, err := readApplied(state); err == nil || report != nil {
				t.Errorf("readApplied = %v, %v; want nil and an error", report, err)
			}
		})
	}
}

// A crash between a report's write and its rename leaves the temporary file: the next report takes it over, so no crash
// leaves a file in the state directory for ever, and the record is private whatever mode the leftover had.
func TestTheNextReportTakesOverALeftTemporaryFile(t *testing.T) {
	cases := map[string]func(t *testing.T, state, tmp string){
		"a partial file of another mode": func(t *testing.T, _, tmp string) {
			if err := os.WriteFile(tmp, []byte(`{"format":1,"resources":{"dnsbl/stale"`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a symbolic link to a file that must stay untouched": func(t *testing.T, state, tmp string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, tmp); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
					t.Errorf("the link's target = %q, %v; want it untouched", raw, err)
				}
			})
		},
		"a FIFO": func(t *testing.T, _, tmp string) {
			if err := syscall.Mkfifo(tmp, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"an empty directory": func(t *testing.T, _, tmp string) {
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, leave := range cases {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			tmp := filepath.Join(state, "applied.json.tmp")
			leave(t, state, tmp)
			want := map[string]resources.Cursor{"dnsbl/manifest": {Generation: 7, Digest: digestA}}
			if err := writeApplied(state, want); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(tmp); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the left temporary file is still there after a report: %v", err)
			}
			entries, err := os.ReadDir(state)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != "applied.json" {
					t.Errorf("the state directory holds %s after a report, want applied.json alone", e.Name())
				}
			}
			if info, err := os.Stat(filepath.Join(state, "applied.json")); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("applied.json = %v, %v; want mode 0600", info, err)
			}
			if report, err := readApplied(state); err != nil || len(report) != 1 || report["dnsbl/manifest"] != want["dnsbl/manifest"] {
				t.Errorf("readApplied = %v, %v; want %v", report, err, want)
			}
		})
	}
}

// Rename cannot replace a directory, so what sits at the record's own name decides whether a report can land: a link is
// replaced itself, an empty directory is removed first, and a directory with content is never deleted by Core.
func TestAReportOverADirectoryOrALinkAtTheRecord(t *testing.T) {
	want := map[string]resources.Cursor{"dnsbl/manifest": {Generation: 7, Digest: digestA}}
	t.Run("an empty directory", func(t *testing.T) {
		state := t.TempDir()
		path := filepath.Join(state, "applied.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeApplied(state, want); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Errorf("applied.json = %v, %v; want a regular file of mode 0600", info, err)
		}
		if report, err := readApplied(state); err != nil || len(report) != 1 || report["dnsbl/manifest"] != want["dnsbl/manifest"] {
			t.Errorf("readApplied = %v, %v; want %v", report, err, want)
		}
	})
	t.Run("a symbolic link to another file", func(t *testing.T) {
		state := t.TempDir()
		path := filepath.Join(state, "applied.json")
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := writeApplied(state, want); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			t.Errorf("applied.json = %v, %v; want a regular file", info, err)
		}
		if raw, err := os.ReadFile(target); err != nil || string(raw) != "keep" {
			t.Errorf("the link's target = %q, %v; want it untouched", raw, err)
		}
	})
	t.Run("a directory with content", func(t *testing.T) {
		state := t.TempDir()
		path := filepath.Join(state, "applied.json")
		inner := filepath.Join(path, "inner")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inner, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := writeApplied(state, want); err == nil {
			t.Error("the report succeeded over a directory with content, want an error")
		}
		if info, err := os.Lstat(path); err != nil || !info.IsDir() {
			t.Errorf("applied.json = %v, %v; want the directory untouched", info, err)
		}
		if raw, err := os.ReadFile(inner); err != nil || string(raw) != "keep" {
			t.Errorf("the directory's content = %q, %v; want it untouched", raw, err)
		}
	})
}
