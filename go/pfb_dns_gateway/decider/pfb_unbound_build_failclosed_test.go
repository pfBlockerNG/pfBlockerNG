// Tests that dnsblBuildFromManifest fails closed when a feed cannot be read AFTER the manifest validated: a missing or
// unreadable member makes the generation unusable (no partial build) and opens the ledger entry, as
// dnsbl_build_from_manifest does when its fail_closed line reader raises _DnsblGenerationError.
//
// The failure cannot be staged on disk: root reads any file, and validation (an os.Stat of every raw) already refuses a
// missing one. openFeedFile is the seam. The expected texts are what CPython 3.11 wrote and recorded for the same
// failures (open raising PermissionError(13, ...); iteration raising OSError(5, "Input/output error"), which carries no
// file name).
package decider

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// failingFeed is a feed file whose reads fail with EIO once it has served realReads reads from the real file.
type failingFeed struct {
	feedFile
	realReads int
	path      string
}

func (f *failingFeed) Read(p []byte) (int, error) {
	if f.realReads > 0 {
		f.realReads--
		return f.feedFile.Read(p)
	}
	return 0, &os.PathError{Op: "read", Path: f.path, Err: syscall.EIO}
}

func bldSwapOpenFeed(t *testing.T, open func(path string) (feedFile, error)) {
	t.Helper()
	previous := openFeedFile
	openFeedFile = open
	t.Cleanup(func() { openFeedFile = previous })
}

// bldTwoFeedManifest stages a.raw and b.raw under one manifest and returns the module and the manifest path.
func bldTwoFeedManifest(t *testing.T) (m *pfbUnbound, dir, manifestPath string) {
	t.Helper()
	dir = t.TempDir()
	bldWriteFile(t, filepath.Join(dir, "a.raw"), "a.example\n")
	bldWriteFile(t, filepath.Join(dir, "b.raw"), "b.example\n")
	manifestPath = filepath.Join(dir, "pfb_py_sources.json")
	bldWriteManifest(t, manifestPath, map[string]any{"version": 1, "config": map[string]any{}, "feeds": []any{
		map[string]any{"raw": "a.raw", "feed": "A", "group": "G", "log_flag": "1"},
		map[string]any{"raw": "b.raw", "feed": "B", "group": "G", "log_flag": "1"},
	}})
	return bldModuleIn(dir), dir, manifestPath
}

func bldRealOpen(path string) (feedFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func TestManifestBuildFailsClosedWhenAFeedCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(dir string) func(path string) (feedFile, error)
		want string // the generation error, after "Failed to build DNSBL structures from raw: "
	}{
		{
			name: "the open is refused",
			open: func(dir string) func(string) (feedFile, error) {
				return func(path string) (feedFile, error) {
					if strings.HasSuffix(path, "b.raw") {
						return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EACCES}
					}
					return bldRealOpen(path)
				}
			},
			want: "Failed to read DNSBL feed '<DIR>/b.raw': [Errno 13] Permission denied: '<DIR>/b.raw'",
		},
		{
			name: "a read fails before the first line",
			open: func(dir string) func(string) (feedFile, error) {
				return func(path string) (feedFile, error) {
					file, err := bldRealOpen(path)
					if err == nil && strings.HasSuffix(path, "b.raw") {
						return &failingFeed{feedFile: file, path: path}, nil
					}
					return file, err
				}
			},
			want: "Failed while reading DNSBL feed '<DIR>/b.raw': [Errno 5] Input/output error",
		},
		{
			name: "a read fails after the first line was handed out",
			open: func(dir string) func(string) (feedFile, error) {
				return func(path string) (feedFile, error) {
					file, err := bldRealOpen(path)
					if err == nil && strings.HasSuffix(path, "b.raw") {
						return &failingFeed{feedFile: file, path: path, realReads: 1}, nil
					}
					return file, err
				}
			},
			want: "Failed while reading DNSBL feed '<DIR>/b.raw': [Errno 5] Input/output error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, dir, manifestPath := bldTwoFeedManifest(t)
			out := bldCaptureLog(t)
			bldSwapOpenFeed(t, tc.open(dir))

			if result := m.dnsblBuildFromManifest(manifestPath); result != nil {
				t.Fatalf("dnsblBuildFromManifest = %+v, want nil: one unreadable member rejects the whole generation", result)
			}

			wantLedger := "Failed to build DNSBL structures from raw: " + tc.want
			entries := bldLedgerEntries(t, dir)
			if len(entries) != 1 || entries[0]["facility"] != "dnsbl" || entries[0]["stage"] != "parse" ||
				entries[0]["item"] != manifestPath ||
				strings.ReplaceAll(entries[0]["message"].(string), dir, "<DIR>") != wantLedger {
				t.Errorf("ledger = %v, want one dnsbl/parse entry for %s saying %q", entries, manifestPath, wantLedger)
			}
			// Python writes the reader's line, then the build's.
			wantLog := []string{"[pfBlockerNG]: " + tc.want, "[pfBlockerNG]: " + wantLedger}
			if gotLog := bldGoLines(out, dir); !slices.Equal(gotLog, wantLog) {
				t.Errorf("log lines =\n%q\nwant\n%q", gotLog, wantLog)
			}
		})
	}
}

// The control: the same manifest builds when nothing fails, so the nil above is the read failure and nothing else.
func TestManifestBuildSucceedsThroughTheFeedOpenSeam(t *testing.T) {
	m, dir, manifestPath := bldTwoFeedManifest(t)
	bldSwapOpenFeed(t, bldRealOpen)
	result := m.dnsblBuildFromManifest(manifestPath)
	if result == nil {
		t.Fatalf("did not build; ledger %v", bldLedgerEntries(t, dir))
	}
	for _, name := range []string{"a.example", "b.example"} {
		_, inData := result.dataDB[name]
		_, inZone := result.zoneDB[name]
		if !inData && !inZone {
			t.Errorf("%s was not loaded", name)
		}
	}
	if entries := bldLedgerEntries(t, dir); len(entries) != 0 {
		t.Errorf("ledger = %v, want none", entries)
	}
}

// Without fail_closed (the diagnostic readers) the same failure is logged and the feed yields nothing.
func TestFeedReaderWithoutFailClosedLogsAndYieldsNothingWhenTheOpenIsRefused(t *testing.T) {
	dir := t.TempDir()
	bldWriteFile(t, filepath.Join(dir, "b.raw"), "b.example\n")
	bldSwapOpenFeed(t, func(path string) (feedFile, error) {
		return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EACCES}
	})
	out := bldCaptureLog(t)
	lines, err := bldDrain(dnsblFileLineReader(dir, false), "b.raw")
	if len(lines) != 0 || err != nil {
		t.Errorf("lines = %q, err = %v, want nothing and no error", lines, err)
	}
	want := []string{"[pfBlockerNG]: Failed to read DNSBL feed '<DIR>/b.raw': [Errno 13] Permission denied: '<DIR>/b.raw'"}
	if got := bldGoLines(out, dir); !slices.Equal(got, want) {
		t.Errorf("log lines = %q, want %q", got, want)
	}
}
