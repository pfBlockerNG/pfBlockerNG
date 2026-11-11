package decider

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// readSidecarWhile streams the sidecar and calls onLine(i) as the consumer receives line i (0-based), before it
// asks for the next one; it returns every line received and the error that ended the stream.
func readSidecarWhile(dir string, onLine func(i int)) (lines []string, err error) {
	for line, lineErr := range dnsblFixedTop1mLines(dir) {
		if lineErr != nil {
			return lines, lineErr
		}
		lines = append(lines, line)
		onLine(len(lines) - 1)
	}
	return lines, nil
}

// The TOP1M sidecar the build opens must be the file the path named when it was inspected: a file swapped in between
// the inspection and the open is refused, even though nothing changes while it is read.
func TestSidecarSwappedBetweenInspectionAndOpenIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		swap    func(t *testing.T, path string)
		wantErr bool
	}{
		{"another file renamed over it", func(t *testing.T, path string) {
			bldWriteFile(t, path+".new", "other.example\n")
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"the same file touched", func(t *testing.T, path string) {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			later := info.ModTime().Add(2 * time.Second)
			if err := os.Chtimes(path, later, later); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"nothing", func(*testing.T, string) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := bldSidecar(t, "a.example\nb.example\n")
			sidecarBeforeOpen = func() { tc.swap(t, path) }
			t.Cleanup(func() { sidecarBeforeOpen = nil })
			var lines []string
			var gotErr error
			for line, err := range dnsblFixedTop1mLines(dir) {
				if err != nil {
					gotErr = err
					break
				}
				lines = append(lines, line)
			}
			if !tc.wantErr {
				if gotErr != nil || !slices.Equal(lines, []string{"a.example", "b.example"}) {
					t.Errorf("lines = %q, err = %v, want the file as it was inspected", lines, gotErr)
				}
				return
			}
			if want := "TOP1M sidecar changed before reading: '" + path + "'"; gotErr == nil || gotErr.Error() != want || len(lines) != 0 {
				t.Errorf("lines = %q, err = %v, want no line and %q", lines, gotErr, want)
			}
		})
	}
}

// A pathname that now names a different regular file is not "the file was replaced by rename-over" unless the open
// file lost its last name there: a file moved aside and a new one created under the old name is refused.
func TestSidecarMovedAsideAndRecreatedWhileReadingIsRefused(t *testing.T) {
	dir, path := bldSidecar(t, "a.example\nb.example\n")
	_, err := readSidecarWhile(dir, func(i int) {
		if i != 0 {
			return
		}
		if err := os.Rename(path, path+".moved"); err != nil {
			t.Fatal(err)
		}
		bldWriteFile(t, path, "other.example\n")
	})
	if want := "TOP1M sidecar changed while reading: '" + path + "'"; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

// A sidecar unlinked while it is read fails the build: the pathname no longer names what was read.
func TestSidecarUnlinkedWhileReadingFailsClosed(t *testing.T) {
	dir, path := bldSidecar(t, "a.example\nb.example\n")
	lines, err := readSidecarWhile(dir, func(i int) {
		if i != 0 {
			return
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	})
	if want := "TOP1M sidecar read failed: '" + path + "'"; err == nil || err.Error() != want {
		t.Errorf("lines = %q, err = %v, want the stream to end with %q", lines, err, want)
	}
}

// Bytes the reader has not reached yet may be rewritten and put back, size and mtime restored, while the pathname is
// atomically replaced (the unlinked-and-replaced file excuses the metadata change): the reader still consumed bytes
// that differ from the first pass, so the build is refused. Without the rewrite the same flow is accepted.
func TestSidecarUnreadBytesRewrittenThenRestoredBeforeAtomicReplaceIsRefused(t *testing.T) {
	// four 3000-byte lines: bufio's 4096-byte fills put the bytes at 10000 in the last fill, after line 0 is delivered
	line := strings.Repeat("x", 2999)
	content := strings.Repeat(line+"\n", 4)
	const offset = 10000
	for _, tc := range []struct {
		name    string
		rewrite bool
	}{
		{"unread bytes rewritten and restored", true},
		{"nothing rewritten", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := bldSidecar(t, content)
			keep := path + ".keep" // a second name keeps the inode writable after the rename-over
			if err := os.Link(path, keep); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			writeAt := func(text string) {
				f, err := os.OpenFile(keep, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.WriteAt([]byte(text), offset); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(keep, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			lines, gotErr := readSidecarWhile(dir, func(i int) {
				switch i {
				case 0:
					if tc.rewrite {
						writeAt("NEW.EXAMPLE")
					}
					bldWriteFile(t, path+".new", "replacement.example\n")
					if err := os.Rename(path+".new", path); err != nil {
						t.Fatal(err)
					}
				case 3:
					if tc.rewrite {
						writeAt(content[offset : offset+len("NEW.EXAMPLE")])
					}
				}
			})
			if !tc.rewrite {
				if gotErr != nil || len(lines) != 4 {
					t.Errorf("%d lines, err = %v, want the whole file as it was opened", len(lines), gotErr)
				}
				return
			}
			if want := "TOP1M sidecar changed while reading: '" + path + "'"; gotErr == nil || gotErr.Error() != want {
				t.Errorf("err = %v, want %q", gotErr, want)
			}
		})
	}
}

// A line that is not valid UTF-8 ends the stream with a read failure; the valid line before it was already
// delivered, so a consumer that ignored the error would keep a partial list.
func TestSidecarValidLineThenInvalidUtf8EndsTheStreamWithAReadFailure(t *testing.T) {
	dir, path := bldSidecar(t, "valid.example\n\xff\nafter.example\n")
	lines, err := readSidecarWhile(dir, func(int) {})
	if want := "TOP1M sidecar read failed: '" + path + "'"; err == nil || err.Error() != want || !slices.Equal(lines, []string{"valid.example"}) {
		t.Errorf("lines = %q, err = %v, want [valid.example] then %q", lines, err, want)
	}
}
