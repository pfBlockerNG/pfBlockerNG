package feedparse

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type readStep struct {
	data string
	err  error
}

// stepReader returns its steps one Read at a time, then io.EOF: a read error that a retry would not repeat.
type stepReader struct{ steps []readStep }

func (r *stepReader) Read(p []byte) (int, error) {
	if len(r.steps) == 0 {
		return 0, io.EOF
	}
	s := r.steps[0]
	r.steps = r.steps[1:]
	return copy(p, s.data), s.err
}

func (r *stepReader) Close() error { return nil }

var readErrorCases = []struct {
	name  string
	steps []readStep
}{
	{"one byte then an error at the BOM probe", []readStep{{"a", errRead}}},
	{"buffered UTF-8 then an error at the rune peek", []readStep{{"abc", errRead}}},
	{"an error after a whole line", []readStep{{"line one\n", nil}, {"ab", errRead}}},
	{"UTF-16 then an error", []readStep{{"\xff\xfea\x00", errRead}}},
}

// bufio.Reader.Peek hands back a read error with the bytes it could not fill and then forgets it: the error must still end
// the stream, not a later io.EOF.
func TestNormalizeStreamReturnsReadErrorsFromPeeks(t *testing.T) {
	for _, c := range readErrorCases {
		t.Run(c.name, func(t *testing.T) {
			out, err := os.Create(filepath.Join(t.TempDir(), "feed.norm"))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			if err := normalizeStream(&stepReader{steps: append([]readStep(nil), c.steps...)}, out); !errors.Is(err, errRead) {
				t.Errorf("normalizeStream error = %v, want the read error %v", err, errRead)
			}
		})
	}
}

// A .orig that cannot be read to its end publishes nothing: the raw .orig is parsed and no .norm, sidecar or temp is left.
func TestNormalizeFileFallsBackOnASourceReadError(t *testing.T) {
	for _, c := range readErrorCases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			orig := filepath.Join(dir, "feed.orig")
			if err := os.WriteFile(orig, []byte("abc\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := openNormSource
			openNormSource = func(string) (io.ReadCloser, error) {
				return &stepReader{steps: append([]readStep(nil), c.steps...)}, nil
			}
			t.Cleanup(func() { openNormSource = previous })
			if got, want := NormalizeFile(dir, "feed"), (NormResult{Path: orig, Changed: true}); got != want {
				t.Errorf("NormalizeFile = %+v, want raw fallback %+v", got, want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var names [][]byte
			for _, e := range entries {
				names = append(names, []byte(e.Name()))
			}
			if got := bytes.Join(names, []byte(",")); string(got) != "feed.orig" {
				t.Errorf("the directory holds %s, want only feed.orig", got)
			}
		})
	}
}
