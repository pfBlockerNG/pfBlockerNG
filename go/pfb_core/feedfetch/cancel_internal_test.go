package feedfetch

// A decompression bomb against a cancellation (#3973 review): a 4 GiB bzip2 bomb outlived its 2 s deadline by 16 s,
// because the context was polled per 4 KiB of compressed input, which a bomb turns into hundreds of MiB. The context is
// cancelled here once some output has passed, and the probe or the extraction must stop within a few KiB more.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	bombSize   = 32 << 20 // zeros in each bomb
	cancelAt   = 1 << 20  // the output after which the context is cancelled
	afterLimit = 64 << 10 // the output tolerated after that
)

// bzip2Bomb is `head -c 32M /dev/zero | bzip2 -9`: the standard library has no bzip2 compressor.
const bzip2Bomb = "QlpoOTFBWSZTWaIgopoBAQHAAMAAAAggADCAKRtoAgGiAQDi7kinChIURBRTQA=="

// cancelAfter counts the output that reaches it and cancels the context once cancelAt bytes have.
type cancelAfter struct {
	n      int64
	cancel context.CancelFunc
}

func (c *cancelAfter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	if c.n >= cancelAt {
		c.cancel()
	}
	return len(p), nil
}

type bomb struct {
	name, mime string
	tarInner   bool
	path       string
}

// bombs writes a gzip, a bzip2, a zip and a tar.gz of bombSize zeros, and a small tar, into a temporary directory.
func bombs(t *testing.T) []bomb {
	t.Helper()
	zeros := make([]byte, bombSize)
	gz := func(b []byte) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(b); err != nil || w.Close() != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tarOf := func(b []byte) []byte {
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		if err := w.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil || w.Close() != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	var zipBody bytes.Buffer
	zw := zip.NewWriter(&zipBody)
	member, err := zw.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(zeros); err != nil || zw.Close() != nil {
		t.Fatal(err)
	}
	bz, err := base64.StdEncoding.DecodeString(bzip2Bomb)
	if err != nil {
		t.Fatal(err)
	}
	out := []bomb{{name: "gzip", mime: mimeGzip}, {name: "bzip2", mime: mimeBzip2}, {name: "zip", mime: mimeZip},
		{name: "tar.gz", mime: mimeGzip, tarInner: true}, {name: "tar", mime: mimeTar}}
	bodies := [][]byte{gz(zeros), bz, zipBody.Bytes(), gz(tarOf(zeros)), tarOf([]byte("1\n"))}
	dir := t.TempDir()
	for i := range out {
		out[i].path = filepath.Join(dir, out[i].name)
		if err := os.WriteFile(out[i].path, bodies[i], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Both the structural probe and the extraction of every compressed container stop soon after their context ends: the
// context is minded on the side of what a decompressor yields.
func TestADecompressionBombStopsSoonAfterItsContextEnds(t *testing.T) {
	for _, b := range bombs(t) {
		if b.mime == mimeTar {
			continue // nothing to decompress
		}
		for what, run := range map[string]func(context.Context, io.Writer) error{
			"probe":      func(ctx context.Context, w io.Writer) error { return structural(ctx, b.mime, b.path, w) },
			"extraction": func(ctx context.Context, w io.Writer) error { return extract(ctx, b.mime, b.path, b.tarInner, w) },
		} {
			t.Run(b.name+" "+what, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				w := &cancelAfter{cancel: cancel}
				if err := run(ctx, w); !errors.Is(err, context.Canceled) || w.n-cancelAt > afterLimit {
					t.Fatalf("must end with its context within %d bytes of output: %v, %d bytes past the cancellation (a bomb of %d)",
						afterLimit, err, w.n-cancelAt, bombSize)
				}
			})
		}
	}
}

// A context that is already done ends the structural probe of every container.
func TestEveryStructuralProbeEndsWithAContextAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, b := range bombs(t) {
		if err := structural(ctx, b.mime, b.path, io.Discard); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: a done context must end the probe: %v", b.name, err)
		}
	}
}

func TestCompressedInnerProbeStopsWithItsContext(t *testing.T) {
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(t.TempDir(), "raw.gz")
	if err := os.WriteFile(raw, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	ctx := &cancelAtCheckContext{Context: base, cancel: cancel, at: 1}
	if got := innerType(ctx, mimeGzip, raw); got != mimeEmptyInner || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("the inner probe must stop with its context, got %q and %v", got, ctx.Err())
	}

	f, feed := &Fetcher{}, Feed{Dir: t.TempDir(), Name: "FEED"}
	f.FreeBytes = func(string) (uint64, bool) { return 1 << 20, true }
	base, cancel = context.WithCancel(context.Background())
	ctx = &cancelAtCheckContext{Context: base, cancel: cancel, at: 3}
	if _, refusal := f.gate(ctx, feed, raw, time.Time{}); refusal == nil || refusal.Reason != context.Canceled.Error() {
		t.Fatalf("the inner-probe refusal must report the context reason: %+v (%d checks)", refusal, ctx.checks)
	}
	cancel()
}

func TestExtractedZipVerdictReportsItsContextReason(t *testing.T) {
	inner := zipMembers(t, zipMember{"a.txt", []byte("1.2.3.4\n")})
	payload := append([]byte{0}, inner...)
	rawBody := zipMembers(t, zipMember{"inner.bin", payload})
	raw := filepath.Join(t.TempDir(), "raw.zip")
	if err := os.WriteFile(raw, rawBody, 0o600); err != nil {
		t.Fatal(err)
	}
	f, feed := &Fetcher{}, Feed{Dir: t.TempDir(), Name: "FEED"}
	f.FreeBytes = func(string) (uint64, bool) { return 1 << 20, true }
	base, cancel := context.WithCancel(context.Background())
	ctx := &cancelAtCheckContext{Context: base, cancel: cancel, at: 3}
	if _, refusal := f.gate(ctx, feed, raw, time.Time{}); refusal == nil || refusal.Reason != context.Canceled.Error() {
		t.Fatalf("the zip-inner verdict must report the context reason: %+v (%d checks)", refusal, ctx.checks)
	}
}
