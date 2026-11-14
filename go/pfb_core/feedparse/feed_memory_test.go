package feedparse

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
)

func TestNormalizeFileBoundsHeapForLargeFeed(t *testing.T) {
	const feedBytes = 64 << 20
	dir := t.TempDir()
	origPath := filepath.Join(dir, "feed.orig")
	orig, err := os.Create(origPath)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{'a'}, 64<<10)
	for left := feedBytes; left > 0; {
		n := len(chunk)
		if n > left {
			n = left
		}
		if _, err := orig.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	if _, err := orig.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	if err := orig.Close(); err != nil {
		t.Fatal(err)
	}

	var got NormResult
	growth := heapGrowth(t, func() { got = NormalizeFile(dir, "feed") })
	t.Logf("HeapAlloc growth: %d bytes", growth)
	if got.Path != filepath.Join(dir, "feed.norm") || !got.Normalized || !got.Changed {
		t.Fatalf("NormalizeFile = %+v, want a changed normalized feed", got)
	}
	if growth > 16<<20 {
		t.Errorf("heap grew by %d bytes for a %d-byte feed, want at most %d", growth, feedBytes, 16<<20)
	}
	out, err := os.Open(got.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	info, err := out.Stat()
	if err != nil || info.Size() != feedBytes+1 {
		t.Fatalf("normalized size = %v, %v; want %d", info, err, feedBytes+1)
	}
	var first, last [1]byte
	if _, err := out.ReadAt(first[:], 0); err != nil {
		t.Fatal(err)
	}
	if _, err := out.ReadAt(last[:], feedBytes); err != nil {
		t.Fatal(err)
	}
	if first[0] != 'a' || last[0] != '\n' {
		t.Errorf("normalized endpoints = %q and %q, want 'a' and LF", first[0], last[0])
	}
}

type distinctIPv4Reader struct {
	next, count         int
	line                [16]byte
	lineLen, lineOffset int
}

func (r *distinctIPv4Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		if r.lineOffset == r.lineLen {
			if r.next == r.count {
				break
			}
			line := r.line[:0]
			line = append(line, '1', '0', '.')
			line = strconv.AppendInt(line, int64((r.next>>16)&255), 10)
			line = append(line, '.')
			line = strconv.AppendInt(line, int64((r.next>>8)&255), 10)
			line = append(line, '.')
			line = strconv.AppendInt(line, int64(r.next&255), 10)
			line = append(line, '\n')
			r.lineLen, r.lineOffset = len(line), 0
			r.next++
		}
		n := copy(p[written:], r.line[r.lineOffset:r.lineLen])
		written += n
		r.lineOffset += n
	}
	if written == 0 {
		return 0, io.EOF
	}
	return written, nil
}

type heapTrackingReader struct {
	r     io.Reader
	atEOF uint64
}

func (r *heapTrackingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err == io.EOF {
		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		r.atEOF = mem.HeapAlloc
	}
	return n, err
}

func TestDNSBLCompactDedupHeapPerAddress(t *testing.T) {
	const (
		addresses  = 500_000
		maxHeapUse = 26 << 20
	)
	runtime.GC()
	oldGC := debug.SetGCPercent(-1)
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	in := &heapTrackingReader{
		r:     &distinctIPv4Reader{count: addresses},
		atEOF: before.HeapAlloc,
	}
	got, err := ParseDNSBLFeed(in, DNSBLConfig{DNSBLIP: true, Lenient: true}, io.Discard, Sink{})
	growth := in.atEOF - before.HeapAlloc
	debug.SetGCPercent(oldGC)
	runtime.GC()
	if err != nil {
		t.Fatalf("ParseDNSBLFeed: %v", err)
	}
	if len(got.IP4) != addresses || len(got.IP6) != 0 || !got.UpdateIP {
		t.Fatalf("DNSBL result has %d IPv4 and %d IPv6 addresses, update=%t; want %d distinct IPv4 addresses", len(got.IP4), len(got.IP6), got.UpdateIP, addresses)
	}
	t.Logf("live HeapAlloc at EOF: %d bytes (%d bytes/address)", growth, growth/addresses)
	if growth > maxHeapUse {
		t.Errorf("live heap grew by %d bytes for %d distinct IPs, want at most %d", growth, addresses, maxHeapUse)
	}
}
