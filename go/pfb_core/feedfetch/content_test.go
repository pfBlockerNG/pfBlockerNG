package feedfetch_test

// Content-gate behaviour (#3973) the parity corpus cannot pin: what PHP cannot be made to do off the appliance (a lower
// extraction ceiling, a full disk, a cancelled context), what only one libmagic and one unzip would settle (a zip behind
// prepended bytes), the staged archive's timestamp, a comma at the edge of a copy chunk, and the classifier's labels.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

const oldCopy = "old\n"

func gzipOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipOf(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "a.txt", Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// seededFeed is a fetcher over a feed that already publishes oldCopy, and a directory for local sources.
func seededFeed(t *testing.T) (*feedfetch.Fetcher, feedfetch.Feed, string) {
	t.Helper()
	f, feed := quickFetcher(t)
	src := t.TempDir()
	f.Policy.LocalDirs = []string{src}
	if err := os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte(oldCopy), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, feed, src
}

// localRequest serves body as a local file source.
func localRequest(t *testing.T, src string, body []byte) feedfetch.Request {
	t.Helper()
	p := filepath.Join(src, "src.bin")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return feedfetch.Request{URL: "file://" + p}
}

// strays names what a refused or finished call must not leave in the feed directory: an extraction's staging file or
// the staged ".raw" (which only an archive success keeps).
func strays(t *testing.T, feed feedfetch.Feed, keepRaw bool) []string {
	t.Helper()
	entries, err := os.ReadDir(feed.Dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pfbstage_") || (e.Name() == "FEED.raw" && !keepRaw) {
			out = append(out, e.Name())
		}
	}
	return out
}

// A context that is done refuses the ingest of an archive, with the published copy kept.
func TestACancelledContextRefusesAnArchive(t *testing.T) {
	f, feed, src := seededFeed(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := f.Ingest(ctx, feed, localRequest(t, src, gzipOf(t, []byte("1.2.3.4\n"))))
	if res.OK || res.Reason != context.Canceled.Error() || published(t, feed) != oldCopy || len(strays(t, feed, false)) != 0 {
		t.Fatalf("a cancelled context must refuse the archive: %+v, published %q, strays %v", res, published(t, feed), strays(t, feed, false))
	}
}

// stagedCtx is cancelled from the moment an extraction has opened its staging file.
type stagedCtx struct {
	context.Context
	dir string
}

func (c stagedCtx) Err() error {
	if m, _ := filepath.Glob(filepath.Join(c.dir, ".pfbstage_*")); len(m) > 0 {
		return context.Canceled
	}
	return nil
}

// The extraction itself, not only the structural test before it, stops when the context does.
func TestACancelledContextStopsAnExtractionInProgress(t *testing.T) {
	f, feed, src := seededFeed(t)
	big := bytes.Repeat([]byte("1.2.3.4\n"), 1<<19) // 4 MiB, about 4 KB gzipped
	res := f.Ingest(stagedCtx{context.Background(), feed.Dir}, feed, localRequest(t, src, gzipOf(t, big)))
	if res.OK || res.Reason != context.Canceled.Error() || published(t, feed) != oldCopy || len(strays(t, feed, false)) != 0 {
		t.Fatalf("an extraction must end with its context: %+v, published %d bytes, strays %v", res, len(published(t, feed)), strays(t, feed, false))
	}
}

// A zip hidden behind prepended bytes is no zip to the magic number, so it is an octet stream a structural probe
// recovers. (PHP cannot pin this: libmagic 5.46 still calls it a zip and Info-ZIP's unzip -t refuses it.)
func TestAZipBehindPrependedBytesIsRecoveredFromTheOctetStream(t *testing.T) {
	f, feed, src := seededFeed(t)
	body := append(bytes.Repeat([]byte{0}, 8), zipOf(t, "1.2.3.4\n")...)
	res := f.Ingest(context.Background(), feed, localRequest(t, src, body))
	if !res.OK || published(t, feed) != "1.2.3.4\n" {
		t.Fatalf("a recovered zip must be published: %+v, published %q", res, published(t, feed))
	}
	if raw, err := os.ReadFile(filepath.Join(feed.Dir, "FEED.raw")); err != nil || !bytes.Equal(raw, body) {
		t.Fatalf("the staged archive must stay: %v", err)
	}
}

// One byte over the per-file ceiling is refused, the ceiling itself is not: in every container, counting the bytes the
// published copy would hold. (The corpus row pins PHP's count, 2 GiB, which is too large to try at the byte.)
func TestAnExtractionStopsAtThePerFileCeiling(t *testing.T) {
	const limit = 100
	payload := func(n int) []byte { return bytes.Repeat([]byte("x"), n) }
	bzip2 := map[int]string{ // bzip2 of n "x"; the standard library has no compressor
		limit:     "QlpoOTFBWSZTWdGErXsAAAIBgEAAAEAgACEAggsXckU4UJDRhK17",
		limit + 1: "QlpoOTFBWSZTWea8nUoAAAIBgCAAAEAgACEAggsXckU4UJDmvJ1K",
	}
	cases := []struct {
		name, refusal string
		body          func(n int) []byte
	}{
		{"gzip", "gzip extraction failed (gunzip exit 153)", func(n int) []byte { return gzipOf(t, payload(n)) }},
		{"bzip2", "bzip2 extraction failed (bzip2 exit 153)", func(n int) []byte {
			b, err := base64.StdEncoding.DecodeString(bzip2[n])
			if err != nil {
				t.Fatal(err)
			}
			return b
		}},
		{"zip", "zip publish failed (tar exit 153)", func(n int) []byte { return zipOf(t, string(payload(n))) }},
		{"tar", "tar extraction failed (tar exit 153)", func(n int) []byte { return tarOf(t, payload(n)) }},
		{"tar.gz", "gzip extraction failed (gunzip exit 153)", func(n int) []byte { return gzipOf(t, tarOf(t, payload(n))) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, feed, src := seededFeed(t)
			f.SetExtractMax(limit)
			if res := f.Ingest(context.Background(), feed, localRequest(t, src, c.body(limit))); !res.OK || published(t, feed) != string(payload(limit))+"\n" {
				t.Fatalf("a payload of exactly the ceiling must be published: %+v, published %q", res, published(t, feed))
			}
			res := f.Ingest(context.Background(), feed, localRequest(t, src, c.body(limit+1)))
			want := c.refusal + " -- output exceeded the extraction size ceiling"
			if res.OK || res.Reason != want || published(t, feed) != string(payload(limit))+"\n" || len(strays(t, feed, true)) != 0 {
				t.Fatalf("a payload one byte over must be refused, keeping the published copy: %+v (want %q), strays %v", res, want, strays(t, feed, true))
			}
		})
	}
}

// An archive needs room for itself in the feed directory and no more; a plain text feed is never measured; a directory
// whose space cannot be read is no shortfall (pfb_extract_space_shortfall).
func TestAnArchiveIsRefusedWhenTheFeedDirectoryCannotHoldIt(t *testing.T) {
	f, feed, src := seededFeed(t)
	body := gzipOf(t, []byte("1.2.3.4\n"))
	req := localRequest(t, src, body)
	var asked string
	f.FreeBytes = func(dir string) (uint64, bool) { asked = dir; return uint64(len(body)) - 1, true }
	res := f.Ingest(context.Background(), feed, req)
	if res.OK || res.Stage != "size" || res.Reason != "staging_space_low" || res.Detected != feed.Dir || asked != feed.Dir ||
		published(t, feed) != oldCopy || len(strays(t, feed, false)) != 0 {
		t.Fatalf("an archive one byte too large for the directory must be refused: %+v (asked %q), strays %v", res, asked, strays(t, feed, false))
	}
	f.FreeBytes = func(string) (uint64, bool) { return uint64(len(body)), true }
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("room for exactly the archive must do: %+v", res)
	}
	f.FreeBytes = func(string) (uint64, bool) { return 0, false }
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("an unreadable free space is no shortfall: %+v", res)
	}
	f.FreeBytes = func(string) (uint64, bool) { t.Error("a plain text feed must not be measured"); return 0, true }
	if res := f.Ingest(context.Background(), feed, localRequest(t, src, []byte("5.6.7.8\n"))); !res.OK {
		t.Fatalf("a plain text feed must be published: %+v", res)
	}
}

// The staged archive carries the remote timestamp (A16), as the published copy does.
func TestAnArchiveKeepsTheRemoteTimestampOnItsStagedBody(t *testing.T) {
	stamp := time.Unix(1700000000, 0)
	url, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", stamp.UTC().Format(http.TimeFormat))
		w.Write(gzipOf(t, []byte("1.2.3.4\n")))
	})
	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:" + port(t, url) + "/list", Timeout: 10 * time.Second})
	if !res.OK {
		t.Fatalf("%+v", res)
	}
	for _, name := range []string{"FEED.raw", "FEED.orig"} {
		info, err := os.Stat(filepath.Join(feed.Dir, name))
		if err != nil || !info.ModTime().Equal(stamp) {
			t.Fatalf("%s must carry the remote timestamp %v: %v, %v", name, stamp, info, err)
		}
	}
}

// The comma transform reads one byte past a comma: a comma last in a copy chunk (io.Copy's is 32 KiB) must be held until
// the next chunk shows what follows it.
func TestACommaAtTheEdgeOfACopyChunkIsTransformedWhole(t *testing.T) {
	for off := 32760; off <= 32776; off++ {
		f, feed, src := seededFeed(t)
		member := strings.Repeat("a", off) + ", b,c\n"
		res := f.Ingest(context.Background(), feed, localRequest(t, src, zipOf(t, member)))
		if want := strings.Repeat("a", off) + "; b\nc\n"; !res.OK || published(t, feed) != want {
			t.Fatalf("comma at %d: %+v, published %d bytes, want %d", off, res, len(published(t, feed)), len(want))
		}
	}
}

func TestClassifyAnswersTheLabelsTheGatesNeed(t *testing.T) {
	at257 := func(s string) []byte { return append(bytes.Repeat([]byte("a"), 257), s...) }
	ustar := at257("ustar\x0000")
	cases := []struct {
		name string
		head []byte
		want string
	}{
		{"empty", nil, "inode/x-empty"},
		{"text", []byte("1.2.3.4\n"), "text/plain"},
		{"shebang script is text", []byte("#!/bin/sh\necho hi\n"), "text/plain"},
		{"html", []byte("<!DOCTYPE html>\n<html>"), "text/html"},
		{"html in capitals after white space", []byte(" \n\t<HTML>"), "text/html"},
		{"html after a utf-8 bom", []byte("\xef\xbb\xbf<html>"), "text/html"},
		{"gzip", []byte{0x1f, 0x8b, 8, 0}, "application/gzip"},
		{"bzip2", []byte("BZh91AY&SY"), "application/x-bzip2"},
		{"bzip2 of the smallest block size", []byte("BZh11AY&SY"), "application/x-bzip2"},
		{"bzip2 needs a block size", []byte("BZhost\n"), "text/plain"},
		{"bzip2 has no block size 0", []byte("BZh0"), "text/plain"},
		{"zip", []byte("PK\x03\x04\x14\x00"), "application/zip"},
		{"empty zip", []byte("PK\x05\x06\x00\x00"), "application/zip"},
		{"tar", ustar, "application/x-tar"},
		{"posix tar magic ending the head", at257("ustar\x00"), "application/x-tar"},
		{"gnu tar", at257("ustar  \x00"), "application/x-tar"},
		{"ustar without the nul of the magic is text", at257("ustar"), "text/plain"},
		{"ustar followed by text is text", at257("ustar.example\n"), "text/plain"},
		{"utf-16le bom", []byte("\xff\xfe1\x00"), "text/plain"},
		{"utf-16be bom", []byte("\xfe\xff\x001"), "text/plain"},
		{"utf-32le bom", []byte("\xff\xfe\x00\x001\x00\x00\x00"), "text/plain"},
		{"utf-32be bom", []byte("\x00\x00\xfe\xff\x00\x00\x001"), "text/plain"},
		{"a nul outside a bom encoding", []byte("a\x00b"), "application/octet-stream"},
		{"binary", bytes.Repeat([]byte{0, 1, 2, 3}, 8), "application/octet-stream"},
		{"latin-1 text", []byte("caf\xe9\n"), "text/plain"},
		{"windows-1252 text", []byte("\x93quoted\x94 \x80 5\n"), "text/plain"},
		{"a nul behind latin-1 text", []byte("caf\xe9\x00\n"), "application/octet-stream"},
		{"utf-8", []byte("caf\u00e9\n"), "text/plain"},
		{"a rune cut by the end of the sample", []byte("abc\xe2\x82"), "text/plain"},
		{"a rune cut by the end of the body", []byte("abc\xe2\x82"), "text/plain"},
	}
	for _, c := range cases {
		if got := feedfetch.Classify(c.head); got != c.want {
			t.Errorf("%s: classified %q, want %q", c.name, got, c.want)
		}
	}
}

// An extraction is published readable by the feed's unprivileged readers: its staging file is created private, so the
// mode is set on purpose (#2169).
func TestAnExtractionIsPublishedWorldReadable(t *testing.T) {
	for name, body := range map[string][]byte{"gzip": gzipOf(t, []byte("1.2.3.4\n")), "zip": zipOf(t, "1.2.3.4\n"), "tar": tarOf(t, []byte("1.2.3.4\n"))} {
		t.Run(name, func(t *testing.T) {
			f, feed, src := seededFeed(t)
			if res := f.Ingest(context.Background(), feed, localRequest(t, src, body)); !res.OK {
				t.Fatalf("%+v", res)
			}
			if info, err := os.Stat(filepath.Join(feed.Dir, "FEED.orig")); err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("the published copy must be 0644: %v, %v", info, err)
			}
		})
	}
}

// A transcoded extraction is published as readable as any extraction: the transcode keeps the mode it finds
// (pfb_utf16_transcode_file restores it).
func TestATranscodedExtractionIsPublishedWorldReadable(t *testing.T) {
	f, feed, src := seededFeed(t)
	utf16 := []byte("\xff\xfe1\x00.\x002\x00.\x003\x00.\x004\x00\n\x00")
	if res := f.Ingest(context.Background(), feed, localRequest(t, src, gzipOf(t, utf16))); !res.OK || published(t, feed) != "1.2.3.4\n" {
		t.Fatalf("%+v, published %q", res, published(t, feed))
	}
	if info, err := os.Stat(filepath.Join(feed.Dir, "FEED.orig")); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the published copy must be 0644: %v, %v", info, err)
	}
}

// Member names never reach the file system, so a name that would leave its directory is no reason to refuse a zip or a
// tar, whatever the standard library's insecure-path setting (a change of default must not turn into a refusal).
func TestAnInsecureMemberNameIsNoFaultWhenTheStandardLibraryReportsIt(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0,tarinsecurepath=0")
	zipBody := func() []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.Create("../../evil.txt")
		w.Write([]byte("1.2.3.4\n"))
		zw.Close()
		return buf.Bytes()
	}()
	tarBody := func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		tw.WriteHeader(&tar.Header{Name: "/etc/evil.txt", Mode: 0o644, Size: 8})
		tw.Write([]byte("1.2.3.4\n"))
		tw.Close()
		return buf.Bytes()
	}()
	for name, body := range map[string][]byte{"zip": zipBody, "tar": tarBody} {
		f, feed, src := seededFeed(t)
		if res := f.Ingest(context.Background(), feed, localRequest(t, src, body)); !res.OK || published(t, feed) != "1.2.3.4\n" {
			t.Fatalf("%s: %+v, published %q", name, res, published(t, feed))
		}
	}
}

// Every container's structural test and extraction answer to the context, not only the gzip's.
func TestACancelledContextRefusesEveryContainer(t *testing.T) {
	bzip2, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWdGErXsAAAIBgEAAAEAgACEAggsXckU4UJDRhK17")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 100)
	bodies := map[string][]byte{
		"gzip": gzipOf(t, payload), "bzip2": bzip2, "zip": zipOf(t, string(payload)), "tar": tarOf(t, payload),
		"tar.gz": gzipOf(t, tarOf(t, payload)),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			f, feed, src := seededFeed(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			res := f.Ingest(ctx, feed, localRequest(t, src, body))
			if res.OK || res.Reason != context.Canceled.Error() || published(t, feed) != oldCopy || len(strays(t, feed, false)) != 0 {
				t.Fatalf("%+v, published %q, strays %v", res, published(t, feed), strays(t, feed, false))
			}
		})
	}
}

// A publication that fails after the extraction leaves neither the extraction nor the staged archive behind.
func TestAFailedPublicationLeavesNoExtractionBehind(t *testing.T) {
	f, feed, src := seededFeed(t)
	orig := filepath.Join(feed.Dir, "FEED.orig")
	os.Remove(orig)
	if err := os.MkdirAll(filepath.Join(orig, "held"), 0o700); err != nil { // a directory the rename cannot replace
		t.Fatal(err)
	}
	res := f.Ingest(context.Background(), feed, localRequest(t, src, gzipOf(t, []byte("1.2.3.4\n"))))
	if res.OK || len(strays(t, feed, false)) != 0 {
		t.Fatalf("a publication that cannot rename must fail clean: %+v, strays %v", res, strays(t, feed, false))
	}
}

// Every extraction, not only a gzip's, stops when its context ends part-way through it.
func TestACancelledContextStopsEveryExtractionInProgress(t *testing.T) {
	bzip2, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWdGErXsAAAIBgEAAAEAgACEAggsXckU4UJDRhK17")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 100)
	bodies := map[string][]byte{
		"bzip2": bzip2, "zip": zipOf(t, string(payload)), "tar": tarOf(t, payload), "tar.gz": gzipOf(t, tarOf(t, payload)),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			f, feed, src := seededFeed(t)
			res := f.Ingest(stagedCtx{context.Background(), feed.Dir}, feed, localRequest(t, src, body))
			if res.OK || res.Reason != context.Canceled.Error() || published(t, feed) != oldCopy || len(strays(t, feed, false)) != 0 {
				t.Fatalf("an extraction must end with its context: %+v, published %q, strays %v", res, published(t, feed), strays(t, feed, false))
			}
		})
	}
}

// A context that ended during the verdict refuses for itself, not for the feed: an octet stream whose recovery probes
// were cut short is not known to hold no archive.
func TestAContextThatEndedDuringTheVerdictIsNoMimeRefusal(t *testing.T) {
	f, feed, src := seededFeed(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := f.Ingest(ctx, feed, localRequest(t, src, bytes.Repeat([]byte{0, 1, 2, 3}, 64)))
	if res.OK || res.Reason != context.Canceled.Error() || res.Stage != "" || res.Detected != "" || published(t, feed) != oldCopy {
		t.Fatalf("the refusal must be the context's: %+v, published %q", res, published(t, feed))
	}
}

// An octet stream is tried as a zip before it is tried as a tar (ADR-45's order: zip, gzip, bzip2, tar). A tar without
// the ustar magic (version 7), which no magic number names, whose one member is a zip, is both: it is the zip.
func TestTheRecoveryOfAnOctetStreamTriesZipBeforeTar(t *testing.T) {
	inner := zipOf(t, "1.2.3.4\n")
	body := tarOf(t, inner)
	hdr := body[:512]
	clear(hdr[257:265]) // no magic and no version: a version 7 header
	copy(hdr[148:156], "        ")
	sum := 0
	for _, c := range hdr {
		sum += int(c)
	}
	copy(hdr[148:156], fmt.Sprintf("%06o\x00 ", sum))
	tr := tar.NewReader(bytes.NewReader(body))
	if _, err := tr.Next(); err != nil {
		t.Fatalf("the fixture must read as a tar: %v", err)
	}
	if member, err := io.ReadAll(tr); err != nil || !bytes.Equal(member, inner) {
		t.Fatalf("the fixture's member must be the zip: %v", err)
	}
	if got := feedfetch.Classify(body); got != "application/octet-stream" {
		t.Fatalf("the fixture must be an octet stream, not %q", got)
	}
	f, feed, src := seededFeed(t)
	if res := f.Ingest(context.Background(), feed, localRequest(t, src, body)); !res.OK || published(t, feed) != "1.2.3.4\n" {
		t.Fatalf("the zip must win: %+v, published %q", res, published(t, feed))
	}
}

func TestMIMEProbeDoesNotStopAtOneKiB(t *testing.T) {
	body := append(bytes.Repeat([]byte("a"), 1<<10), 0, 'x')
	f, feed, src := seededFeed(t)
	res := f.Ingest(context.Background(), feed, localRequest(t, src, body))
	if res.OK || res.Stage != "mime" || res.Reason != "mime_not_allowed" ||
		res.Detected != "application/octet-stream rc=0" || published(t, feed) != oldCopy {
		t.Fatalf("the full sniff window must see the binary byte after 1 KiB: %+v, published %q", res, published(t, feed))
	}
}

// The MIME probe classifies exactly the first MiB: a NUL as its last byte makes the body binary, one byte later the
// probe never sees it and the body is text to the MIME stage.
func TestMIMEProbeWindowIsExactlyOneMiB(t *testing.T) {
	for _, tc := range []struct {
		at      int
		refused bool
	}{{1<<20 - 1, true}, {1 << 20, false}} {
		body := bytes.Repeat([]byte("1.2.3.4\n"), (1<<20)/8+1)
		body[tc.at] = 0
		f, feed, src := seededFeed(t)
		res := f.Ingest(context.Background(), feed, localRequest(t, src, body))
		if mimeRefused := res.Stage == "mime"; mimeRefused != tc.refused {
			t.Fatalf("a NUL at offset %d: want refused by the MIME stage %v, got %+v", tc.at, tc.refused, res)
		}
	}
}
