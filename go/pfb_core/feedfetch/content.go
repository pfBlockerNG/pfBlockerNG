package feedfetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// The content gates of pfb_download() ($type === ''), run on the staged ".raw" after the transfer: the MIME verdict
// (pfb_filter FILE_MIME), the allow-list, the recovery of an octet stream, and the inner verdict of a compressed body
// (FILE_MIME_COMPRESSED). PHP asks libmagic through file(1); Core has none, so classify answers for what the allow-list
// names. The difference is the point of #3905's option 1 (owner decision, 2026-11-13): every text body passes, where
// libmagic refused text it took for shell, C or assembler source.

const (
	// sniffBytes is how much of a body is classified: libmagic reads a bounded prefix too.
	sniffBytes = 1 << 20

	mimeOctet      = "application/octet-stream"
	mimeEmptyFile  = "inode/x-empty"
	mimeEmptyInner = "application/x-empty" // what libmagic -Z says of a compressed nothing: not the type it allows
	mimeGzip       = "application/gzip"
	mimeBzip2      = "application/x-bzip2"
	mimeZip        = "application/zip"
	mimeTar        = "application/x-tar"
	mimeText       = "text/plain"
	mimeHTML       = "text/html"
)

// mimeAllowed is $pfb['mime_types'], the allow-list a body is held to (pfblockerng.inc, 629-642).
var mimeAllowed = map[string]bool{
	mimeEmptyFile: true, "text/x-file": true, mimeText: true, mimeHTML: true, "text/xml": true, "text/csv": true,
	"application/csv": true, "application/json": true, "application/x-ndjson": true, mimeGzip: true,
	"application/x-gzip": true, mimeBzip2: true, mimeZip: true, mimeTar: true,
}

// boms are the byte order marks of UTF-16 and UTF-32 text; the 4-byte ones come first, as pfb_utf16_transcode_file()
// tests them (FF FE 00 00 is a UTF-32LE mark before it is a UTF-16LE mark and a NUL).
var boms = [][]byte{{0xff, 0xfe, 0, 0}, {0, 0, 0xfe, 0xff}, {0xff, 0xfe}, {0xfe, 0xff}}

// classify is `file -b --mime-type` for the head of a body, as far as the gates need it: the magic numbers of the
// containers the allow-list names, then text or binary. more tells that the body goes on past head.
//
// Text is any body without a NUL, or UTF-16/32 behind its mark: a Latin-1 or Windows-1252 feed is text, as libmagic takes
// it, and goes on to the parser's raw-byte path (#3906) instead of being refused here. Text takes the label of its
// opening where a cheap rule gives libmagic's: text/html for an HTML opening, else text/plain. Every other body is
// application/octet-stream, whatever libmagic would call it (a PDF, an executable).
func classify(head []byte, more bool) string {
	switch {
	case len(head) == 0:
		return mimeEmptyFile
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return mimeGzip
	case len(head) > 3 && bytes.HasPrefix(head, []byte("BZh")) && head[3] >= '1' && head[3] <= '9':
		return mimeBzip2
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")): // an empty zip is its end record
		return mimeZip
	case len(head) > 257 && (bytes.HasPrefix(head[257:], []byte("ustar\x00")) || bytes.HasPrefix(head[257:], []byte("ustar  \x00"))):
		return mimeTar // POSIX and GNU: the NUL keeps a text body that reads "ustar" there a text body
	case isText(head):
		if htmlOpening(head) {
			return mimeHTML
		}
		return mimeText
	}
	return mimeOctet
}

func isText(b []byte) bool {
	for _, bom := range boms {
		if bytes.HasPrefix(b, bom) {
			return true
		}
	}
	return bytes.IndexByte(b, 0) < 0
}

// htmlOpening is libmagic's "<!doctype html" / "<html" at the start, case-blind, after white space and a UTF-8 mark.
func htmlOpening(b []byte) bool {
	b = bytes.TrimLeft(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), " \t\r\n\v\f")
	for _, open := range [...]string{"<!doctype html", "<html"} {
		if len(b) >= len(open) && bytes.EqualFold(b[:len(open)], []byte(open)) {
			return true
		}
	}
	return false
}

// head reads the first sniffBytes of r; more tells that r may hold more. size is r's length when it is known, else -1:
// a body that fits is read into a buffer one byte longer, so that filling it can only mean there is more.
func head(r io.Reader, size int64) (b []byte, more bool) {
	n := int64(sniffBytes)
	if size >= 0 && size < n {
		n = size + 1
	}
	b = make([]byte, n)
	got, err := io.ReadFull(r, b)
	return b[:got], err == nil
}

// verdict is pfb_filter(FILE_MIME) on the staged body at path: its allow-listed type, or false with the detail
// pfb_validate_log() records. An octet stream is not accepted, but a structural probe may recognise what it holds
// (zip, gzip, bzip2, tar, in that order) and then it is that (ADR-45).
func verdict(ctx context.Context, path string) (mime, detected string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "file-not-found rc=-1", false
	}
	size := int64(-1)
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	b, more := head(f, size)
	f.Close()
	mime = classify(b, more)
	if mime == mimeOctet {
		for _, t := range [...]string{mimeZip, mimeGzip, mimeBzip2, mimeTar} {
			if structural(ctx, t, path, io.Discard) == nil {
				return t, "", true
			}
		}
	}
	if !mimeAllowed[mime] {
		return "", mime + " rc=0", false
	}
	return mime, "", true
}

// innerVerdict is `file -bZ --mime-type` for a gzip or bzip2 body: the type of what it holds, from the first bytes of the
// decompressed stream. Nothing at all is application/x-empty, which the allow-list does not name.
func innerVerdict(r io.Reader) string {
	b, more := head(r, -1)
	if len(b) == 0 {
		return mimeEmptyInner
	}
	return classify(b, more)
}

// gate runs the content gates on the staged ".raw" and returns the body to publish: the staged file itself for a text
// feed, or an archive's extraction staged beside the published copy. A refusal is a Result (without a Status), the
// extraction removed; ".raw" is the caller's. The order is pfb_download()'s: the verdict, room for the archive, its
// structural test, the inner verdict of a gzip or bzip2, the extraction, and a zip's verdict on what it extracted. Every
// step ends with the context's: PHP has no wall-clock bound on any of them.
func (f *Fetcher) gate(ctx context.Context, feed Feed, raw string, lastMod time.Time) (string, *Result) {
	// A refusal is the feed's fault unless the context ended the work: which of the two ended the work is what the error
	// that stopped it says, and for the verdict (whose probes swallow theirs) what the context says.
	refuse := func(stage, reason, detected string) (string, *Result) {
		if err := ctx.Err(); err != nil {
			return "", &Result{Reason: err.Error()}
		}
		return "", &Result{Reason: reason, Stage: stage, Detected: detected}
	}
	failed := func(err error, stage, reason, detected string) (string, *Result) {
		if ctxEnded(err) {
			return "", &Result{Reason: err.Error()}
		}
		return "", &Result{Reason: reason, Stage: stage, Detected: detected}
	}
	mime, detected, ok := verdict(ctx, raw)
	if !ok {
		return refuse("mime", "mime_not_allowed", detected)
	}
	switch mime {
	case mimeGzip, mimeBzip2, mimeZip, mimeTar:
	default:
		return raw, nil
	}
	if !lastMod.IsZero() {
		os.Chtimes(raw, lastMod, lastMod) // the remote timestamp rides on the archive too (A16)
	}
	// #2658: room for the archive itself and nothing more, as /var is a small RAM disk on a default install; a file
	// system that cannot say is no shortfall.
	if info, err := os.Stat(raw); err == nil {
		free := f.FreeBytes
		if free == nil {
			free = freeBytes
		}
		if avail, known := free(feed.Dir); known && avail < uint64(info.Size()) {
			return refuse("size", "staging_space_low", feed.Dir)
		}
	}
	if err := structural(ctx, mime, raw, io.Discard); err != nil {
		return failed(err, "structural", "probe_failed", mime+" "+filepath.Base(raw))
	}
	tarInner := false
	if mime == mimeGzip || mime == mimeBzip2 {
		inner := innerType(ctx, mime, raw)
		if !mimeAllowed[inner] {
			return refuse("inner", "compressed_mime_not_allowed", inner+" rc=0")
		}
		tarInner = inner == mimeTar
	}
	body, err := f.stage(ctx, feed, mime, raw, tarInner)
	if err != nil {
		code := exitFailed
		if errors.Is(err, errCeiling) {
			code = exitCeiling
		}
		return failed(err, "", extractionFailure(mime, code), "")
	}
	if mime == mimeZip {
		// What the list holds is the extraction, not the archive (#808): it is gated as a body, staged (#2169).
		if _, detected, ok := verdict(ctx, body); !ok {
			os.Remove(body)
			return refuse("inner", "inner_mime_not_allowed", detected)
		}
	}
	return body, nil
}
