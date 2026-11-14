package feedfetch

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// Containers: the standard library in place of the unzip, gunzip, bzip2 and tar that pfb_download() runs. An archive is
// read the way `tar -xOf` and `gunzip -c` read it: every member's bytes, concatenated, and no member name ever reaches the
// file system (the ADR-46 member guard belongs to the Extras extractions, which write names).

const (
	// maxExtract is what `ulimit -f 4194304` lets one file hold under FreeBSD's sh, in 512-byte blocks: PHP's ceiling on
	// an extracted payload. It is per file, not per archive, and no member count or ratio is bounded (#2658).
	maxExtract = 4194304 * 512

	exitFailed  = 1   // an extraction that ended in an error
	exitCeiling = 153 // SIGXFSZ (128 + 25): the writer that outgrew the ceiling
)

var errCeiling = errors.New("extraction outgrew the per-file ceiling")

// ctxReader ends a read once the context is done, so an extraction or a structural test stops with it (PHP has no
// wall-clock bound on either). It wraps what a decompressor yields, never what it reads: a bomb turns 4 KiB of bzip2
// into hundreds of MiB, which a poll of the input lets run on past the context (a 4 GiB bomb by 16 s, #3973).
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// inflate is the stream a gzip or bzip2 file holds, read under the context.
func inflate(ctx context.Context, mime string, f io.Reader) (io.Reader, error) {
	if mime == mimeBzip2 {
		return ctxReader{ctx, bzip2.NewReader(f)}, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return ctxReader{ctx, zr}, nil
}

// structural is the structural test of an archive (unzip -t, gunzip -t, bzip2 -t, tar -tf): the whole of it is read, and the
// checks each format carries (a gzip's CRC, a zip's central directory and member CRCs, a tar's header sums) must hold.
// An archive with nothing in it fails, as unzip -t's exit status says. What a gzip, bzip2 or zip member holds goes to out:
// io.Discard, which a test replaces to count it.
func structural(ctx context.Context, mime, path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	switch mime {
	case mimeGzip, mimeBzip2:
		zr, err := inflate(ctx, mime, f)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, zr)
		return err
	case mimeZip:
		zr, err := openZip(f)
		if err != nil {
			return err
		}
		if len(zr.File) == 0 {
			return errors.New("zip without members")
		}
		for _, zf := range zr.File {
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			_, err = io.Copy(out, ctxReader{ctx, rc})
			rc.Close()
			if err != nil {
				return err
			}
		}
		return nil
	case mimeTar:
		tr := tar.NewReader(f)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := tr.Next(); errors.Is(err, io.EOF) {
				return nil
			} else if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
				return err
			}
		}
	}
	return nil
}

// openZip reads the central directory. A member name that would leave its directory is no fault here: nothing is
// extracted to a name.
func openZip(f *os.File) (*zip.Reader, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(f, info.Size())
	if errors.Is(err, zip.ErrInsecurePath) {
		err = nil
	}
	return zr, err
}

// capWriter refuses the write that would take a file past limit bytes: the one RLIMIT_FSIZE kills a writer for.
type capWriter struct {
	w    io.Writer
	left int64 // bytes it may still write
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		return 0, errCeiling
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

// commaWriter is `sed 's/,[[:space:]]/; /g' | tr ',' '\n'`, the zip workaround for lists that keep their entries on one
// line (SFS, hpHosts): a comma and the one white-space byte after it become "; ", any other comma a newline. sed works a
// line at a time, so a comma before a newline is a plain comma; shortcut: white space is ASCII (sed's locale may add more).
type commaWriter struct {
	w       io.Writer
	pending bool // a comma whose follower has not arrived yet
	buf     []byte
}

func (c *commaWriter) Write(p []byte) (int, error) {
	out := c.buf[:0]
	for _, b := range p {
		if c.pending {
			c.pending = false
			if b == ' ' || b == '\t' || b == '\v' || b == '\f' || b == '\r' {
				out = append(out, ';', ' ')
				continue
			}
			out = append(out, '\n')
		}
		if b == ',' {
			c.pending = true
			continue
		}
		out = append(out, b)
	}
	c.buf = out
	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// flush ends the stream: a comma last of all is a newline.
func (c *commaWriter) flush() error {
	if !c.pending {
		return nil
	}
	c.pending = false
	_, err := c.w.Write([]byte{'\n'})
	return err
}

// innerType is what `file -bZ --mime-type` says of a gzip or bzip2 body: the type of the stream it holds.
func innerType(ctx context.Context, mime, path string) string {
	f, err := os.Open(path)
	if err != nil {
		return mimeOctet
	}
	defer f.Close()
	zr, err := inflate(ctx, mime, f)
	if err != nil {
		return mimeOctet
	}
	return innerVerdict(zr)
}

// extract writes the payload of the archive at path to w: a gzip's or bzip2's stream (a tar's members when tarInner), a
// tar's members, a zip's members through commaWriter. A non-regular member (a directory, a link) has no bytes to add.
func extract(ctx context.Context, mime, path string, tarInner bool, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader
	switch mime {
	case mimeGzip, mimeBzip2:
		zr, err := inflate(ctx, mime, f)
		if err != nil {
			return err
		}
		src = zr
	case mimeZip:
		zr, err := openZip(f)
		if err != nil {
			return err
		}
		cw := &commaWriter{w: w}
		for _, zf := range zr.File {
			if !zf.Mode().IsRegular() {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			_, err = io.Copy(cw, ctxReader{ctx, rc})
			rc.Close()
			if err != nil {
				return err
			}
		}
		return cw.flush()
	default:
		src = f
		tarInner = true
	}
	if !tarInner {
		_, err = io.Copy(w, src) // a gzip's or bzip2's, minding the context (inflate)
		return err
	}
	tr := tar.NewReader(src)
	for {
		if _, err := tr.Next(); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return err
		}
		if _, err := io.Copy(w, ctxReader{ctx, tr}); err != nil {
			return err
		}
	}
}

// stage extracts into a file beside the published copy (pfb_stage_publish): 0644 when it is whole, gone when it is not.
// It returns the file, or what ended the extraction.
func (f *Fetcher) stage(ctx context.Context, feed Feed, mime, raw string, tarInner bool) (string, error) {
	out, err := os.CreateTemp(feed.Dir, ".pfbstage_")
	if err != nil {
		return "", err
	}
	limit := f.extractMax
	if limit <= 0 {
		limit = maxExtract
	}
	err = extract(ctx, mime, raw, tarInner, &capWriter{w: out, left: limit})
	if cerr := out.Chmod(0o644); err == nil {
		err = cerr
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}

// ctxEnded tells that err is the context's own: a cancelled or expired context is no fault of the feed.
func ctxEnded(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// extractionFailure is pfb_download()'s text for an extraction that failed with status code.
func extractionFailure(mime string, code int) string {
	var text string
	switch mime {
	case mimeGzip:
		text = fmt.Sprintf("gzip extraction failed (gunzip exit %d)", code)
	case mimeBzip2:
		text = fmt.Sprintf("bzip2 extraction failed (bzip2 exit %d)", code)
	case mimeZip:
		text = fmt.Sprintf("zip publish failed (tar exit %d)", code)
	default:
		text = fmt.Sprintf("tar extraction failed (tar exit %d)", code)
	}
	if code == exitCeiling {
		text += " -- output exceeded the extraction size ceiling"
	}
	return text
}
