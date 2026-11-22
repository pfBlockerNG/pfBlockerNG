package feedfetch

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

type validators struct {
	etag    string
	lastMod time.Time
}

type ftpMetadata struct {
	lastMod time.Time
	size    int64
}

func ftpMetadataFor(t transfer) ftpMetadata {
	return ftpMetadata{lastMod: t.lastMod, size: t.size}
}

func ftpTime(unix int64) time.Time {
	if unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

func readFTPMetadata(feed Feed) ftpMetadata {
	return readFTPMetadataAt(feed.path(".orig"))
}

func readFTPMetadataAt(base string) ftpMetadata {
	var m ftpMetadata
	if b, err := os.ReadFile(base + ".lastmod"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			m.lastMod = ftpTime(n)
		}
	}
	if b, err := os.ReadFile(base + ".size"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			m.size = n
		}
	}
	return m
}

func writeSidecarAtomically(path, value string) {
	tmp := path + ".part"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		os.Remove(tmp)
		return
	}
	if os.Rename(tmp, path) != nil {
		os.Remove(tmp)
	}
}

func writeFTPMetadataAt(base string, m ftpMetadata) {
	lastMod, size := base+".lastmod", base+".size"
	os.Remove(lastMod)
	os.Remove(size)
	if !m.lastMod.IsZero() {
		writeSidecarAtomically(lastMod, strconv.FormatInt(m.lastMod.Unix(), 10))
	}
	if m.size > 0 {
		writeSidecarAtomically(size, strconv.FormatInt(m.size, 10))
	}
}

// readValidators returns the stored ETag and Last-Modified (pfb_validator_read), or nil when neither is usable.
func readValidators(feed Feed) *validators {
	var v validators
	if b, err := os.ReadFile(feed.path(".orig.etag")); err == nil {
		v.etag = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(feed.path(".orig.lastmod")); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			v.lastMod = time.Unix(n, 0)
		}
	}
	if v.etag == "" && v.lastMod.IsZero() {
		return nil
	}
	return &v
}

// writeValidators stores what a response carried for the published copy (pfb_validator_write): never an empty value,
// CR/LF stripped so an ETag cannot inject a header when it is sent back.
func writeValidators(feed Feed, etag string, lastMod time.Time) {
	writeValidatorsAt(feed.path(".orig"), etag, lastMod)
}

// writeValidatorsAt is writeValidators beside any base: a changed probe keeps them beside its body (#3911). Each file is
// replaced by a rename, never written through: a run folder holds hard links of the published ones.
func writeValidatorsAt(base, etag string, lastMod time.Time) {
	if etag = strings.NewReplacer("\r", "", "\n", "").Replace(etag); etag != "" {
		writeSidecarAtomically(base+".etag", etag)
	}
	if !lastMod.IsZero() && lastMod.Unix() > 0 {
		writeSidecarAtomically(base+".lastmod", strconv.FormatInt(lastMod.Unix(), 10))
	}
}

// DigestSuffixes are the digest sidecars of a feed's published copy: xxh128, and the legacy MD5 a digest read falls back to.
func DigestSuffixes() []string { return []string{".orig.xxhash128", ".orig.md5"} }

// dropDigests removes the digest sidecars of the published copy, to be called before the copy is replaced: a digest that
// outlived its copy would let a source holding the older bytes read as unchanged.
func dropDigests(feed Feed) error {
	for _, s := range DigestSuffixes() {
		if err := os.Remove(feed.path(s)); err != nil && !os.IsNotExist(err) {
			return errors.New("published digest could not be replaced")
		}
	}
	return nil
}

// finish is pfb_download_finalize_text() on the staged body, once its digest is taken: UTF-16/32 text transcoded to
// UTF-8 (#946), then a missing trailing newline added (#1263), and the body synced, so that the published copy survives
// a power loss whole, not as an empty file. The newline goes to a copy renamed over the body, never through it: a probe
// body staged by a rename may be a hard link of a published file.
func finish(body string) error {
	transcode(body)
	f, err := os.Open(body)
	if err != nil {
		return errors.New("staged body could not be read")
	}
	last := make([]byte, 1)
	var werr error
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		if _, err := f.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			werr = replaceByCopy(f, body, info.Mode().Perm(), []byte("\n"), time.Time{})
		}
	}
	serr := f.Sync()
	if err := f.Close(); err != nil || werr != nil || serr != nil {
		return errors.New("staged body could not be written")
	}
	return nil
}

// replaceByCopy replaces path, open as in, by a synced copy of it with tail at its end and, unless mtime is zero, that
// modification time: path may be a hard link of a published file, which is never written through.
func replaceByCopy(in *os.File, path string, mode os.FileMode, tail []byte, mtime time.Time) error {
	out, err := os.CreateTemp(filepath.Dir(path), ".pfbstage_")
	if err != nil {
		return err
	}
	_, err = in.Seek(0, io.SeekStart)
	if err == nil {
		_, err = io.Copy(out, in)
	}
	if err == nil {
		_, err = out.Write(tail)
	}
	err = errors.Join(err, out.Chmod(mode), out.Sync(), out.Close())
	if err == nil && !mtime.IsZero() {
		err = os.Chtimes(out.Name(), mtime, mtime)
	}
	if err == nil {
		err = os.Rename(out.Name(), path)
	}
	if err != nil {
		os.Remove(out.Name())
	}
	return err
}

// publish makes body the published copy in one rename, with digest beside it: the xxh128 of the raw bytes the transfer
// left, as the probe hashes them (#713).
func publish(feed Feed, body, digest string, lastMod time.Time) error {
	published := feed.path(".orig")
	if err := dropDigests(feed); err != nil {
		return err
	}
	if err := os.Rename(body, published); err != nil {
		return errors.New("published copy could not be replaced")
	}
	os.WriteFile(feed.path(".orig.xxhash128"), []byte(digest), 0o600)
	if !lastMod.IsZero() {
		os.Chtimes(published, lastMod, lastMod)
	}
	return nil
}

// localDecision compares a local source with the published copy's digest (pfb_local_feed_changed); without a baseline
// the published copy itself is hashed, and any read failure means changed.
func localDecision(path string, feed Feed) Decision {
	algo, baseline := digest.Read(feed.path(".orig"))
	sum := digest.File
	if algo == digest.MD5 {
		sum = digest.MD5File
	}
	if algo == "" {
		var err error
		if baseline, err = digest.File(feed.path(".orig")); err != nil {
			return Changed
		}
	}
	if d, err := sum(path); err == nil && d == baseline {
		return Unchanged
	}
	return Changed
}

// retime gives path the modification time mtime: in place when the file has one name only, otherwise on a copy renamed
// over it, as a hard link is never written through.
func retime(path string, mtime time.Time) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
		return replaceByCopy(in, path, info.Mode().Perm(), nil, mtime)
	}
	return os.Chtimes(path, mtime, mtime)
}
