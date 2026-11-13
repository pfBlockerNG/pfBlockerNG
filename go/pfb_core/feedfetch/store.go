package feedfetch

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pfBlockerNG/xxh3"
)

type validators struct {
	etag    string
	lastMod time.Time
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

// writeValidatorsAt is writeValidators beside any base: a changed probe keeps them beside its body (#3911).
func writeValidatorsAt(base, etag string, lastMod time.Time) {
	if etag = strings.NewReplacer("\r", "", "\n", "").Replace(etag); etag != "" {
		os.WriteFile(base+".etag", []byte(etag), 0o600)
	}
	if !lastMod.IsZero() && lastMod.Unix() > 0 {
		os.WriteFile(base+".lastmod", []byte(strconv.FormatInt(lastMod.Unix(), 10)), 0o600)
	}
}

// fileDigest is the file's xxh128, hex: what PHP's hash('xxh128') writes to ".orig.xxhash128".
func fileDigest(path string) (string, error) { return hashFile(path, xxh3.New128()) }

// md5Digest reads only a legacy ".orig.md5" baseline PHP wrote (pfb_local_feed_changed); nothing writes an md5.
func md5Digest(path string) (string, error) { return hashFile(path, md5.New()) }

func hashFile(path string, h hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Content-change detection only: the feed server controls the bytes, so collision resistance is no security property.
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// publish makes the staged body the published copy in one rename: its raw-byte digest is recorded first (the probe
// hashes raw bytes, #713), then a missing trailing newline is added (#1263).
func publish(feed Feed, staged string, lastMod time.Time) error {
	digest, err := fileDigest(staged)
	if err != nil {
		return errors.New("staged body could not be read")
	}
	f, err := os.OpenFile(staged, os.O_RDWR, 0)
	if err != nil {
		return errors.New("staged body could not be read")
	}
	last := make([]byte, 1)
	var werr error
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		if _, err := f.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			_, werr = f.WriteAt([]byte("\n"), info.Size())
		}
	}
	serr := f.Sync() // the published copy survives a power loss whole, not as an empty file
	if err := f.Close(); err != nil || werr != nil || serr != nil {
		return errors.New("staged body could not be written")
	}
	published := feed.path(".orig")
	// A digest that outlived its copy would let an upstream revert to those older bytes read as unchanged.
	for _, s := range [...]string{".orig.xxhash128", ".orig.md5"} {
		if err := os.Remove(feed.path(s)); err != nil && !os.IsNotExist(err) {
			return errors.New("published digest could not be replaced")
		}
	}
	if err := os.Rename(staged, published); err != nil {
		return errors.New("published copy could not be replaced")
	}
	os.WriteFile(feed.path(".orig.xxhash128"), []byte(digest), 0o600)
	if !lastMod.IsZero() {
		os.Chtimes(published, lastMod, lastMod)
	}
	return nil
}

// readBaseline is pfb_hash_read: ".orig.xxhash128", else a legacy ".orig.md5", named by its suffix. A missing,
// unreadable or malformed sidecar is no baseline, and a bad xxh128 never falls back to the md5 behind it.
func readBaseline(feed Feed) (algo, digest string) {
	for _, a := range [...]string{"xxhash128", "md5"} {
		b, err := os.ReadFile(feed.path(".orig." + a))
		if os.IsNotExist(err) {
			continue
		}
		digest = strings.Trim(string(b), " \t\n\r\x00\x0B")
		if err != nil || len(digest) != 32 || !allIn(digest, "0123456789abcdef") {
			return "", ""
		}
		return a, digest
	}
	return "", ""
}

// localDecision compares a local source with the published copy's digest (pfb_local_feed_changed); without a baseline
// the published copy itself is hashed, and any read failure means changed.
func localDecision(path string, feed Feed) Decision {
	algo, baseline := readBaseline(feed)
	digest := fileDigest
	if algo == "md5" {
		digest = md5Digest
	}
	if algo == "" {
		var err error
		if baseline, err = fileDigest(feed.path(".orig")); err != nil {
			return Changed
		}
	}
	if d, err := digest(path); err == nil && d == baseline {
		return Unchanged
	}
	return Changed
}
