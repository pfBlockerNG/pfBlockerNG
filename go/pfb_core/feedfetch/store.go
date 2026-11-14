package feedfetch

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
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

// dropDigests removes the digest sidecars of the published copy, to be called before the copy is replaced: a digest that
// outlived its copy would let a source holding the older bytes read as unchanged.
func dropDigests(feed Feed) error {
	for _, s := range [...]string{".orig.xxhash128", ".orig.md5"} {
		if err := os.Remove(feed.path(s)); err != nil && !os.IsNotExist(err) {
			return errors.New("published digest could not be replaced")
		}
	}
	return nil
}

// publish makes body the published copy in one rename, finished as pfb_download_finalize_text() finishes it: the digest
// recorded is of wire, the raw bytes the transfer left (the probe hashes raw bytes, #713): body itself for a text feed,
// the archive for an extraction. Then UTF-16/32 text is transcoded to UTF-8 (#946), and a missing trailing newline is
// added (#1263).
func publish(feed Feed, body, wire string, lastMod time.Time) error {
	digest, err := fileDigest(wire)
	if err != nil {
		return errors.New("staged body could not be read")
	}
	transcode(body)
	f, err := os.OpenFile(body, os.O_RDWR, 0)
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
	if err := dropDigests(feed); err != nil {
		return err
	}
	if err := os.Rename(body, published); err != nil {
		return errors.New("published copy could not be replaced")
	}
	os.WriteFile(feed.path(".orig.xxhash128"), []byte(sum), 0o600)
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
