package feedfetch

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
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

// writeValidators stores what a response carried (pfb_validator_write): never an empty value, CR/LF stripped so an
// ETag cannot inject a header when it is sent back.
func writeValidators(feed Feed, etag string, lastMod time.Time) {
	if etag = strings.NewReplacer("\r", "", "\n", "").Replace(etag); etag != "" {
		os.WriteFile(feed.path(".orig.etag"), []byte(etag), 0o600)
	}
	if !lastMod.IsZero() && lastMod.Unix() > 0 {
		os.WriteFile(feed.path(".orig.lastmod"), []byte(strconv.FormatInt(lastMod.Unix(), 10)), 0o600)
	}
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
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
	if err := f.Close(); err != nil || werr != nil {
		return errors.New("staged body could not be written")
	}
	published := feed.path(".orig")
	if err := os.Rename(staged, published); err != nil {
		return errors.New("published copy could not be replaced")
	}
	os.WriteFile(feed.path(".orig.sha256"), []byte(digest), 0o600)
	if !lastMod.IsZero() {
		os.Chtimes(published, lastMod, lastMod)
	}
	return nil
}

// localDecision compares a local source with the published copy's digest (pfb_local_feed_changed); without a recorded
// digest the published copy itself is hashed, and any read failure means changed.
func localDecision(path string, feed Feed) Decision {
	baseline, err := os.ReadFile(feed.path(".orig.sha256"))
	if err != nil || len(baseline) == 0 {
		d, err := fileDigest(feed.path(".orig"))
		if err != nil {
			return Changed
		}
		baseline = []byte(d)
	}
	if d, err := fileDigest(path); err == nil && d == string(baseline) {
		return Unchanged
	}
	return Changed
}
