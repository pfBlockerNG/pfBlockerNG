// Package digest is the digest sidecars of a feed's files: the xxh128 of the bytes PHP's pfb_content_hash() hashes, written
// as "<file>.xxhash128", and the legacy "<file>.md5" baseline PHP wrote before it (pfb_hash_read()). feedfetch keeps the
// published copy's digest with it and feedparse the source digest of a .norm; both read and write the same format.
package digest

import (
	"crypto/md5"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/pfBlockerNG/xxh3"
)

// The algorithms of a sidecar, named by the suffix of its file.
const (
	XXH128 = "xxhash128"
	MD5    = "md5"
)

// Bytes is the xxh128 of b, hex: what PHP's hash('xxh128') gives.
func Bytes(b []byte) string {
	h := xxh3.New128()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// File is the xxh128 of the file's bytes, hex: what PHP's hash_file('xxh128') writes to a sidecar.
func File(path string) (string, error) { return hashFile(path, xxh3.New128()) }

// MD5File reads only a legacy md5 baseline PHP wrote (pfb_local_feed_changed); nothing writes an md5.
func MD5File(path string) (string, error) { return hashFile(path, md5.New()) }

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

// Read is pfb_hash_read() for the sidecars of base: "<base>.xxhash128", else a legacy "<base>.md5", the algorithm named by
// the suffix. A missing, unreadable or malformed sidecar is no baseline, and a bad xxh128 never falls back to the md5 behind it.
func Read(base string) (algo, digest string) {
	for _, a := range [...]string{XXH128, MD5} {
		b, err := os.ReadFile(base + "." + a)
		if os.IsNotExist(err) {
			continue
		}
		digest = strings.Trim(string(b), " \t\n\r\x00\x0B")
		if err != nil || !isDigest(digest) {
			return "", ""
		}
		return a, digest
	}
	return "", ""
}

// isDigest reports whether s is 32 lower-case hex characters, as pfb_hash_read() requires.
func isDigest(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
