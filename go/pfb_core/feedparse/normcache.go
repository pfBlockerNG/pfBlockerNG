package feedparse

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/xxh3"
)

// NormResult is pfb_feed_normalize()'s answer: the file to parse, whether its content changed since the last pass and
// whether it is a usable .norm.
type NormResult struct {
	Path                string
	Changed, Normalized bool
}

// openNormSource opens the .orig that NormalizeFile streams; tests replace it to inject read errors.
var openNormSource = func(path string) (io.ReadCloser, error) { return os.Open(path) }

// NormalizeFile is the storage half of pfb_feed_normalize() for the feed name in dir, with the same conversion rules as Normalize:
// the downloaded <name>.orig becomes <name>.norm, rebuilt only when <name>.norm is missing or <name>.norm.src.xxhash128 names
// another .orig. The .norm is written to <name>.norm.tmp beside its target and renamed into place; calls in one dir run one at a
// time under a nonblocking flock on the dir. Contention returns the raw .orig without touching the cache or temporary.
//
// The .orig is hashed and converted through bounded streams. The .norm and the sidecar are 0644, as the old path writes them, for a
// pre-script that drops privileges.
//
// Path is the .norm, or the .orig on any failure: a feed degrades to raw parsing, never to an empty one. Changed is false only
// when the normalized content is proven unchanged against a recorded baseline (a fresh sidecar, or a rebuild that is byte for
// byte the .norm it replaces); a missing or corrupt sidecar, or a legacy md5 one, is no baseline and reports true, so that
// clearing the sidecars (Force) defeats the skip that rides on it.
func NormalizeFile(dir, name string) NormResult {
	orig, norm := filepath.Join(dir, name+".orig"), filepath.Join(dir, name+".norm")
	srcBase := filepath.Join(dir, name+".norm.src")
	fallback := NormResult{Path: orig, Changed: true}

	// Two calls for one feed would share <name>.norm.tmp and pair one call's .norm with the other's sidecar: one call per directory.
	lock, err := os.Open(dir)
	if err != nil {
		return fallback
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fallback
	}

	srcDigest, err := digest.File(orig)
	if err != nil {
		return fallback
	}
	algo, recorded := digest.Read(srcBase)
	if algo == digest.XXH128 && recorded == srcDigest {
		if _, err := os.Stat(norm); err == nil {
			return NormResult{Path: norm, Normalized: true}
		}
	}
	prev, err := digest.File(norm)
	hadBaseline := algo == digest.XXH128 && err == nil

	source, err := openNormSource(orig)
	if err != nil {
		return fallback
	}
	tmpPath := norm + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600) // beside the target: a rename across filesystems is not atomic
	if err != nil {
		source.Close()
		return fallback
	}
	sourceHash := xxh3.New128()
	normErr := normalizeStream(io.TeeReader(source, sourceHash), tmp)
	sourceErr := source.Close()
	if normErr != nil || sourceErr != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fallback
	}
	srcDigest = hex.EncodeToString(sourceHash.Sum(nil))
	var werr error
	if cerr := tmp.Chmod(0o644); werr == nil { // The named temp starts at 0600.
		werr = cerr
	}
	if serr := tmp.Sync(); werr == nil { // the .norm survives a power loss whole, not as an empty file behind a fresh sidecar
		werr = serr
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return fallback
	}
	outDigest, err := digest.File(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		return fallback
	}
	changed := !(hadBaseline && outDigest == prev)
	sidecar := srcBase + "." + digest.XXH128
	if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
		os.Remove(tmp.Name())
		return fallback
	}
	if err := os.Rename(tmp.Name(), norm); err != nil {
		os.Remove(tmp.Name())
		return fallback
	}
	if err := os.WriteFile(sidecar, []byte(srcDigest), 0o644); err != nil {
		return fallback
	}
	return NormResult{Path: norm, Changed: changed, Normalized: true}
}
