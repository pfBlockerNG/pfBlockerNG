package feedparse

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/xxh3"
)

// NormResult is pfb_feed_normalize()'s answer: the file to parse, whether its content changed since the last pass and
// whether it is a usable .norm.
type NormResult struct {
	Path                string
	Changed, Normalized bool
}

// NormalizeFile is the storage half of pfb_feed_normalize() for the feed name in dir, with the same conversion rules as Normalize:
// the downloaded <name>.orig becomes <name>.norm, rebuilt only when <name>.norm is missing or <name>.norm.src.xxhash128 names
// another .orig. The .norm is written beside its target and renamed into place.
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

	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), ".pfbnorm_") {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
			}
		}
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

	source, err := os.Open(orig)
	if err != nil {
		return fallback
	}
	tmp, err := os.CreateTemp(dir, ".pfbnorm_*") // beside the target: a rename across filesystems is not atomic
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
	if cerr := tmp.Chmod(0o644); werr == nil { // CreateTemp makes 0600
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
