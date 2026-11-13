package feedparse

import (
	"os"
	"path/filepath"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// NormResult is pfb_feed_normalize()'s answer: the file to parse, whether its content changed since the last pass and
// whether it is a usable .norm.
type NormResult struct {
	Path                string
	Changed, Normalized bool
}

// NormalizeFile is the storage half of pfb_feed_normalize() for the feed name in dir, with Normalize as the conversion: the
// downloaded <name>.orig becomes <name>.norm, rebuilt only when <name>.norm is missing or <name>.norm.src.xxhash128 (the xxh128
// of the .orig the .norm was built from) names another .orig. The .norm is written beside its target and renamed into place.
//
// The .orig is read whole: at the download ceiling (2 GiB) the peak is more than twice the feed, and about three times more for a
// UTF-16 one. The .norm and the sidecar are 0644, as the old path writes them, for a pre-script that drops privileges.
//
// Path is the .norm, or the .orig on any failure: a feed degrades to raw parsing, never to an empty one. Changed is false only
// when the normalized content is proven unchanged against a recorded baseline (a fresh sidecar, or a rebuild that is byte for
// byte the .norm it replaces); a missing or corrupt sidecar, or a legacy md5 one, is no baseline and reports true, so that
// clearing the sidecars (Force) defeats the skip that rides on it.
func NormalizeFile(dir, name string) NormResult {
	orig, norm := filepath.Join(dir, name+".orig"), filepath.Join(dir, name+".norm")
	srcBase := filepath.Join(dir, name+".norm.src")
	fallback := NormResult{Path: orig, Changed: true}

	// The digest is of the bytes about to be converted: a .orig replaced meanwhile reads as stale on the next pass, never as fresh.
	src, err := os.ReadFile(orig)
	if err != nil {
		return fallback
	}
	srcDigest := digest.Bytes(src)
	algo, recorded := digest.Read(srcBase)
	if algo == digest.XXH128 && recorded == srcDigest {
		if _, err := os.Stat(norm); err == nil {
			return NormResult{Path: norm, Normalized: true}
		}
	}
	prev, err := digest.File(norm)
	hadBaseline := algo == digest.XXH128 && err == nil

	out := Normalize(src)
	tmp, err := os.CreateTemp(dir, ".pfbnorm_*") // beside the target: a rename across filesystems is not atomic
	if err != nil {
		return fallback
	}
	_, werr := tmp.Write(out)
	if cerr := tmp.Chmod(0o644); werr == nil { // CreateTemp makes 0600
		werr = cerr
	}
	if serr := tmp.Sync(); werr == nil { // the .norm survives a power loss whole, not as an empty file behind a fresh sidecar
		werr = serr
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil || os.Rename(tmp.Name(), norm) != nil {
		os.Remove(tmp.Name())
		return fallback
	}
	os.WriteFile(srcBase+"."+digest.XXH128, []byte(srcDigest), 0o644)
	return NormResult{Path: norm, Changed: !(hadBaseline && digest.Bytes(out) == prev), Normalized: true}
}
