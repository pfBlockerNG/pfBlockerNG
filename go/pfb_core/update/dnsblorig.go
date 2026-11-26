package update

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// dnsblOrigRename is the move's one write: a test's fault seam.
var dnsblOrigRename = os.Rename

// dnsblOrigSidecars are what PHP keeps beside a DNSBL download: the conditional-GET validators (pfb_validator_write) and
// the content digests, under the names the Core Updater reads.
var dnsblOrigSidecars = []string{".etag", ".lastmod", ".xxhash128", ".md5"}

// MoveDNSBLOrig moves PHP's DNSBL downloads into the Core Updater's DNSBL feed folder, once, at the cutover (issue #4258):
// each <db>/dnsblorig/<feed>.orig, a regular file of a valid feed name, goes to <db>/dnsbl with its validators and digests,
// so the first Update re-downloads nothing it would not have before. A feed whose .orig the Core Updater already holds is
// its own and left as it is. The sidecars move before the .orig: the Core Updater trusts validators and digests only beside
// a copy, so a move cut short leaves at most a feed it downloads again, and the next move completes it. Anything else in
// dnsblorig stays.
func MoveDNSBLOrig(dbDir string) error {
	from, to := filepath.Join(dbDir, "dnsblorig"), filepath.Join(dbDir, "dnsbl")
	entries, err := os.ReadDir(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".orig")
		if !ok || !feedstage.ValidName(name) || !e.Type().IsRegular() {
			continue
		}
		if err := os.MkdirAll(to, 0o755); err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(to, name+".orig")); !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err) // nil: the Core Updater's own
			continue
		}
		for _, s := range append(dnsblOrigSidecars, "") {
			file := name + ".orig" + s
			if fi, err := os.Lstat(filepath.Join(from, file)); err != nil || !fi.Mode().IsRegular() {
				continue // none, or moved by a move cut short
			}
			if err := dnsblOrigRename(filepath.Join(from, file), filepath.Join(to, file)); err != nil {
				errs = append(errs, err)
				break
			}
		}
	}
	return errors.Join(errs...)
}
