package update

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// dnsblOrigLink and dnsblOrigRemove are the move's writes: a test's fault seams.
var dnsblOrigLink, dnsblOrigRemove = os.Link, os.Remove

// dnsblOrigSidecars are what the Core Updater reads beside a feed's .orig: the conditional-GET validators
// (pfb_validator_write), the FTP size, which PHP never writes, and the content digests.
var dnsblOrigSidecars = append([]string{".orig.etag", ".orig.lastmod", ".orig.size"}, feedfetch.DigestSuffixes()...)

// MoveDNSBLOrig moves PHP's DNSBL downloads into the Core Updater's DNSBL feed folder, once, at the cutover (issue #4258):
// each <db>/dnsblorig/<feed>.orig, a regular file of a valid feed name, goes to <db>/dnsbl with its validators and digests,
// so the first Update re-downloads nothing it would not have before. A feed whose .orig the Core Updater holds is its own:
// it is left as it is, and PHP's superseded copies are removed. Anything else in dnsblorig stays.
//
// A feed moves by hard links, its sidecars before its .orig, and PHP's copies go only once the .orig is linked: a move cut
// short leaves either every PHP file in place, or the .orig linked, and the next move completes it. The Core Updater trusts
// validators and digests only beside a copy, so what a cut-short move linked is never trusted on its own. Nothing else writes
// dnsbl or dnsblorig while the move runs (PHP's DNSBL pass no longer runs at the cutover): the caller runs the Core Updater's recovery of the feed folder (feedstage.Recover) first, then
// the move until it returns nil, and only then the first Update, which would otherwise publish over a half-moved feed.
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
		if err := moveDNSBLOrigFeed(from, to, name); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func moveDNSBLOrigFeed(from, to, name string) error {
	src := func(suffix string) string { return filepath.Join(from, name+suffix) }
	dst := func(suffix string) string { return filepath.Join(to, name+suffix) }
	if held, err := os.Lstat(dst(".orig")); err == nil {
		if !held.Mode().IsRegular() {
			return nil // no copy: PHP's stays
		}
		// the Core Updater's own, or linked by a move cut short: PHP's copies are superseded, and no later move brings them back
		return removeDNSBLOrigSources(src)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(to, 0o755); err != nil {
		return err
	}
	for _, s := range dnsblOrigSidecars {
		// one left with no copy beside it, or linked by a move cut short: what PHP has replaces it
		if err := dnsblOrigRemove(dst(s)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		fi, err := os.Lstat(src(s))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return err
		case !fi.Mode().IsRegular():
			continue
		}
		if err := dnsblOrigLink(src(s), dst(s)); err != nil {
			return err
		}
	}
	// a link never replaces: a copy found there fails the move rather than being overwritten
	if err := dnsblOrigLink(src(".orig"), dst(".orig")); err != nil {
		return err
	}
	return removeDNSBLOrigSources(src)
}

// removeDNSBLOrigSources removes PHP's copies of a moved or superseded feed, its .orig last: while it stays, the next move
// finds a copy in dnsbl and finishes here.
func removeDNSBLOrigSources(src func(string) string) error {
	for _, s := range slices.Concat(dnsblOrigSidecars, []string{".orig"}) {
		if fi, err := os.Lstat(src(s)); err != nil || !fi.Mode().IsRegular() {
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			continue
		}
		if err := dnsblOrigRemove(src(s)); err != nil {
			return err
		}
	}
	return nil
}

// moveDNSBLOrig is the cutover's move, run by every Update before it decides its work (issue #4258's contract): the DNSBL
// feed folder is recovered first, then PHP's downloads are moved into it. Once nothing is left to move it costs one
// directory read. A move that fails fails the Update, so nothing is published over a half-moved feed, and the next Update
// tries once more: an error a retry never clears (a directory at a sidecar name, EXDEV, EACCES) fails each Update visibly.
func (u *updater) moveDNSBLOrig() error {
	if info, err := os.Lstat(u.db("dnsbl")); err == nil && info.IsDir() {
		if err := feedstage.Recover(u.db("dnsbl")); err != nil {
			return fmt.Errorf("the DNSBL feed folder cannot be recovered before PHP's downloads in dnsblorig move into it: %w", err)
		}
	}
	if err := MoveDNSBLOrig(u.loop.DBDir); err != nil {
		return fmt.Errorf("PHP's DNSBL downloads in dnsblorig cannot be moved into the DNSBL feed folder: %w", err)
	}
	return nil
}
