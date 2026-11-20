package feedfetch

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// The Blacklist category archives (#3978): the blacklist branches of pfb_download(). A row's tar (gzipped or not) is
// kept as "<dbdir>/<download>", and every member under a folder named for its category ("<cat>/domains" or
// "<cat>/<sub>/domains") is published as "<name>_<cat>" or "<name>_<cat>_<sub>" in the category folder "<dbdir>/<name>",
// which is replaced whole. <name> is the download's name without ".tar.gz" or ".tar".

// The two `tar -s` rules of the extraction, in order: the first that matches renames the member. They match as POSIX
// regular expressions do: leftmost-longest, with "." matching a line break too.
var blacklistRules = []*regexp.Regexp{posix(`(?s).*/(.*)/(.*)/domains`), posix(`(?s).*/(.*)/domains`)}

func posix(expr string) *regexp.Regexp {
	re := regexp.MustCompile(expr)
	re.Longest()
	return re
}

// errNoCategory is a category archive whose extraction holds no category file.
var errNoCategory = errors.New("archive holds no category")

// blacklist is pfb_download() for a blacklist row.
func (f *Fetcher) blacklist(ctx context.Context, cfg ExtrasConfig, x Extra, req Request) Result {
	// A folder an interrupted swap left aside goes back before anything can fail, so a failed download leaves it in service
	// (owner, 2026-11-19; PHP recovers it only inside a publication).
	recoverDirs(cfg.DBDir)
	base := filepath.Join(x.Dir, x.Download)
	raw := base + ".raw"
	defer os.Remove(raw)
	_, t, r := f.extrasFetch(ctx, req, raw)
	if r != nil {
		return *r
	}
	if t.status == 304 {
		if _, err := os.Stat(base + ".orig"); err == nil {
			return accepted
		}
		return transferRefused(304)
	}
	if !accepts(t.status) {
		return transferRefused(t.status)
	}
	// Only a tar is a category archive: a text list, a zip or a bzip2 leaves the folder as it is (issues #2635, #2739).
	mime, detected, ok := verdict(ctx, raw)
	if !ok {
		return refused("mime", "mime_not_allowed", detected)
	}
	if mime != mimeGzip && mime != mimeTar {
		return refused("extract", "blacklist_not_archive", mime)
	}
	if !t.lastMod.IsZero() {
		os.Chtimes(raw, t.lastMod, t.lastMod)
	}
	if f.extractShort(raw, x.Dir, cfg.DBDir, filepath.Join(x.Dir, x.File)) {
		return refused("size", "staging_space_low", filepath.Base(raw))
	}
	if structural(ctx, mime, raw, io.Discard) != nil {
		return refused("structural", "probe_failed", mime+" "+filepath.Base(raw))
	}
	if rename(raw, base) != nil {
		return publishRefused
	}
	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(base), ".tar.gz"), ".tar")
	if !wordName(name) {
		return refused("extract", "invalid_filename", name)
	}
	names, listed := tarNames(ctx, mime, base)
	if r := memberRefused(names, listed); r != nil {
		os.Remove(base)
		return *r
	}
	whole := func(target string, extract func(string) error) (bool, string) { return replaceDir(target, extract), "" }
	if r := published(whole, filepath.Join(cfg.DBDir, name), "blacklist", filepath.Base(base), func(dir string) error {
		err := f.extractCategories(ctx, mime, base, name, dir)
		if err == nil {
			touch(filepath.Join(dir, name+".update"))
		}
		return err
	}); !r.OK {
		return r
	}
	// No reader takes the change-detection sidecars of a category archive (issue #2738).
	for _, sfx := range []string{".orig", ".xxhash128", ".md5"} {
		os.Remove(base + sfx)
	}
	return accepted
}

// wordName is pfb_filter(PFB_FILTER_WORD) as its caller takes it: letters, digits and underscores, and neither "" nor "0".
func wordName(s string) bool {
	if s == "" || s == "0" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !word(s[i]) {
			return false
		}
	}
	return true
}

// linkMember is a hard-link member: name, under dir, becomes another name for target, already extracted there, and
// replaces what an earlier member left under that name (removeEarlier). A link whose target is not an extracted file (a
// skipped link or special member, a member outside the categories, a path that cannot exist, or none at all) is
// skipped, and still replaces the earlier entry of its name, as any later member does. A link to itself is a no-op.
func linkMember(dir, target, name string) error {
	for _, n := range []string{target, name} {
		if !filepath.IsLocal(filepath.FromSlash(n)) {
			return errUnsafeMember
		}
	}
	from, p := filepath.Join(dir, filepath.FromSlash(target)), filepath.Join(dir, filepath.FromSlash(name))
	if p == from {
		return nil
	}
	if err := removeEarlier(p); err != nil {
		return err
	}
	if info, err := os.Lstat(from); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.Link(from, p)
}

// removeEarlier removes what an earlier member left at p before a later file, link or skipped member takes the name, so
// the later member wins: a file, or an empty folder. A folder that holds other members refuses the archive.
func removeEarlier(p string) error {
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// extractCategories is `tar -xf --include='*domains' -s <blacklistRules>` into dir, then pfb_blacklist_tar_finalize_staged():
// a top-level file named for the archive must be there, and a dash in such a file's name becomes an underscore.
func (f *Fetcher) extractCategories(ctx context.Context, mime, archive, name, dir string) error {
	err := walkTar(ctx, mime, archive, func(h *tar.Header, r io.Reader) error {
		if !categoryMember(h.Name) {
			return nil
		}
		if h.Typeflag == tar.TypeLink {
			// tar renames a hard link's target by the same rules, so a linked category is published too.
			return linkMember(dir, categoryName(h.Linkname, name), categoryName(h.Name, name))
		}
		return f.writeMember(dir, categoryName(h.Name, name), h.Typeflag == tar.TypeDir, regularMember(h), r)
	})
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	found := false
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasPrefix(e.Name(), name) {
			continue
		}
		found = true
		if strings.Contains(e.Name(), "-") {
			if err := os.Rename(filepath.Join(dir, e.Name()), filepath.Join(dir, strings.ReplaceAll(e.Name(), "-", "_"))); err != nil {
				return err
			}
		}
	}
	if !found {
		return errNoCategory
	}
	return nil
}

// categoryMember is bsdtar's --include='*domains': the name, or a folder it sits in, ends in "domains".
func categoryMember(member string) bool {
	for _, c := range strings.Split(strings.TrimSuffix(member, "/"), "/") {
		if strings.HasSuffix(c, "domains") {
			return true
		}
	}
	return false
}

// categoryName applies the first of blacklistRules that matches, once, as `tar -s` does.
func categoryName(member, name string) string {
	for n, re := range blacklistRules {
		m := re.FindStringSubmatchIndex(member)
		if m == nil {
			continue
		}
		cat := name + "_" + member[m[2]:m[3]]
		if n == 0 {
			cat += "_" + member[m[4]:m[5]]
		}
		return member[:m[0]] + cat + member[m[1]:]
	}
	return member
}

// stageBackup prefixes the live folder an interrupted publication of today's PHP (pfb_stage_publish_dir()) left aside.
const stageBackup = ".pfbstagebak2_"

// replaceDir publishes a folder whole in one step (#4141): extract fills a new generation beside target,
// .<name>.<pid>.<8 hex>, and a link to it is renamed over target, so target is never absent and a run killed at any
// point leaves the previous generation or the new one. The publication holds .<name>.lock beside target throughout and
// is refused while another holds it, so its cleanup (every generation but this one and the previous) never meets one
// being written. A target that is still a real folder waits under .pfbstagebak2_<name> while the link replaces it (so
// recoverDirs puts it back after a run killed in between, or a failed restore) and then becomes the previous generation
// (a run killed after the link landed leaves it to be dropped beside the link); a missing target leaves no previous
// generation to tell apart, so none is removed. A folder an interrupted publication left aside is put back first.
func replaceDir(target string, extract func(dir string) error) bool {
	parent, base := filepath.Dir(target), filepath.Base(target)
	if !recoverDirs(parent) {
		return false
	}
	lock, err := os.OpenFile(filepath.Join(parent, "."+base+".lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return false
	}
	defer lock.Close() // closing the file releases the lock
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return false
	}
	previous := ""
	if to, err := os.Readlink(target); err == nil {
		var ours bool
		if previous, ours = generationOf(target, to); !ours {
			return false // a link this code did not make is the administrator's layout
		}
	}
	gen := generationDir(target)
	if os.Mkdir(gen, 0o755) != nil {
		return false
	}
	if os.Chmod(gen, 0o755) != nil || extract(gen) != nil {
		os.RemoveAll(gen)
		return false
	}
	aside := ""
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink == 0 {
		// a real folder waits under the name recoverDirs puts back, until the link stands in its place
		aside = filepath.Join(parent, stageBackup+base)
		if !info.IsDir() || os.Rename(target, aside) != nil {
			os.RemoveAll(gen)
			return false
		}
	}
	link := gen + ".link"
	if os.Symlink(filepath.Base(gen), link) != nil || rename(link, target) != nil {
		os.Remove(link)
		if aside != "" {
			os.Rename(aside, target)
		}
		os.RemoveAll(gen)
		return false
	}
	if aside != "" {
		previous = generationDir(target)
		if os.Rename(aside, previous) != nil {
			return true // recoverDirs drops it beside the link
		}
		previous = filepath.Base(previous)
	}
	if previous == "" {
		return true
	}
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		name := e.Name()
		if name != filepath.Base(gen) && name != previous && isGeneration(base, strings.TrimSuffix(name, ".link")) {
			os.RemoveAll(filepath.Join(parent, name))
		}
	}
	return true
}

// generationDir is a new generation's folder beside target: .<name>.<pid>.<8 hex>.
func generationDir(target string) string {
	var id [4]byte
	rand.Read(id[:])
	return filepath.Join(filepath.Dir(target),
		fmt.Sprintf(".%s.%d.%s", filepath.Base(target), os.Getpid(), hex.EncodeToString(id[:])))
}

// generationID reports whether s is a generation's <pid>.<8 hex>.
var generationID = regexp.MustCompile(`^[0-9]+\.[0-9a-f]{8}$`).MatchString

// generationOf is the name of the folder a link at target points to (to, as Readlink spells it), and whether that is a
// generation of target beside it: one this code made.
func generationOf(target, to string) (string, bool) {
	if !filepath.IsAbs(to) {
		to = filepath.Join(filepath.Dir(target), to)
	}
	to = filepath.Clean(to)
	return filepath.Base(to), filepath.Dir(to) == filepath.Clean(filepath.Dir(target)) &&
		isGeneration(filepath.Base(target), filepath.Base(to))
}

// isGeneration reports whether name is a generation of the folder base: .<base>.<pid>.<8 hex>.
func isGeneration(base, name string) bool {
	rest, ok := strings.CutPrefix(name, "."+base+".")
	return ok && generationID(rest)
}

// recoverDirs is pfb_stage_publish_dir_recover(): every folder an interrupted swap left aside in dir goes back to its
// name, or is dropped when a folder, or a link to a generation, stands there again; a link to a generation that names
// no folder gives way to it, and a link this code did not make is left alone. It reports false when one could not be
// settled.
func recoverDirs(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	ok := true
	for _, e := range entries {
		live, found := strings.CutPrefix(e.Name(), stageBackup)
		if !found || live == "" || !e.IsDir() {
			continue
		}
		backup, live := filepath.Join(dir, e.Name()), filepath.Join(dir, live)
		if info, err := os.Lstat(live); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				to, _ := os.Readlink(live)
				if _, ours := generationOf(live, to); !ours {
					ok = false // a link this code did not make is left as it is
					continue
				}
				if gen, err := os.Stat(live); os.IsNotExist(err) || err == nil && !gen.IsDir() {
					// a link naming no folder: the folder set aside is the only copy
					if os.Remove(live) != nil || rename(backup, live) != nil {
						ok = false
					}
					continue
				} else if err != nil {
					ok = false
					continue
				}
			} else if !info.IsDir() {
				ok = false
				continue
			}
			if os.RemoveAll(backup) != nil {
				ok = false
			}
			continue
		}
		if rename(backup, live) != nil {
			ok = false
		}
	}
	return ok
}
