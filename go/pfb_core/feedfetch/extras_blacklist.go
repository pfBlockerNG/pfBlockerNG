package feedfetch

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// blacklist is pfb_download() for a blacklist row. It reports whether the row succeeded.
func (f *Fetcher) blacklist(ctx context.Context, cfg ExtrasConfig, x Extra, req Request) bool {
	// A folder an interrupted swap left aside goes back before anything can fail, so a failed download leaves it in service
	// (owner, 2026-11-19; PHP recovers it only inside a publication).
	recoverDirs(cfg.DBDir)
	src, _ := f.entry(ctx, req)
	if src == nil || f.proxyUnusableFor(src) {
		return false
	}
	base := filepath.Join(x.Dir, x.Download)
	raw := base + ".raw"
	defer os.Remove(raw)
	t := f.fetch(ctx, src, req, raw, nil)
	if t.reason != "" {
		return false
	}
	if t.status == 304 {
		_, err := os.Stat(base + ".orig")
		return err == nil
	}
	if t.status != 200 && t.status != 221 && t.status != 226 {
		return false
	}
	// Only a tar is a category archive: a text list, a zip or a bzip2 leaves the folder as it is (issues #2635, #2739).
	mime, _, ok := verdict(ctx, raw)
	if !ok || mime != mimeGzip && mime != mimeTar {
		return false
	}
	if !t.lastMod.IsZero() {
		os.Chtimes(raw, t.lastMod, t.lastMod)
	}
	if f.extractShort(raw, x.Dir, cfg.DBDir, filepath.Join(x.Dir, x.File)) || structural(ctx, mime, raw, io.Discard) != nil {
		return false
	}
	if rename(raw, base) != nil {
		return false
	}
	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(base), ".tar.gz"), ".tar")
	if !wordName(name) {
		return false
	}
	if names, ok := tarNames(ctx, mime, base); !ok || unsafeMember(names) {
		os.Remove(base)
		return false
	}
	if !replaceDir(filepath.Join(cfg.DBDir, name), func(dir string) error {
		return f.extractCategories(ctx, mime, base, name, dir)
	}) {
		return false
	}
	// No reader takes the change-detection sidecars of a category archive (issue #2738).
	for _, sfx := range []string{".orig", ".xxhash128", ".md5"} {
		os.Remove(base + sfx)
	}
	touch(filepath.Join(cfg.DBDir, name, name+".update"))
	return true
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

// linkMember is a hard-link member: name, under dir, becomes another name for target, already extracted there.
func linkMember(dir, target, name string) error {
	for _, n := range []string{target, name} {
		if !filepath.IsLocal(filepath.FromSlash(n)) {
			return errUnsafeMember
		}
	}
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.Link(filepath.Join(dir, filepath.FromSlash(target)), p)
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
		return f.writeMember(dir, categoryName(h.Name, name), h.Typeflag == tar.TypeDir, h.Typeflag == tar.TypeReg, r)
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
		return errNoDatabase
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

// stageBackup prefixes the live folder replaceDir moves aside while it swaps.
const stageBackup = ".pfbstagebak2_"

// replaceDir is pfb_stage_publish_dir(): extract fills a directory staged beside target, which then replaces target
// whole. The live folder is moved aside first and put back if the swap fails; one an interrupted swap left aside is put
// back before anything else.
func replaceDir(target string, extract func(dir string) error) bool {
	parent := filepath.Dir(target)
	if !recoverDirs(parent) {
		return false
	}
	staged, err := os.MkdirTemp(parent, ".pfbstagedir_")
	if err != nil {
		return false
	}
	defer os.RemoveAll(staged)
	if os.Chmod(staged, 0o755) != nil || extract(staged) != nil {
		return false
	}
	backup := ""
	if info, err := os.Lstat(target); err == nil {
		if !info.IsDir() {
			return false
		}
		backup = filepath.Join(parent, stageBackup+filepath.Base(target))
		if _, err := os.Lstat(backup); err == nil || rename(target, backup) != nil {
			return false
		}
	}
	if rename(staged, target) != nil {
		if backup != "" {
			recoverDirs(parent)
		}
		return false
	}
	return backup == "" || os.RemoveAll(backup) == nil
}

// recoverDirs is pfb_stage_publish_dir_recover(): every folder an interrupted swap left aside in dir goes back to its
// name, or is dropped when a folder stands there again. It reports false when one could not be settled.
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
			if !info.IsDir() || os.RemoveAll(backup) != nil {
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
