package feedfetch

import (
	"archive/tar"
	"archive/zip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// publishGeoIP is the geoip branch of pfb_download(). A tar (gzipped or not) is extracted with its top folder stripped,
// and its members are published into the share by mergeIntoDir (pfb_geoip_extract_tar_to_share); a zip of more than one
// member does the same inside target (pfb_stage_publish_dir_merge), which only the CSV row, whose target is the share,
// accepts. A zip of one member is published whole over target. Every member name is checked before
// anything is written (ADR-46). Any other accepted body is renamed over target. On a database row a body, or the
// archive's member of that name, must be a MaxMind DB (owner, #4058).
func (f *Fetcher) publishGeoIP(ctx context.Context, mime, raw, share, target string) Result {
	switch mime {
	case mimeGzip, mimeTar:
		names, ok := tarNames(ctx, mime, raw)
		if r := memberRefused(names, ok); r != nil {
			return *r
		}
		return published(archiveMerge(raw), share, "geoip", filepath.Base(raw), func(dir string) error {
			return checkedDatabases(dir, target, f.extractTarStripped(ctx, mime, raw, dir))
		})
	case mimeZip:
		names, ok := zipNames(raw)
		if ok && len(names) > 1 {
			if r := memberRefused(names, ok); r != nil {
				return *r
			}
			return published(archiveMerge(raw), target, "geoip zip", filepath.Base(raw), func(dir string) error {
				return checkedDatabases(dir, target, f.extractZipStripped(ctx, raw, dir))
			})
		}
		// tar -xOf of the zip: every member's bytes, published whole over target (a directory refuses it).
		staged, err := os.CreateTemp(filepath.Dir(target), ".pfbstage_")
		if err != nil {
			return publishRefused
		}
		werr := extractZipPayload(ctx, raw, &capWriter{w: staged, left: f.ceiling()})
		if cerr := staged.Chmod(0o644); werr == nil {
			werr = cerr
		}
		if cerr := staged.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil && isDatabase(target) && !maxMindDB(staged.Name()) {
			werr = errNotADatabase
		}
		if werr != nil {
			os.Remove(staged.Name())
			return extractRefused("geoip zip", werr, filepath.Base(raw))
		}
		if os.Rename(staged.Name(), target) != nil {
			os.Remove(staged.Name())
			return publishRefused
		}
		return accepted
	}
	if os.Rename(raw, target) != nil {
		return publishRefused
	}
	return accepted
}

// memberRefused is pfb_archive_unsafe_member() as a refusal: an archive that cannot be listed, or its first member name
// that would leave the extraction folder; nil when every name is safe.
func memberRefused(names []string, listed bool) *Result {
	detected := "unlistable-archive"
	if listed {
		if detected = unsafeMember(names); detected == "" {
			return nil
		}
	}
	r := refused("member", "unsafe_member_name", detected)
	return &r
}

// published is a folder publisher (archiveMerge, replaceDir) as a row's outcome: what stopped the extraction of what from
// the archive named detail, else a publication that could not complete.
func published(publish func(string, func(string) error) bool, target, what, detail string,
	extract func(dir string) error) Result {
	var xerr error
	ok := publish(target, func(dir string) error { xerr = extract(dir); return xerr })
	switch {
	case ok:
		return accepted
	case xerr != nil:
		return extractRefused(what, xerr, detail)
	}
	return publishRefused
}

// archiveMerge is mergeIntoDir for the archive downloaded to raw (<download>.raw), named by its download.
func archiveMerge(raw string) func(string, func(string) error) bool {
	archive := strings.TrimSuffix(filepath.Base(raw), ".raw")
	return func(target string, extract func(string) error) bool { return mergeIntoDir(target, archive, extract) }
}

var (
	errUnsafeMember = errors.New("archive member leaves the extraction directory")
	errNotADatabase = errors.New("not a MaxMind DB")
	errNoDatabase   = errors.New("archive holds no database for the row")
)

// rename is os.Rename, a test seam for a publication that fails part-way.
var rename = os.Rename

// unsafeMember is pfb_archive_unsafe_member(): the first name that is absolute, has a ".." component, a component over
// 255 bytes or is over 1024 bytes; "" when there is none.
func unsafeMember(names []string) string {
	for _, n := range names {
		if n == "" {
			continue
		}
		if n[0] == '/' || len(n) > 1024 {
			return n
		}
		for _, c := range strings.Split(n, "/") {
			if c == ".." || len(c) > 255 {
				return n
			}
		}
	}
	return ""
}

// tarNames is `tar -tf`: the member names, or false when the archive cannot be listed.
func tarNames(ctx context.Context, mime, path string) ([]string, bool) {
	var names []string
	err := walkTar(ctx, mime, path, func(h *tar.Header, _ io.Reader) error {
		names = append(names, h.Name)
		return nil
	})
	return names, err == nil
}

// zipNames is `unzip -Z1`: the member names, directories included.
func zipNames(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	zr, err := openZip(f)
	if err != nil {
		return nil, false
	}
	names := make([]string, 0, len(zr.File))
	for _, zf := range zr.File {
		names = append(names, zf.Name)
	}
	return names, true
}

func walkTar(ctx context.Context, mime, path string, each func(*tar.Header, io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var src io.Reader = f
	if mime == mimeGzip || mime == mimeBzip2 {
		if src, err = inflate(ctx, mime, f); err != nil {
			return err
		}
	}
	tr := tar.NewReader(src)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			return err
		}
		if err := each(h, ctxReader{ctx, tr}); err != nil {
			return err
		}
	}
}

// stripped is the member's name with its first component removed (--strip=1; a leading "." is that component, and a run
// of separators after it is skipped, as bsdtar takes it): "" when nothing is left.
func stripped(name string) string {
	_, rest, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(strings.TrimLeft(rest, "/"), "/")
}

func (f *Fetcher) extractTarStripped(ctx context.Context, mime, raw, dir string) error {
	return walkTar(ctx, mime, raw, func(h *tar.Header, r io.Reader) error {
		name := stripped(h.Name)
		if h.Typeflag == tar.TypeLink && path.Clean(stripped(h.Linkname)) == path.Clean(name) {
			return nil // a hard link to its own name (GNU tar's second copy of a file) leaves that file in place
		}
		return f.writeMember(dir, name, h.Typeflag == tar.TypeDir, regularMember(h), r)
	})
}

func (f *Fetcher) extractZipStripped(ctx context.Context, raw, dir string) error {
	file, err := os.Open(raw)
	if err != nil {
		return err
	}
	defer file.Close()
	zr, err := openZip(file)
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		isDir := strings.HasSuffix(zf.Name, "/") || zf.Mode().IsDir()
		var r io.Reader
		var rc io.ReadCloser
		if zf.Mode().IsRegular() && !isDir {
			if rc, err = zf.Open(); err != nil {
				return err
			}
			r = ctxReader{ctx, rc}
		}
		err = f.writeMember(dir, stripped(zf.Name), isDir, r != nil, r)
		if rc != nil {
			rc.Close()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// regularMember tells a tar member that holds a file's bytes. Its type flag decides, never its mode bits, and a type
// tar does not know is a regular file, as POSIX and both tars take it; links, special files, folders, pax global
// headers and GNU dump-folder and volume-label entries are not.
func regularMember(h *tar.Header) bool {
	switch h.Typeflag {
	case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo, tar.TypeXGlobalHeader, 'D', 'V':
		return false
	}
	return true
}

// writeMember writes one stripped member under dir: a directory, or a regular file under the per-file ceiling.
// A link or special member is skipped where tar would create it (owner, plan of #3978): a symbolic link in a published
// folder would read its target as data. A later member replaces the earlier file of its name.
func (f *Fetcher) writeMember(dir, name string, isDir, isReg bool, r io.Reader) error {
	rel := filepath.FromSlash(name)
	if filepath.Clean(rel) == "." { // no name, or the extraction folder itself
		return nil
	}
	// unsafeMember refused such names before extraction; this keeps the write itself inside dir.
	if !filepath.IsLocal(rel) {
		return errUnsafeMember
	}
	p := filepath.Join(dir, rel)
	if isDir {
		if info, err := os.Lstat(p); err == nil && !info.IsDir() {
			if err := removeEarlier(p); err != nil {
				return err
			}
		}
		return os.MkdirAll(p, 0o755)
	}
	// A later member of a name replaces the earlier one, never writing through a hard link it shares; a skipped member
	// drops it too.
	if err := removeEarlier(p); err != nil {
		return err
	}
	if !isReg {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(&capWriter{w: out, left: f.ceiling()}, r)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// extractZipPayload is `tar -xOf` of a zip: every regular member's bytes, in order.
func extractZipPayload(ctx context.Context, raw string, w io.Writer) error {
	file, err := os.Open(raw)
	if err != nil {
		return err
	}
	defer file.Close()
	zr, err := openZip(file)
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		if !zf.Mode().IsRegular() {
			continue
		}
		if err := copyZipMember(ctx, zf, w); err != nil {
			return err
		}
	}
	return nil
}

func copyZipMember(ctx context.Context, zf *zip.File, w io.Writer) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(w, ctxReader{ctx, rc})
	return err
}

// mergeIntoDir publishes an archive's entries into target, the share (#4142). extract fills a generation reached through
// one hidden link per archive, target/.<archive>, which replaceDir swaps in one step, and each entry is a fixed link
// through it (<entry> -> .<archive>/<entry>), so every entry of the archive switches with that one rename and a reader
// never sees two generations of it. An entry that is still a real file, or a link this code did not make, becomes its
// link by one rename; one that a newer generation no longer holds reads as missing. A member named with a leading dot,
// a live directory, a live link to a folder (the country folder among them) or a member directory over a live file
// refuses the whole publication before anything changes. An entry relink that fails after the archive link switched
// reports a failed publication, and the next one finishes the switch.
func mergeIntoDir(target, archive string, extract func(dir string) error) bool {
	if archive == "" || strings.HasPrefix(archive, ".") || strings.Contains(archive, "/") || strings.HasSuffix(archive, ".entry") {
		return false // it would name no link of its own beside the entries, or another archive's lock or temp link
	}
	if info, err := os.Lstat(target); err != nil || !info.IsDir() {
		return false
	}
	hidden := "." + archive
	var names []string
	if !replaceDir(filepath.Join(target, hidden), func(dir string) error {
		if err := extract(dir); err != nil {
			return err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !mergeable(target, e) {
				return errLiveEntry
			}
			names = append(names, e.Name())
		}
		return nil
	}) {
		return false
	}
	tmp := filepath.Join(target, hidden+".entry")
	os.Remove(tmp) // a killed run's
	for _, name := range names {
		live, want := filepath.Join(target, name), hidden+"/"+name
		if to, err := os.Readlink(live); err == nil && to == want {
			continue
		}
		if os.Symlink(want, tmp) != nil || rename(tmp, live) != nil {
			os.Remove(tmp)
			return false
		}
	}
	return true
}

// errLiveEntry is a member that may not replace what stands at its name in the share.
var errLiveEntry = errors.New("member may not replace its live entry")

// mergeable reports whether the staged entry e may take its name in target: not a dot name (which covers the country
// folder's lock .cc.lock and its generations .cc.*), not cc, the country folder's link (#4142), and either nothing
// there, an entry link of this code (entryLink), or, for a member file, a file or a link that names no folder (dangling,
// or to a file). A link to a folder, or one whose target cannot be told, refuses, where PHP's merge replaces any link:
// the country folder is one.
func mergeable(target string, e os.DirEntry) bool {
	if strings.HasPrefix(e.Name(), ".") || e.Name() == "cc" {
		return false
	}
	live := filepath.Join(target, e.Name())
	info, err := os.Lstat(live)
	switch {
	case os.IsNotExist(err):
		return true
	case err != nil || info.IsDir():
		return false
	case info.Mode()&os.ModeSymlink != 0:
		if to, _ := os.Readlink(live); entryLink(target, to, e.Name()) {
			return true
		}
		if to, err := os.Stat(live); err == nil && to.IsDir() || err != nil && !os.IsNotExist(err) {
			return false // a link to a folder (the country folder, or an administrator's), or one that cannot be told
		}
	}
	return !e.IsDir()
}

// entryLink reports whether to, the text of the link at target/name, is an entry link of this code:
// .<archive>/<name>, where target/.<archive> is an archive link to one of its generations.
func entryLink(target, to, name string) bool {
	archive, entry, ok := strings.Cut(to, "/")
	if !ok || entry != name || !strings.HasPrefix(archive, ".") || archive == "." || archive == ".." {
		return false
	}
	link := filepath.Join(target, archive)
	gen, err := os.Readlink(link)
	if err != nil {
		return false
	}
	_, ours := generationOf(link, gen)
	return ours
}

// checkedDatabases refuses an extraction (err already nil) that holds a database file without the MaxMind DB marker, or,
// on a database row (target names a .mmdb), one without that database: the whole publication then stays out of the share
// (owner, #4058).
func checkedDatabases(dir, target string, err error) error {
	if err != nil {
		return err
	}
	if isDatabase(target) {
		if info, err := os.Lstat(filepath.Join(dir, filepath.Base(target))); err != nil || !info.Mode().IsRegular() {
			return errNoDatabase
		}
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && isDatabase(p) && !maxMindDB(p) {
			return errNotADatabase
		}
		return nil
	})
}
