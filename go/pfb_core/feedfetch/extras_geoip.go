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

// publishGeoIP is the geoip branch of pfb_download(). A tar (gzipped or not) is extracted with its top folder stripped
// into a directory staged inside the share, and each member then replaces its live copy (pfb_geoip_extract_tar_to_share);
// a zip of more than one member does the same inside target (pfb_stage_publish_dir_merge), which only the CSV row, whose
// target is the share, accepts. A zip of one member is published whole over target. Every member name is checked before
// anything is written (ADR-46). Any other accepted body is renamed over target. On a database row a body, or the
// archive's member of that name, must be a MaxMind DB (owner, #4058).
func (f *Fetcher) publishGeoIP(ctx context.Context, mime, raw, share, target string) Result {
	switch mime {
	case mimeGzip, mimeTar:
		names, ok := tarNames(ctx, mime, raw)
		if r := memberRefused(names, ok); r != nil {
			return *r
		}
		return f.merged(share, func(dir string) error {
			return checkedDatabases(dir, target, f.extractTarStripped(ctx, mime, raw, dir))
		})
	case mimeZip:
		names, ok := zipNames(raw)
		if ok && len(names) > 1 {
			if r := memberRefused(names, ok); r != nil {
				return *r
			}
			return f.merged(target, func(dir string) error {
				return checkedDatabases(dir, target, f.extractZipStripped(ctx, raw, dir))
			})
		}
		// tar -xOf of the zip: every member's bytes, published whole over target (a directory refuses it).
		staged, err := os.CreateTemp(filepath.Dir(target), ".pfbstage_")
		if err != nil {
			return refused("publish", err.Error(), "")
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
			return refused("extract", werr.Error(), filepath.Base(raw))
		}
		if err := os.Rename(staged.Name(), target); err != nil {
			os.Remove(staged.Name())
			return refused("publish", err.Error(), "")
		}
		return accepted
	}
	if err := os.Rename(raw, target); err != nil {
		return refused("publish", err.Error(), "")
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

// merged is mergeIntoDir as a row's outcome: what stopped the extraction, else a publication that could not complete.
func (f *Fetcher) merged(target string, extract func(dir string) error) Result {
	var xerr error
	if f.mergeIntoDir(target, func(dir string) error { xerr = extract(dir); return xerr }) {
		return accepted
	}
	if xerr != nil {
		return refused("extract", xerr.Error(), "")
	}
	return refused("publish", "the extraction could not be published", "")
}

var (
	errUnsafeMember = errors.New("archive member leaves the extraction directory")
	errNotADatabase = errors.New("not a MaxMind DB")
	errNoDatabase   = errors.New("archive holds no database for the row")
)

// rename is os.Rename, a test seam for a publication that fails part-way.
var rename = os.Rename

// link is os.Link, a test seam for link(2) as FreeBSD has it.
var link = os.Link

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

// mergeIntoDir is pfb_stage_publish_dir_merge(): extract fills a directory staged inside target, and each of its
// top-level entries then replaces its live counterpart by rename. A directory on either side (a live one, or a staged one
// whose name is taken) refuses the whole publication before the first move. Every live file it replaces is hard-linked
// aside first, so a rename that fails part-way puts the earlier ones back: the share holds one generation, never a mix
// (PHP leaves the mix). A file that cannot be put back keeps its copy in the ".pfbbackup_" directory. Each swap is one
// rename, so a reader that opens several of the files while a merge runs can still see both generations, as in PHP.
func (f *Fetcher) mergeIntoDir(target string, extract func(dir string) error) bool {
	if info, err := os.Lstat(target); err != nil || !info.IsDir() {
		return false
	}
	staged, err := os.MkdirTemp(target, ".pfbstagedir_")
	if err != nil {
		return false
	}
	defer os.RemoveAll(staged)
	if os.Chmod(staged, 0o755) != nil || extract(staged) != nil {
		return false
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		return false
	}
	for _, e := range entries {
		live := filepath.Join(target, e.Name())
		info, err := os.Lstat(live)
		if err == nil && (info.IsDir() || e.IsDir()) {
			return false
		}
	}
	backup, err := os.MkdirTemp(target, ".pfbbackup_")
	if err != nil {
		return false
	}
	keepBackup := false // a rollback that could not put a file back leaves its copy here
	defer func() {
		if !keepBackup {
			os.RemoveAll(backup)
		}
	}()
	kept := map[string]bool{}
	for _, e := range entries {
		live := filepath.Join(target, e.Name())
		if _, err := os.Lstat(live); err == nil {
			if backupEntry(live, filepath.Join(backup, e.Name())) != nil {
				return false
			}
			kept[e.Name()] = true
		}
	}
	for i, e := range entries {
		if rename(filepath.Join(staged, e.Name()), filepath.Join(target, e.Name())) != nil {
			for _, done := range entries[:i] {
				live := filepath.Join(target, done.Name())
				if kept[done.Name()] {
					if rename(filepath.Join(backup, done.Name()), live) != nil {
						keepBackup = true
					}
				} else {
					os.RemoveAll(live)
				}
			}
			return false
		}
	}
	return true
}

// backupEntry keeps a live entry aside by a hard link, and a symbolic link as the link it is: FreeBSD's link(2) follows
// one, which fails for a dangling link and turns a restored link into a copy of its target.
func backupEntry(live, backup string) error {
	if info, err := os.Lstat(live); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		to, err := os.Readlink(live)
		if err != nil {
			return err
		}
		return os.Symlink(to, backup)
	}
	return link(live, backup)
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
