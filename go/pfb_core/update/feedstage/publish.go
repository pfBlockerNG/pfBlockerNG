package feedstage

import (
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// The names a run stages beside a feed's files. Recover knows each of them: a staged output (stagePrefix), a baseline backup
// ("." + target + backupMark + random), the pre-script's copy "<name>.pre", the DNSBL post-script's copy "<name>.post" and
// the IP post-script's restore point "<name>.orig.post".
const (
	stagePrefix  = ".pfbstage-"
	backupMark   = ".pfbbackup-"
	restorePoint = ".orig.post"
)

// parsedSource names the record of the normalized input a feed's published lists stand for, beside them as a digest sidecar.
const parsedSource = ".parsed.src"

type stagedFeedFile struct {
	name, temp string
}

type pathSnapshot struct {
	items []snapshotItem
}

type snapshotItem struct {
	target, backup string
	existed        bool
}

// The file operations of a run and of Recover go through these, so that a test can stop at each one (step "op:<name>").
func rename(from, to string) error { step("op:rename"); return os.Rename(from, to) }
func remove(path string) error     { step("op:remove"); return os.Remove(path) }
func link(from, to string) error   { step("op:link"); return os.Link(from, to) }
func truncate(path string) error   { step("op:truncate"); return os.Truncate(path, 0) }
func createTemp(dir string) (*os.File, error) {
	step("op:create")
	return os.CreateTemp(dir, stagePrefix)
}

func regularExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func removeIfExists(path string) error {
	if err := remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func stageOutput(dir string, write func(io.Writer) error) (string, error) {
	file, err := createTemp(dir)
	if err != nil {
		return "", err
	}
	name := file.Name()
	ok := false
	defer func() {
		if !ok {
			remove(name)
		}
	}()
	if err = write(file); err == nil {
		err = file.Chmod(0o644)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

// publishStaged renames every staged file over its target, or none: a failed rename puts back the targets already replaced.
func publishStaged(dir string, files []stagedFeedFile) error {
	for _, file := range files {
		if filepath.Base(file.name) != file.name || filepath.Dir(file.temp) != dir {
			return errors.New("invalid staged feed file")
		}
		if info, err := os.Lstat(filepath.Join(dir, file.name)); err == nil && !info.Mode().IsRegular() {
			return errors.New("parsed target is not a regular file")
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = filepath.Join(dir, file.name)
	}
	backup, err := snapshotPaths(paths)
	if err != nil {
		return err
	}
	committed := 0
	for i, file := range files {
		if err := rename(file.temp, filepath.Join(dir, file.name)); err != nil {
			return backup.undo(committed, err)
		}
		committed = i + 1
	}
	if err := syncDir(dir); err != nil {
		return backup.undo(committed, err)
	}
	backup.discard()
	return nil
}

func (s *pathSnapshot) undo(committed int, err error) error {
	if restoreErr := s.restoreThrough(committed); restoreErr != nil {
		return errors.Join(err, restoreErr)
	}
	s.discard()
	return err
}

func syncDir(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	if closeErr := directory.Close(); err == nil {
		err = closeErr
	}
	return err
}

func validatorPaths(feed feedfetch.Feed) []string {
	return []string{feedPath(feed, ".orig.etag"), feedPath(feed, ".orig.lastmod"), feedPath(feed, ".orig.size")}
}

func feedStatePaths(feed feedfetch.Feed) []string {
	return append([]string{feedPath(feed, ".orig"), feedPath(feed, ".orig.xxhash128"), feedPath(feed, ".orig.md5")},
		validatorPaths(feed)...)
}

func snapshotPaths(paths []string) (*pathSnapshot, error) {
	backup := &pathSnapshot{items: make([]snapshotItem, 0, len(paths))}
	for _, target := range paths {
		item := snapshotItem{target: target}
		info, err := os.Lstat(target)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			backup.discard()
			return nil, err
		case !info.Mode().IsRegular():
			backup.discard()
			return nil, errors.New("feed artifact is not a regular file")
		default:
			item.existed = true
			item.backup, err = backupFile(target, info.Mode().Perm())
			if err != nil {
				backup.discard()
				return nil, err
			}
		}
		backup.items = append(backup.items, item)
	}
	return backup, nil
}

// backupFile keeps source under a name that says what it backs up, so that Recover can put it back after a KILL. The copy
// is built under the staged prefix, which Recover removes, and gets its backup name only once whole: no incomplete file ever
// carries one.
func backupFile(source string, mode fs.FileMode) (string, error) {
	staged, err := stagedCopy(source, mode)
	if err != nil {
		return "", err
	}
	defer remove(staged)
	step("backup:" + filepath.Base(source))
	for range 100 {
		backup := filepath.Join(filepath.Dir(source), "."+filepath.Base(source)+backupMark+strconv.FormatUint(rand.Uint64(), 36))
		err := link(staged, backup)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil { // a folder without hard links: a rename names the whole copy as well
			if err := rename(staged, backup); err != nil {
				return "", err
			}
		}
		return backup, nil
	}
	return "", errors.New("no free backup name")
}

// stagedCopy is a whole copy of source under the staged prefix. Writers replace a target by rename, so a hard link keeps the
// old bytes; a synced copy is the fallback.
func stagedCopy(source string, mode fs.FileMode) (string, error) {
	dir := filepath.Dir(source)
	file, err := createTemp(dir)
	if err != nil {
		return "", err
	}
	name := file.Name()
	file.Close()
	if remove(name) == nil && link(source, name) == nil {
		return name, nil
	}
	remove(name)
	name, err = stageOutput(dir, func(w io.Writer) error {
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		defer input.Close()
		_, err = io.Copy(w, input)
		return err
	})
	if err == nil {
		if err = os.Chmod(name, mode); err != nil {
			remove(name)
		}
	}
	return name, err
}

func (s *pathSnapshot) restore() error {
	if err := s.restoreThrough(len(s.items)); err != nil {
		return err
	}
	s.discard()
	return nil
}

// keepAbsent makes a restore remove paths instead of putting their old copies back.
func (s *pathSnapshot) keepAbsent(paths ...string) {
	for _, path := range paths {
		for i := range s.items {
			item := &s.items[i]
			if item.target == path {
				item.existed = false
				if item.backup != "" {
					remove(item.backup)
					item.backup = ""
				}
				break
			}
		}
	}
}

func (s *pathSnapshot) restoreThrough(n int) error {
	var first error
	for i := n - 1; i >= 0; i-- {
		item := &s.items[i]
		if item.existed {
			if err := rename(item.backup, item.target); err != nil {
				if first == nil {
					first = err
				}
			} else {
				item.backup = ""
			}
		} else if err := removeIfExists(item.target); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *pathSnapshot) discard() {
	for _, item := range s.items {
		if item.backup != "" {
			remove(item.backup)
		}
	}
}

func sameFileContents(path, want string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("feed source is not a regular file")
	}
	if info.Size() != int64(len(want)) {
		return false, nil
	}
	data, err := os.ReadFile(path)
	return string(data) == want, err
}

// Recover makes the feed folder dir consistent before the next run stages anything (issue #4038, cutover item from #4035):
// a KILL leaves restore points, backups and staged files. A regular IP restore point is renamed back over the download, then
// every backup over its target; the validators of a feed whose files were put back are dropped, so that its next run
// transfers again; staged files and script copies are removed. A restore point that is no regular file is removed, as
// feedparse's Restore does. A folder that is a symbolic link is refused, untouched.
func Recover(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("feed folder is not an absolute path")
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return errors.New("feed folder is not a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if stem, ok := strings.CutSuffix(e.Name(), restorePoint); ok && validFeedWord(stem) {
			path := filepath.Join(dir, e.Name())
			if e.Type().IsRegular() {
				errs = append(errs, rename(path, filepath.Join(dir, stem+".orig")))
			} else {
				errs = append(errs, remove(path))
			}
		}
	}
	restored, putBack := map[string]bool{}, map[string]bool{}
	for _, e := range entries {
		target, _, ok := strings.Cut(strings.TrimPrefix(e.Name(), "."), backupMark)
		stem, _, _ := strings.Cut(target, ".")
		if !ok || !strings.HasPrefix(e.Name(), ".") || !validFeedWord(stem) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if !e.Type().IsRegular() {
			errs = append(errs, remove(path))
			continue
		}
		errs = append(errs, rename(path, filepath.Join(dir, target)))
		restored[target], putBack[stem] = true, true
	}
	for stem := range putBack {
		feed := feedfetch.Feed{Dir: dir, Name: stem}
		for _, path := range validatorPaths(feed) {
			if !restored[filepath.Base(path)] {
				errs = append(errs, removeIfExists(path))
			}
		}
	}
	for _, e := range entries {
		name := e.Name()
		stem, pre := strings.CutSuffix(name, ".pre")
		if !pre {
			stem, _ = strings.CutSuffix(name, ".post")
		}
		if strings.HasPrefix(name, stagePrefix) || stem != name && validFeedWord(stem) {
			errs = append(errs, removeIfExists(filepath.Join(dir, name)))
		}
	}
	errs = append(errs, syncDir(dir))
	return errors.Join(errs...)
}
