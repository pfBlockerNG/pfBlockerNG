package feedstage

import (
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// The names a run stages beside a feed's files. Recover knows each of them: a staged output (stagePrefix), the entries and
// marker of a journal set (see journal), the pre-script's copy "<name>.pre", the DNSBL post-script's copy "<name>.post", the
// IP post-script's restore point "<name>.orig.post", and the temporaries of those copies and of the normalization.
const (
	stagePrefix  = ".pfbstage-"
	backupMark   = ".pfbbackup-"
	absentMark   = ".pfbabsent-"
	commitMark   = ".pfbcommit-"
	restorePoint = ".orig.post"
)

// recoveredSuffixes are the copies and temporaries a KILL can leave behind a feed stem: feedparse's script copies, their
// copyFile temporaries, and NormalizeFile's.
var recoveredSuffixes = []string{".pre", ".post", ".pre.tmp", ".post.tmp", ".orig.post.tmp", ".norm.tmp"}

// parsedSource names the record of the normalized input a feed's published lists stand for, beside them as a digest sidecar.
const parsedSource = ".parsed.src"

type stagedFeedFile struct {
	name, temp string
}

// journal is one set of files a run replaces together, recorded on disk so that Recover can finish it after a KILL. Each
// target that exists is kept as ".<target>.pfbbackup-<id>", whole before it gets that name; each that does not exist is
// recorded as an empty ".<target>.pfbabsent-<id>". The set commits at one operation, the creation of ".pfbcommit-<id>";
// its entries are then removed, the marker last. Without the marker the set rolls back (rollbackSet), with it forward
// (finishSet), whatever point a KILL stopped either at.
type journal struct {
	dir, id   string
	entries   []journalEntry
	committed bool // a commit that failed left its marker: the set is Recover's to finish forward
}

type journalEntry struct {
	target, path string // the file the entry puts back, and the entry
	absent       bool
}

// The file operations of a run and of Recover go through these, so that a test can stop at each one (step "op:<name>").
func rename(from, to string) error { step("op:rename"); return os.Rename(from, to) }
func link(from, to string) error   { step("op:link"); return os.Link(from, to) }
func truncate(path string) error   { step("op:truncate"); return os.Truncate(path, 0) }
func createTemp(dir string) (*os.File, error) {
	step("op:create")
	return os.CreateTemp(dir, stagePrefix)
}
func create(path string) (*os.File, error) {
	step("op:create")
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// fault is a test seam beside step: an error it returns for an operation ("remove", "lstat" or "sync") and its path stands
// for that operation's own error, which no folder a test can build produces. Production never sets it.
var fault = func(op, path string) error { return nil }

func remove(path string) error {
	step("op:remove")
	if err := fault("remove", path); err != nil {
		return err
	}
	return os.Remove(path)
}

func lstat(path string) (fs.FileInfo, error) {
	if err := fault("lstat", path); err != nil {
		return nil, err
	}
	return os.Lstat(path)
}

func syncFile(file *os.File) error {
	if err := fault("sync", file.Name()); err != nil {
		return err
	}
	return file.Sync()
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

// publishStaged renames every staged file over its target in one journal set: all of them, or none.
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
	set, err := snapshotPaths(paths)
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := rename(file.temp, filepath.Join(dir, file.name)); err != nil {
			return errors.Join(err, set.rollback())
		}
	}
	if err := syncDir(dir); err != nil {
		return errors.Join(err, set.rollback())
	}
	if err := set.commit(); err != nil {
		return errors.Join(err, set.rollback())
	}
	return nil
}

func syncDir(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = syncFile(directory)
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

// snapshotPaths opens a journal set over paths, which share one folder. A path in copies is backed up by a copy, never a
// hard link: a writer edits that file in place during the run.
func snapshotPaths(paths []string, copies ...string) (*journal, error) {
	set := &journal{dir: filepath.Dir(paths[0]), id: strconv.FormatUint(rand.Uint64(), 36)}
	for _, target := range paths {
		entry := journalEntry{target: target}
		info, err := os.Lstat(target)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			entry.path, entry.absent = set.entryPath(target, absentMark), true
			err = createEmpty(entry.path)
		case err == nil && !info.Mode().IsRegular():
			err = errors.New("feed artifact is not a regular file")
		case err == nil:
			entry.path = set.entryPath(target, backupMark)
			err = backupFile(target, entry.path, info.Mode().Perm(), !slices.Contains(copies, target))
		}
		if err != nil {
			return nil, errors.Join(err, set.rollback())
		}
		set.entries = append(set.entries, entry)
	}
	// The entries are on disk before any target changes.
	if err := syncDir(set.dir); err != nil {
		return nil, errors.Join(err, set.rollback())
	}
	return set, nil
}

func (s *journal) entryPath(target, mark string) string {
	return filepath.Join(s.dir, "."+filepath.Base(target)+mark+s.id)
}

func createEmpty(path string) error {
	file, err := create(path)
	if err != nil {
		return err
	}
	return file.Close()
}

// backupFile keeps source as backup, so that a rollback can put it back after a KILL. The copy is built under the staged
// prefix, which Recover removes, and gets its backup name only once whole: no incomplete file ever carries one.
func backupFile(source, backup string, mode fs.FileMode, mayLink bool) error {
	staged, err := stagedCopy(source, mode, mayLink)
	if err != nil {
		return err
	}
	defer remove(staged)
	step("backup:" + filepath.Base(source))
	err = link(staged, backup)
	if err != nil && !errors.Is(err, fs.ErrExist) { // a folder without hard links: a rename names the whole copy as well
		err = rename(staged, backup)
	}
	return err
}

// stagedCopy is a whole copy of source under the staged prefix. Writers replace a target by rename, so a hard link keeps
// the old bytes unless mayLink is false; a synced copy is the fallback.
func stagedCopy(source string, mode fs.FileMode, mayLink bool) (string, error) {
	dir := filepath.Dir(source)
	if mayLink {
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
	}
	name, err := stageOutput(dir, func(w io.Writer) error {
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

// keepAbsent makes a rollback remove paths instead of putting their old copies back: an absent record beside the backup,
// which rollbackSet obeys over it. A record that cannot be written leaves the old copy to the rollback, which describes
// the download put back with it.
func (s *journal) keepAbsent(paths ...string) {
	for _, path := range paths {
		entry := journalEntry{target: path, path: s.entryPath(path, absentMark), absent: true}
		if !slices.Contains(s.entries, entry) && createEmpty(entry.path) == nil {
			s.entries = append(s.entries, entry)
		}
	}
}

// rollback rolls the set back, unless a failed commit left its marker: a rollback under a marker would leave a set half
// rolled back that Recover then finishes forward.
func (s *journal) rollback() error {
	if s.committed {
		return nil
	}
	return rollbackSet(s.entries)
}

// commit commits the set: the marker, synced with the folder, then finishSet. An error means the commit is not durable,
// and the run fails, one rule for a marker that cannot be created or synced: the entries stay, the caller calls rollback,
// and the feed fails at publish. With the marker gone again the rollback puts the old files back; a marker that cannot be
// removed leaves the set committed, the rollback a no-op and the new files to Recover, which finishes the set forward.
func (s *journal) commit() error {
	marker := filepath.Join(s.dir, commitMark+s.id)
	file, err := create(marker)
	if err != nil {
		return err
	}
	err = errors.Join(syncFile(file), file.Close())
	if err == nil {
		err = syncDir(s.dir)
	}
	if err != nil {
		if removeErr := removeIfExists(marker); removeErr != nil {
			s.committed = true
			return errors.Join(err, removeErr)
		}
		return err
	}
	_ = finishSet(marker, s.entries) // the commit is durable: what stays is finished by Recover or the feed's next run
	return nil
}

// finishSet removes the entries of a committed set, then its marker: the marker stays while an entry does, so that no
// rollback ever reaches a committed set.
func finishSet(marker string, entries []journalEntry) error {
	var errs []error
	for _, entry := range entries {
		errs = append(errs, removeIfExists(entry.path))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return removeIfExists(marker)
}

// rollbackSet puts back the files of a set that did not commit: each backup is renamed over its target, each target
// recorded absent is removed, and an entry goes only once its file is back, so that a rollback stopped anywhere is finished
// by the next. An absent record beats a backup of the same target, and goes last. The run's restore and Recover share it.
func rollbackSet(entries []journalEntry) error {
	absent := map[string]bool{}
	for _, entry := range entries {
		absent[entry.target] = absent[entry.target] || entry.absent
	}
	var errs []error
	for _, entry := range entries {
		if entry.absent {
			continue
		}
		backup, err := lstat(entry.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // put back already
		}
		if err != nil {
			errs = append(errs, err) // the entry stays for the next rollback
			continue
		}
		target, targetErr := os.Lstat(entry.target)
		// A rename between two links of one file does nothing: such a target holds its backup already.
		if backup.Mode().IsRegular() && !absent[entry.target] && (targetErr != nil || !os.SameFile(backup, target)) {
			errs = append(errs, rename(entry.path, entry.target))
			continue
		}
		errs = append(errs, removeIfExists(entry.path))
	}
	for _, entry := range entries {
		if !entry.absent {
			continue
		}
		err := removeIfExists(entry.target)
		if err == nil {
			err = removeIfExists(entry.path)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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

// journalEntryOf reads the name of an entry of a journal set in dir, and its set's id.
func journalEntryOf(dir, name string) (journalEntry, string, bool) {
	rest, hidden := strings.CutPrefix(name, ".")
	for _, mark := range []string{backupMark, absentMark} {
		target, id, found := strings.Cut(rest, mark)
		stem, _, _ := strings.Cut(target, ".")
		if hidden && found && validFeedWord(stem) && validFeedWord(id) {
			return journalEntry{target: filepath.Join(dir, target), path: filepath.Join(dir, name), absent: mark == absentMark}, id, true
		}
	}
	return journalEntry{}, "", false
}

// finishSets finishes the journal sets in dir, as listed in entries, that hold an entry of the feed stem ("" for every
// set): forward with a commit marker, back without one. A marker names no feed, so with a stem only the markers of sets
// with such an entry are reached; without one, a marker whose entries are all gone is removed too.
func finishSets(dir string, entries []os.DirEntry, stem string) error {
	sets, committed := map[string][]journalEntry{}, map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if id, ok := strings.CutPrefix(name, commitMark); ok && validFeedWord(id) {
			committed[id] = true
		} else if entry, id, ok := journalEntryOf(dir, name); ok {
			if entryStem, _, _ := strings.Cut(filepath.Base(entry.target), "."); stem == "" || entryStem == stem {
				sets[id] = append(sets[id], entry)
			}
		}
	}
	var errs []error
	for id, set := range sets {
		if !committed[id] {
			errs = append(errs, rollbackSet(set))
		}
	}
	for id := range committed {
		if stem == "" || len(sets[id]) > 0 {
			errs = append(errs, finishSet(filepath.Join(dir, commitMark+id), sets[id]))
		}
	}
	return errors.Join(errs...)
}

// finishFeedSets finishes the sets an earlier run of the feed stem left in dir (a rollback or a finishSet that failed),
// as Recover would.
func finishFeedSets(dir, stem string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	return finishSets(dir, entries, stem)
}

// Recover makes the feed folder dir consistent before the next run stages anything (issue #4038, cutover item from #4035):
// a KILL leaves restore points, journal sets and staged files. A regular IP restore point is renamed back over the download
// (a run without a journal set over the download, force parse or reuse, has only that); every journal set with its commit
// marker is finished, every other one rolled back; staged files, script copies and temporaries are removed. A restore point
// that is no regular file is removed, as feedparse's Restore does. Recover stopped anywhere is finished by the next Recover.
// A folder that is a symbolic link is refused, untouched.
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
		name := e.Name()
		if stem, ok := strings.CutSuffix(name, restorePoint); ok && validFeedWord(stem) {
			path := filepath.Join(dir, name)
			if e.Type().IsRegular() {
				errs = append(errs, rename(path, filepath.Join(dir, stem+".orig")))
			} else {
				errs = append(errs, remove(path))
			}
		}
	}
	errs = append(errs, finishSets(dir, entries, ""))
	for _, e := range entries {
		name := e.Name()
		recovered := strings.HasPrefix(name, stagePrefix)
		for _, suffix := range recoveredSuffixes {
			stem, ok := strings.CutSuffix(name, suffix)
			recovered = recovered || ok && validFeedWord(stem)
		}
		if recovered {
			errs = append(errs, removeIfExists(filepath.Join(dir, name)))
		}
	}
	errs = append(errs, syncDir(dir))
	return errors.Join(errs...)
}
