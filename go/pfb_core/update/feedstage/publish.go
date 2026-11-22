package feedstage

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
)

// A run works in a run folder of its own, "<FeedDir>/.pfbrun-<name>", and reaches the feed folder only through its commit:
// COMMIT, a list of renames and removals written whole under another name and then renamed into place, after which the
// run rolls forward whatever point a KILL stops it at. Without COMMIT the feed folder is untouched and the run folder is
// deleted. The feed folder itself holds nothing else of a run.
const (
	stagePrefix = ".pfbstage-" // a staged output in the run folder
	runPrefix   = ".pfbrun-"
	commitName  = "COMMIT"
)

// parsedSource names the record of the normalized input a feed's published lists stand for, beside them as a digest sidecar.
const parsedSource = ".parsed.src"

// seeded are the suffixes of a feed's published files that a run reads, replaces or removes: each is hard-linked into the
// run folder before the run starts, and every writer a run reaches replaces such a file by a rename or removes it, never
// writes through it. ".fail" is not among them: whois touches it in place.
var seeded = []string{".orig", ".orig.xxhash128", ".orig.md5", ".orig.etag", ".orig.lastmod", ".orig.size", ".raw", ".bk",
	".probe", ".probe.etag", ".probe.lastmod", ".probe.size", ".norm", ".norm.src." + digest.XXH128}

// published are the suffixes of every file a commit publishes, in the order it publishes them: the download with its
// digests and validators first, the lists, and the record of their input last. Any other file a run leaves is never
// published.
var published = append(slices.Clone(seeded), ".fail", ".parsed.ip", ".parsed.ndjson", ".parsed.v4.ip", ".parsed.v6.ip",
	parsedSource+"."+digest.XXH128)

// clearable are the suffixes a commit may remove: the seeded files the run removed, and the fail marker a transfer clears.
var clearable = append(slices.Clone(seeded), ".fail")

// retired are what a failed transfer still publishes: the validators it drops and the probe body it consumes (#2820).
var retired = []string{".orig.etag", ".orig.lastmod", ".orig.size", ".probe", ".probe.etag", ".probe.lastmod", ".probe.size"}

// probeTemporaries are what a KILL inside stage 6's change probe, the one writer in the feed folder besides a commit, can
// leave behind a feed stem: the body before it gets its name, and the validators' temporaries.
var probeTemporaries = []string{".orig.etag.part", ".orig.lastmod.part", ".orig.size.part", ".probe.part",
	".probe.etag.part", ".probe.lastmod.part", ".probe.size.part"}

type stagedFeedFile struct {
	name, temp string
}

// The file operations of a run and of Recover go through these, so that a test can stop at each one (step "op:<name>").
func link(from, to string) error { step("op:link"); return os.Link(from, to) }
func truncate(path string) error { step("op:truncate"); return os.Truncate(path, 0) }
func mkdir(path string) error    { step("op:mkdir"); return os.Mkdir(path, 0o755) }
func createTemp(dir string) (*os.File, error) {
	step("op:create")
	return os.CreateTemp(dir, stagePrefix)
}

// fault is a test seam beside step: an error it returns for an operation ("rename", "create", "remove", "lstat" or "sync")
// and its path (a rename's source) stands for that operation's own error, which no folder a test can build produces.
// Production never sets it.
var fault = func(op, path string) error { return nil }

func rename(from, to string) error {
	step("op:rename")
	if err := fault("rename", from); err != nil {
		return err
	}
	return os.Rename(from, to)
}

func create(path string) (*os.File, error) {
	step("op:create")
	if err := fault("create", path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

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

// baselineExists reports whether the download path is there, a regular file: only its absence is false, and anything else
// that stands there, or an error other than absence, is an error, never taken for a download that is missing.
func baselineExists(path string) (bool, error) {
	info, err := lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	case !info.Mode().IsRegular():
		return false, errors.New("feed download is not a regular file")
	}
	return true, nil
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

// openRun makes the run folder of the feed stem in dir and links into it each published file the run reads (seeded). The
// caller has finished or deleted any earlier run folder of the stem (recoverFeed).
func openRun(dir, stem string) (string, error) {
	run := filepath.Join(dir, runPrefix+stem)
	if err := mkdir(run); err != nil {
		return "", err
	}
	if err := syncDir(dir); err != nil { // the run folder survives a power loss before COMMIT is written in it
		return "", errors.Join(err, discard(run))
	}
	for _, suffix := range seeded {
		from := filepath.Join(dir, stem+suffix)
		info, err := lstat(from)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err == nil && !info.Mode().IsRegular():
			err = errors.New("published feed file is not a regular file")
		case err == nil:
			err = link(from, filepath.Join(run, stem+suffix))
		}
		if err != nil {
			return "", errors.Join(err, discard(run))
		}
	}
	return run, nil
}

// commitOp is one line of COMMIT: "rename <name>" moves the run's file over the published one, "remove <name>" removes a
// published file the run removed.
type commitOp struct {
	verb, name string
}

// commit publishes the files of the run folder run whose suffixes are in suffixes, and removes the published ones the run
// does not hold whose suffixes are in removable. committed reports whether COMMIT was made: without it the feed folder is
// untouched and the caller deletes the run folder; with it an error leaves the run folder for Recover, which finishes it.
func commit(dir, run, stem string, suffixes, removable []string) (committed bool, err error) {
	var removals, renames []commitOp
	for _, suffix := range suffixes {
		name := stem + suffix
		_, err := lstat(filepath.Join(run, name))
		if err == nil {
			renames = append(renames, commitOp{"rename", name})
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		if _, err := lstat(filepath.Join(dir, name)); err == nil && slices.Contains(removable, suffix) {
			removals = append(removals, commitOp{"remove", name})
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	ops := append(removals, renames...)
	if err := checkOps(dir, run, ops); err != nil {
		return false, err
	}
	// The files the commit renames are on disk before COMMIT is.
	var text strings.Builder
	for _, op := range ops {
		if op.verb == "rename" {
			if err := syncPath(filepath.Join(run, op.name)); err != nil {
				return false, err
			}
		}
		text.WriteString(op.verb + " " + op.name + "\n")
	}
	staged := filepath.Join(run, commitName+".tmp")
	file, err := create(staged)
	if err != nil {
		return false, err
	}
	_, err = io.WriteString(file, text.String())
	if err = errors.Join(err, syncFile(file), file.Close()); err == nil {
		err = syncDir(run)
	}
	if err == nil {
		err = rename(staged, filepath.Join(run, commitName))
	}
	if err != nil {
		return false, err
	}
	step("committed") // COMMIT stands: from here the run is committed and rolls forward, whatever fails
	if err := syncDir(run); err != nil {
		return true, err
	}
	return true, finishRun(dir, run, ops)
}

func syncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(syncFile(file), file.Close())
}

// checkOps refuses operations that would publish anything but a regular file, or replace or remove anything but one.
func checkOps(dir, run string, ops []commitOp) error {
	for _, op := range ops {
		paths := []string{filepath.Join(dir, op.name)}
		if op.verb == "rename" {
			paths = append(paths, filepath.Join(run, op.name))
		}
		for _, path := range paths {
			info, err := lstat(path)
			if err == nil && !info.Mode().IsRegular() {
				return errors.New("feed file is not a regular file")
			}
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// finishRun runs the operations of a committed run folder in their order, then deletes the folder. A rename whose source
// is gone was done; one whose source is still the published file (the link the run was seeded with) is skipped, as a
// rename over a link of itself does nothing and leaves its source. Stopped anywhere, it is finished by the next call.
func finishRun(dir, run string, ops []commitOp) error {
	if err := checkOps(dir, run, ops); err != nil {
		return err
	}
	for _, op := range ops {
		target := filepath.Join(dir, op.name)
		if op.verb == "remove" {
			if err := removeIfExists(target); err != nil {
				return err
			}
			continue
		}
		source := filepath.Join(run, op.name)
		info, err := lstat(source)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if current, err := lstat(target); err == nil && os.SameFile(info, current) {
			continue
		}
		if err := rename(source, target); err != nil {
			return err
		}
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return discard(run)
}

// discard deletes the run folder run entry by entry, without following a link. COMMIT goes last, so that a committed
// folder says it is committed for as long as any of its files is left.
func discard(run string) error {
	entries, err := os.ReadDir(run)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, last := range []bool{false, true} {
		for _, e := range entries {
			if (e.Name() == commitName) != last {
				continue
			}
			path := filepath.Join(run, e.Name())
			if e.IsDir() {
				err = discard(path)
			} else {
				err = removeIfExists(path)
			}
			if err != nil {
				return err
			}
		}
	}
	return removeIfExists(run)
}

// readCommit reads the COMMIT of the run folder of the feed stem: ok is false when there is none. Every line must be an
// operation on one of the feed's published names (a removal on a clearable one), each name once; anything else is
// refused, whole.
func readCommit(run, stem string) (ops []commitOp, ok bool, err error) {
	// Opened without following a link or waiting on a FIFO: whatever stands there is checked on the open file.
	file, err := os.OpenFile(filepath.Join(run, commitName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, false, errors.Join(err, errors.New("COMMIT is not a regular file"))
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if line == "" {
			continue
		}
		verb, name, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
		suffix, hasStem := strings.CutPrefix(name, stem)
		allowed := published
		if verb == "remove" {
			allowed = clearable
		}
		if !strings.HasSuffix(line, "\n") || verb != "rename" && verb != "remove" || !hasStem || !slices.Contains(allowed, suffix) ||
			seen[name] {
			return nil, false, errors.New("COMMIT names an operation that is no publication of its feed")
		}
		seen[name] = true
		ops = append(ops, commitOp{verb, name})
	}
	return ops, true, nil
}

// recoverRun finishes the run folder run of the feed stem when it holds COMMIT, and deletes it otherwise.
func recoverRun(dir, run, stem string) error {
	ops, ok, err := readCommit(run, stem)
	if err != nil {
		return err
	}
	if ok {
		return finishRun(dir, run, ops)
	}
	return discard(run)
}

// recoverFeed is Recover for the run folder of one feed stem, which Stage.Run calls before it reads the feed's files.
func recoverFeed(dir, stem string) error {
	run := filepath.Join(dir, runPrefix+stem)
	info, err := lstat(run)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("run folder is not a directory")
	}
	return recoverRun(dir, run, stem)
}

// Recover makes the feed folder dir consistent before the next run reads it (issue #4038, cutover item from #4035): every
// run folder a KILL left is finished when it holds COMMIT and deleted otherwise, and the temporaries of stage 6's probe are
// removed. Recover stopped anywhere is finished by the next Recover. A run folder that is no directory or names no feed, a
// COMMIT that is no regular file or names anything but its feed's published files, and a file it would publish that is no
// regular file are refused, left as they are. A path that is not absolute and clean, or a folder that is a symbolic link,
// is refused, untouched. The caller runs it before stage 6 probes a feed in dir (Stage.Run).
func Recover(dir string) error {
	if !cleanPath(dir) {
		return errors.New("feed folder is not an absolute clean path")
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
		if stem, ok := strings.CutPrefix(name, runPrefix); ok {
			if !validFeedWord(stem) || !e.IsDir() {
				errs = append(errs, errors.New("run folder is no directory of a feed"))
			} else {
				errs = append(errs, recoverRun(dir, filepath.Join(dir, name), stem))
			}
			continue
		}
		for _, suffix := range probeTemporaries {
			if stem, ok := strings.CutSuffix(name, suffix); ok && validFeedWord(stem) {
				errs = append(errs, removeIfExists(filepath.Join(dir, name)))
			}
		}
	}
	errs = append(errs, syncDir(dir))
	return errors.Join(errs...)
}

// publishParsed puts the staged lists of a feed into its run folder under their names, with the record of the input they
// stand for ("" for none): the commit publishes them together, so that no KILL can pair a list with another download.
func publishParsed(feed feedfetch.Feed, files []stagedFeedFile, source string) error {
	record, err := stageOutput(feed.Dir, func(w io.Writer) error {
		_, err := io.WriteString(w, source)
		return err
	})
	if err != nil {
		return err
	}
	for _, file := range append(files, stagedFeedFile{name: feed.Name + parsedSource + "." + digest.XXH128, temp: record}) {
		if err := rename(file.temp, filepath.Join(feed.Dir, file.name)); err != nil {
			return err
		}
	}
	return nil
}
