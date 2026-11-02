package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

const (
	maxACLLine  = 4096 // longer lines are skipped: real `access-control:` and `include:` rows are far shorter
	maxACLDepth = 100  // nested includes; a self-including config stops here (Unbound stops at its open-file limit)
	maxACLFiles = 4096 // files read for one config, so that a glob cycle cannot fan out without end
)

// aclFile is a file the rules came from. info is nil when the path was absent or could not be opened for any
// reason but permission, so that failure is retried on the next Refresh.
type aclFile struct {
	path string
	info os.FileInfo
}

// aclGlob is an `include:` pattern and the files it matched. failed is set when a directory the pattern needs could
// not be listed (matches is then empty): the glob stays a dependency, so the ACL reloads once it can be listed.
type aclGlob struct {
	pattern string
	matches []string
	failed  bool
}

// aclDeps is everything a load read: a change to any of it can change the rules.
type aclDeps struct {
	files []aclFile
	globs []aclGlob
}

func (d aclDeps) changed() bool {
	for _, f := range d.files {
		fi, err := os.Stat(f.path)
		if (err != nil) != (f.info == nil) || (err == nil && !sameFile(f.info, fi)) {
			return true
		}
	}
	for _, g := range d.globs {
		if matches, err := globFiles(g.pattern); (err != nil) != g.failed || !slices.Equal(matches, g.matches) {
			return true
		}
	}
	return false
}

// confWalker reads an Unbound config the way Unbound does: line by line, an `include:` read where it stands, so
// that of identical prefixes the row read last wins whichever file it is in.
type confWalker struct {
	rows     map[netip.Prefix]ACLAction
	deps     aclDeps
	opened   int
	implicit []netip.Prefix // netblocks named by an implicit-allow row; allowed after the walk
}

func newConfWalker() *confWalker { return &confWalker{rows: map[netip.Prefix]ACLAction{}} }

// file reads path as a stream (an include can be a DNSBL list of millions of lines). The identity recorded for it
// is taken BEFORE the read: a writer racing the read then changes (mtime, size, mode) against it, so the next
// Refresh reloads instead of trusting a torn read. A permission error keeps the stat taken before Open, so it
// is retried only once that stat changes (a chmod included). An error is one Unbound would not start on either.
func (w *confWalker) file(path string, depth int) error {
	if depth > maxACLDepth {
		return fmt.Errorf("%s: includes nest more than %d deep", path, maxACLDepth)
	}
	if w.opened++; w.opened > maxACLFiles {
		return fmt.Errorf("%s: more than %d files included", path, maxACLFiles)
	}
	before, statErr := os.Stat(path)
	f, err := os.Open(path)
	if err != nil {
		failed := aclFile{path: path}
		if statErr == nil && errors.Is(err, fs.ErrPermission) {
			failed.info = before
		}
		w.deps.files = append(w.deps.files, failed)
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	w.deps.files = append(w.deps.files, aclFile{path: path, info: info})

	r := bufio.NewReaderSize(f, maxACLLine+2) // a longer line comes back as ErrBufferFull and is skipped
	for {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
			if err == nil {
				continue
			}
		}
		// An unterminated tail is ignored: file_put_contents truncates then writes, and a cut-off `refuse_non_local`
		// must never read as `refuse`.
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := w.line(path, depth, bytes.TrimRight(line, "\n")); err != nil {
			return err
		}
	}
}

// line acts on an `access-control:` row and an `include:` (or `include-toplevel:`) directive; keywords start the
// line, as pfSense and Unbound's own tools write them.
func (w *confWalker) line(from string, depth int, raw []byte) error {
	line := bytes.TrimLeft(raw, " \t")
	switch {
	case bytes.HasPrefix(line, []byte("access-control:")):
		if prefix, action, ok := parseACLLine(string(raw)); ok {
			w.rows[prefix] = action
		}
	case bytes.HasPrefix(line, []byte("access-control-")):
		if prefix, ok := parseImplicitRow(string(line)); ok {
			w.implicit = append(w.implicit, prefix)
		}
	case bytes.HasPrefix(line, []byte("include:")), bytes.HasPrefix(line, []byte("include-toplevel:")):
		return w.include(from, depth, string(line))
	}
	return nil
}

// include follows one directive: a quoted or unquoted path (an unquoted one ends at a space, tab or CR, as in Unbound's
// lexer), or a glob (`*`, `?`, `[`) whose matches Unbound reads in sorted order. shortcut: brace and tilde patterns
// fail the load, so the gateway forwards everything; pfSense writes neither.
func (w *confWalker) include(from string, depth int, directive string) error {
	rest := strings.TrimLeft(directive[strings.IndexByte(directive, ':')+1:], " \t")
	target := rest
	if strings.HasPrefix(rest, `"`) {
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return fmt.Errorf("%s: include: unterminated quote in %q", from, directive)
		}
		target = rest[1 : 1+end]
	} else if i := strings.IndexAny(rest, " \t\r"); i >= 0 {
		target = rest[:i]
	}
	switch {
	case target == "":
		return fmt.Errorf("%s: include without a path", from)
	case strings.ContainsAny(target, "{~"):
		return fmt.Errorf("%s: include %q: brace and tilde patterns are not supported", from, target)
	case !strings.ContainsAny(target, "*?["):
		return w.file(target, depth+1)
	}
	pattern := strings.ReplaceAll(target, "[!", "[^") // glob(3) negates with '!'; filepath.Match negates with '^'
	matches, err := globFiles(pattern)
	w.deps.globs = append(w.deps.globs, aclGlob{pattern: pattern, matches: matches, failed: err != nil})
	if err != nil {
		return fmt.Errorf("%s: include %q: %w", from, target, err)
	}
	for _, m := range matches {
		if err := w.file(m, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// allowImplicit gives each implicit-allow netblock that no access-control row names the `allow` Unbound gives it.
func (w *confWalker) allowImplicit() {
	for _, p := range w.implicit {
		if _, listed := w.rows[p]; !listed {
			w.rows[p] = ACLForward
		}
	}
}

// globFiles is filepath.Glob without its leading-dot rule (a wildcard never matches a dot-name the pattern does not
// spell out, as glob(3) does) and without its silence about I/O: a directory it cannot list, whether the pattern spells
// it out or a wildcard names it, fails the walk (issue #3654), where filepath.Glob skips it and the include reads as
// empty. A directory that is not there, is not one, or is a symlink loop matches nothing, as in glob(3): a stray link
// in a directory a `*` names must not fail the include, which would forward the clients its rows deny.
func globFiles(pattern string) ([]string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	dir, file := filepath.Split(pattern)
	switch dir {
	case "":
		dir = "."
	case string(filepath.Separator):
	default:
		dir = dir[:len(dir)-1]
	}
	dirs := []string{dir}
	if strings.ContainsAny(dir, `*?[\`) {
		var err error
		if dirs, err = globFiles(dir); err != nil {
			return nil, err
		}
	}
	var matches []string
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
				continue
			}
			return nil, err
		}
		if !fi.IsDir() {
			continue // a wildcard directory component also names plain files
		}
		names, err := readDirNames(d)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if strings.HasPrefix(n, ".") && !strings.HasPrefix(file, ".") {
				continue
			}
			if ok, _ := filepath.Match(file, n); ok {
				matches = append(matches, filepath.Join(d, n))
			}
		}
	}
	return matches, nil
}

// readDirNames returns the sorted names in dir, and any error listing it.
func readDirNames(dir string) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	slices.Sort(names)
	return names, err
}
