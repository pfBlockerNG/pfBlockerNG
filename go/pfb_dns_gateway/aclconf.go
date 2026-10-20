package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maxACLLine  = 4096 // longer lines are skipped: real `access-control:` and `include:` rows are far shorter
	maxACLDepth = 100  // nested includes; a self-including config stops here (Unbound stops at its open-file limit)
	maxACLFiles = 4096 // files read for one config, so that a glob cycle cannot fan out without end
)

// aclFile is a file the rules came from; info is nil when it was absent.
type aclFile struct {
	path string
	info os.FileInfo
}

// aclGlob is an `include:` pattern and the files it matched.
type aclGlob struct {
	pattern string
	matches []string
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
		if matches, _ := globFiles(g.pattern); !slices.Equal(matches, g.matches) {
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
// is taken BEFORE the read: a writer racing the read then changes (mtime, size) against it, so the next Refresh
// reloads instead of trusting a torn read. An error is one Unbound would not start on either.
func (w *confWalker) file(path string, depth int) error {
	if depth > maxACLDepth {
		return fmt.Errorf("%s: includes nest more than %d deep", path, maxACLDepth)
	}
	if w.opened++; w.opened > maxACLFiles {
		return fmt.Errorf("%s: more than %d files included", path, maxACLFiles)
	}
	f, err := os.Open(path)
	if err != nil {
		w.deps.files = append(w.deps.files, aclFile{path: path})
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
	if err != nil {
		return fmt.Errorf("%s: include %q: %w", from, target, err)
	}
	w.deps.globs = append(w.deps.globs, aclGlob{pattern: pattern, matches: matches})
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

// globFiles is filepath.Glob without its leading-dot rule: a wildcard never matches a dot-name the pattern does not
// spell out, as glob(3) does.
func globFiles(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	pat := strings.Split(filepath.Clean(pattern), string(filepath.Separator))
	return slices.DeleteFunc(matches, func(m string) bool {
		parts := strings.Split(filepath.Clean(m), string(filepath.Separator))
		if len(parts) != len(pat) {
			return false
		}
		for i, part := range parts {
			if strings.HasPrefix(part, ".") && !strings.HasPrefix(pat[i], ".") {
				return true
			}
		}
		return false
	}), nil
}
