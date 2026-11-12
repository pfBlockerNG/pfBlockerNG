package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Core boundary (map #3813): Core runs unchanged off pfSense, so its code imports nothing but the standard library and
// its own packages, and names no pfSense path. A path reaches Core only as a flag value. Every non-test Go file of the module
// is read, whatever its build constraints, so a file built only for FreeBSD is held to the rule on any host.

const coreModule = "github.com/pfBlockerNG/pfBlockerNG/go/pfb_core"

// Prefixes of the pfSense host's own trees, and words that only a pfSense-bound value contains (compared lowercased).
var pfSensePathMarks = []string{
	"/usr/local/", "/var/", "/etc/", "/conf/", "/cf/", "/boot/", "/root/", "/tmp/",
	"config.xml", "pfsense", "pfblockerng.inc", "rc.d/",
}

// boundaryViolations lists every import outside the standard library and the module, and every string literal naming
// a pfSense path, of the non-test Go files under root; files counts what was read.
func boundaryViolations(t *testing.T, root string) (violations []string, files int) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(p, "/")
			if strings.Contains(first, ".") && p != coreModule && !strings.HasPrefix(p, coreModule+"/") {
				violations = append(violations, fset.Position(imp.Pos()).String()+": imports "+p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				value = lit.Value
			}
			lower := strings.ToLower(value)
			for _, mark := range pfSensePathMarks {
				if strings.Contains(lower, mark) {
					violations = append(violations, fset.Position(lit.Pos()).String()+": pfSense path literal "+lit.Value)
					break
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("reading the module: %v", err)
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for _, line := range strings.Split(string(gomod), "\n") {
		if word, _, _ := strings.Cut(strings.TrimSpace(line), " "); word == "require" || word == "replace" {
			violations = append(violations, "go.mod: "+strings.TrimSpace(line)+" (Core builds from the standard library alone)")
		}
	}
	return violations, files
}

func TestCoreImportsNothingPfSenseSpecificAndNamesNoPfSensePath(t *testing.T) {
	violations, files := boundaryViolations(t, ".")
	if files == 0 {
		t.Fatal("no Core Go file was read: the boundary test checked nothing")
	}
	for _, v := range violations {
		t.Error(v)
	}
}
