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

// The Core boundary (map #3813): Core runs unchanged off pfSense, so its code imports nothing but the standard library, its
// own packages, the golang.org/x modules the feed parser's UTS #46 conversion needs (owner decision, #3906) and the
// pfBlockerNG fork of xxh3 for the xxh128 feed digest the PHP side writes (owner decision, #3925), and
// names no pfSense path. A path reaches Core only as a flag value. Every non-test Go file of the module is read, whatever
// its build constraints, so a file built only for FreeBSD is held to the rule on any host.

const coreModule = "github.com/pfBlockerNG/pfBlockerNG/go/pfb_core"

// The only third-party modules Core may import or require: the golang.org/x ones (x/sys for the fork's CPU detection)
// are pinned in go.mod to the versions of go/pfb_dns_gateway; the fork is vendored by Core itself, at any version.
var allowedModules = []string{"golang.org/x/net", "golang.org/x/sys", "golang.org/x/text", "github.com/pfBlockerNG/xxh3"}

func moduleAllowed(path string) bool {
	for _, m := range allowedModules {
		if path == m || strings.HasPrefix(path, m+"/") {
			return true
		}
	}
	return false
}

// Prefixes of the pfSense host's own trees, and words that only a pfSense-bound value contains (compared lowercased).
var pfSensePathMarks = []string{
	"/usr/local/", "/var/", "/etc/", "/conf/", "/cf/", "/boot/", "/root/", "/tmp/",
	"config.xml", "pfsense", "pfblockerng.inc", "rc.d/",
}

// stringConst is the value of e when it is a string literal or a + of them, and false for anything else.
// shortcut: named constants and fmt.Sprintf results are not folded; upgrade if Core ever builds paths that way.
func stringConst(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(e.Value)
		if err != nil {
			value = e.Value
		}
		return value, true
	case *ast.ParenExpr:
		return stringConst(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		x, okX := stringConst(e.X)
		y, okY := stringConst(e.Y)
		return x + y, okX && okY
	}
	return "", false
}

// namesPfSensePath reports whether value holds a mark or is a pfSense tree itself: a mark without its trailing slash.
func namesPfSensePath(value string) bool {
	lower := strings.ToLower(value)
	for _, mark := range pfSensePathMarks {
		if strings.Contains(lower, mark) || (mark[0] == '/' && lower == strings.TrimSuffix(mark, "/")) {
			return true
		}
	}
	return false
}

// boundaryViolations lists every import outside the standard library, the module and allowedModules, every go.mod
// requirement outside allowedModules, every replace, and every string constant (a literal or a + of literals) naming
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
			if strings.Contains(first, ".") && p != coreModule && !strings.HasPrefix(p, coreModule+"/") && !moduleAllowed(p) {
				violations = append(violations, fset.Position(imp.Pos()).String()+": imports "+p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			value, isConst := stringConst(e)
			if !isConst {
				return true
			}
			if namesPfSensePath(value) {
				violations = append(violations, fset.Position(e.Pos()).String()+": pfSense path literal "+strconv.Quote(value))
			}
			return false // a constant is judged whole, once: never again by its operands
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
	inRequire := false
	for _, line := range strings.Split(string(gomod), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var module string
		switch {
		case inRequire && fields[0] == ")":
			inRequire = false
		case inRequire:
			module = fields[0]
		case fields[0] == "require" && len(fields) > 1 && fields[1] == "(":
			inRequire = true
		case fields[0] == "require" && len(fields) > 1:
			module = fields[1]
		case fields[0] == "replace":
			violations = append(violations, "go.mod: "+strings.TrimSpace(line)+" (Core takes no replaced module)")
		}
		if module != "" && !moduleAllowed(module) {
			violations = append(violations, "go.mod: require "+module+" (Core takes only "+strings.Join(allowedModules, " and ")+")")
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

// The rule on synthetic modules: golang.org/x/net, x/text and x/sys, and the pfBlockerNG xxh3 fork, in imports and in
// go.mod, are the only third-party code Core may take (owner decisions #3906 and #3925: the feed parser's UTS #46
// conversion; the xxh128 digest through the fork); everything else, lookalikes and upstream xxh3 included, still fails.
func TestBoundaryRuleAllowsOnlyTheNamedModules(t *testing.T) {
	const idnImport = "import _ \"golang.org/x/net/idna\"\n"
	cases := []struct {
		name, gomod, src string
		want             string // "" = clean, else a substring of the one expected violation
	}{
		{"stdlib only", "module m\n", "import _ \"strings\"\n", ""},
		{"x/net import and require", "module m\n\nrequire golang.org/x/net v0.56.0\n\nrequire golang.org/x/text v0.44.0 // indirect\n", idnImport, ""},
		{"require block", "module m\n\nrequire (\n\tgolang.org/x/net v0.56.0\n\tgolang.org/x/text v0.44.0 // indirect\n)\n", idnImport, ""},
		{"x/text import", "module m\n", "import _ \"golang.org/x/text/unicode/norm\"\n", ""},
		{"other module required", "module m\n\nrequire github.com/pires/go-proxyproto v0.15.0\n", "", "go.mod: require github.com/pires/go-proxyproto"},
		{"other module in a require block", "module m\n\nrequire (\n\tgolang.org/x/net v0.56.0\n\tgithub.com/pires/go-proxyproto v0.15.0\n)\n", "", "go.mod: require github.com/pires/go-proxyproto"},
		{"x/sys required", "module m\n\nrequire golang.org/x/sys v0.49.0 // indirect\n", "", ""},
		{"x/sys imported", "module m\n", "import _ \"golang.org/x/sys/cpu\"\n", ""},
		{"xxh3 fork import and require", "module m\n\nrequire github.com/pfBlockerNG/xxh3 v1.1.1-pfblockerng.1\n", "import _ \"github.com/pfBlockerNG/xxh3\"\n", ""},
		{"other golang.org/x module required", "module m\n\nrequire golang.org/x/crypto v0.1.0\n", "", "go.mod: require golang.org/x/crypto"},
		{"upstream xxh3 required", "module m\n\nrequire github.com/zeebo/xxh3 v1.0.2\n", "", "go.mod: require github.com/zeebo/xxh3"},
		{"lookalike of the xxh3 fork required", "module m\n\nrequire github.com/pfBlockerNG/xxh3x v1.0.0\n", "", "go.mod: require github.com/pfBlockerNG/xxh3x"},
		{"other module imported", "module m\n", "import _ \"github.com/pires/go-proxyproto\"\n", "imports github.com/pires/go-proxyproto"},
		{"other golang.org/x module imported", "module m\n", "import _ \"golang.org/x/crypto/ssh\"\n", "imports golang.org/x/crypto/ssh"},
		{"upstream xxh3 imported", "module m\n", "import _ \"github.com/zeebo/xxh3\"\n", "imports github.com/zeebo/xxh3"},
		{"lookalike of the xxh3 fork imported", "module m\n", "import _ \"github.com/pfBlockerNG/xxh3x\"\n", "imports github.com/pfBlockerNG/xxh3x"},
		{"lookalike module path", "module m\n", "import _ \"golang.org/x/netx/idna\"\n", "imports golang.org/x/netx/idna"},
		{"replace", "module m\n\nreplace golang.org/x/net => ../net\n", "", "go.mod: replace golang.org/x/net"},
		{"pfSense path", "module m\n", "var _ = \"/usr/local/etc\"\n", "pfSense path literal"},
		{"etc tree named without its trailing slash", "module m\n", "var _ = \"/etc\"\n", "pfSense path literal"},
		{"var tree named without its trailing slash", "module m\n", "var _ = \"/var\"\n", "pfSense path literal"},
		{"usr local tree named without its trailing slash", "module m\n", "var _ = \"/usr/local\"\n", "pfSense path literal"},
		{"pfSense path split by a constant concatenation", "module m\n", "var _ = \"/usr/lo\" + \"cal/etc\"\n", "pfSense path literal"},
		{"pfSense tree split by a three-part concatenation", "module m\n", "var _ = \"/us\" + \"r/lo\" + \"cal\"\n", "pfSense path literal"},
		{"a concatenation whose operand names a tree is one violation", "module m\n", "var _ = \"/etc\" + \"/x\"\n", "pfSense path literal"},
		{"pfSense path split by a parenthesised concatenation", "module m\n", "var _ = (\"/usr/lo\") + \"cal/etc\"\n", "pfSense path literal"},
		{"pfSense tree as a filepath.Join element", "module m\n", "import \"path/filepath\"\n\nvar _ = filepath.Join(\"/etc\", \"x\")\n", "pfSense path literal"},
		{"root alone is no pfSense path", "module m\n", "var _ = \"/\"\n", ""},
		{"the API route prefix is no pfSense path", "module m\n", "var _ = \"/v1/\"\n", ""},
		{"a bare word etc is no pfSense path", "module m\n", "var _ = \"etc\"\n", ""},
		{"a media type is no pfSense path", "module m\n", "var _ = \"application/json\"\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(c.gomod), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n\n"+c.src), 0o600); err != nil {
				t.Fatal(err)
			}
			violations, files := boundaryViolations(t, dir)
			if files != 1 {
				t.Fatalf("read %d files, want 1", files)
			}
			switch {
			case c.want == "" && len(violations) != 0:
				t.Errorf("want no violation, got %q", violations)
			case c.want != "" && (len(violations) != 1 || !strings.Contains(violations[0], c.want)):
				t.Errorf("want one violation containing %q, got %q", c.want, violations)
			}
		})
	}
}
