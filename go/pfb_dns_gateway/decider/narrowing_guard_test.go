// The integer-narrowing guard: CodeQL's go/incorrect-integer-conversion flagged four parse sites in this package tree
// (alerts 87-90). A parsed integer is converted only to a type its parse's bit size fits, and anything wider is
// narrowed only through a helper that bounds it explicitly (intOf); this test keeps every such site in that shape.
package decider

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// intWidths are the integer types a conversion can narrow to, with their width in bits and signedness. int and uint
// count as 32 bits: the gateway also builds for 32-bit targets.
var intWidths = map[string]struct {
	bits   int
	signed bool
}{
	"int8": {8, true}, "int16": {16, true}, "int32": {32, true}, "rune": {32, true}, "int": {32, true}, "int64": {64, true},
	"uint8": {8, false}, "byte": {8, false}, "uint16": {16, false}, "uint32": {32, false}, "uint": {32, false},
	"uint64": {64, false}, "uintptr": {32, false},
}

type parsedInt struct {
	bits   int
	signed bool
}

// unsafeNarrowings lists, as "file:line: message", each conversion of a strconv.ParseInt / ParseUint / Atoi result to an
// integer type that cannot hold every value the parse returns, and each such parse whose bit size is not a constant.
func unsafeNarrowings(fset *token.FileSet, file *ast.File) []string {
	var found []string
	report := func(node ast.Node, format string, args ...any) {
		found = append(found, fmt.Sprintf("%s: %s", fset.Position(node.Pos()), fmt.Sprintf(format, args...)))
	}
	parse := func(call *ast.CallExpr) (parsedInt, bool) {
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return parsedInt{}, false
		}
		if pkg, ok := selector.X.(*ast.Ident); !ok || pkg.Name != "strconv" {
			return parsedInt{}, false
		}
		switch selector.Sel.Name {
		case "Atoi":
			return parsedInt{64, true}, true
		case "ParseInt", "ParseUint":
			signed := selector.Sel.Name == "ParseInt"
			literal, ok := call.Args[2].(*ast.BasicLit)
			bits, err := strconv.Atoi(literalValue(literal, ok))
			if err != nil {
				report(call, "strconv.%s with a bit size that is not a constant", selector.Sel.Name)
				return parsedInt{64, signed}, true
			}
			if bits == 0 {
				bits = 64
			}
			return parsedInt{bits, signed}, true
		}
		return parsedInt{}, false
	}
	ast.Inspect(file, func(node ast.Node) bool {
		body, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		parsed := map[string]parsedInt{} // the variables of this block assigned a parse's result
		ast.Inspect(body, func(inner ast.Node) bool {
			switch n := inner.(type) {
			case *ast.AssignStmt:
				if len(n.Rhs) == 1 && len(n.Lhs) >= 1 {
					if call, ok := n.Rhs[0].(*ast.CallExpr); ok {
						if p, ok := parse(call); ok {
							if name, ok := n.Lhs[0].(*ast.Ident); ok && name.Name != "_" {
								parsed[name.Name] = p
							}
						}
					}
				}
			case *ast.CallExpr:
				target, ok := n.Fun.(*ast.Ident)
				if !ok || len(n.Args) != 1 {
					return true
				}
				width, ok := intWidths[target.Name]
				if !ok {
					return true
				}
				arg, ok := n.Args[0].(*ast.Ident)
				if !ok {
					return true
				}
				p, ok := parsed[arg.Name]
				if !ok {
					return true
				}
				fits := width.signed && (p.signed && p.bits <= width.bits || !p.signed && p.bits < width.bits) ||
					!width.signed && !p.signed && p.bits <= width.bits
				if !fits {
					report(n, "%s(%s) narrows a %d-bit parse; parse at the target's bit size or bound it (intOf)",
						target.Name, arg.Name, p.bits)
				}
			}
			return true
		})
		return false
	})
	return found
}

func literalValue(literal *ast.BasicLit, ok bool) string {
	if !ok || literal.Kind != token.INT {
		return ""
	}
	return literal.Value
}

func TestTheNarrowingGuardFlagsAConversionThatCanWrapAndPassesOneThatCannot(t *testing.T) {
	for _, row := range []struct {
		name, body string
		flagged    bool
	}{
		{"ParseInt 64 to int, CodeQL alert 87's shape", `v, _ := strconv.ParseInt(s, 10, 64); return int(v)`, true},
		{"ParseUint 32 to rune, alert 90's shape", `v, _ := strconv.ParseUint(s, 16, 32); return rune(v)`, true},
		{"ParseInt 32 to int16", `v, _ := strconv.ParseInt(s, 10, 32); return int16(v)`, true},
		{"Atoi to int32", `v, _ := strconv.Atoi(s); return int32(v)`, true},
		{"a signed parse to an unsigned type", `v, _ := strconv.ParseInt(s, 10, 8); return uint8(v)`, true},
		{"a bit size that is not a constant", `v, _ := strconv.ParseUint(s, 16, n); return uint64(v)`, true},
		{"ParseUint 16 to rune", `v, _ := strconv.ParseUint(s, 16, 16); return rune(v)`, false},
		{"ParseUint 16 to int", `v, _ := strconv.ParseUint(s, 16, 16); return int(v)`, false},
		{"ParseInt 32 to int32", `v, _ := strconv.ParseInt(s, 10, 32); return int32(v)`, false},
		{"ParseInt 64 kept as int64", `v, _ := strconv.ParseInt(s, 10, 64); return int64(v)`, false},
	} {
		source := "package p\nimport \"strconv\"\nfunc f(s string, n int) any { " + row.body + " }\n"
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "snippet.go", source, 0)
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		if got := unsafeNarrowings(fset, file); (len(got) > 0) != row.flagged {
			t.Errorf("%s: findings %q, want flagged=%v", row.name, got, row.flagged)
		}
	}
}

func TestNoParsedIntegerIsNarrowedToATypeThatCanWrap(t *testing.T) {
	fset := token.NewFileSet()
	var found []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == "testdata" {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		found = append(found, unsafeNarrowings(fset, file)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(found)
	for _, line := range found {
		t.Error(line)
	}
}

// A \u escape is exactly four hex digits, as Python's json reads it; anything else refuses the document.
func TestAUnicodeEscapeReadsFourHexDigitsAndRefusesAnythingElseAsPythonDoes(t *testing.T) {
	const b = `\`
	for body, want := range map[string]string{
		"uFFFF":               "\uffff",
		"u00e9":               "é",
		"uD83D" + b + "uDE00": "😀",
	} {
		if got, ok := parsePyJSON(`"` + b + body + `"`); !ok || got != want {
			t.Errorf("%q: got (%q, %v), want %q", body, got, ok, want)
		}
	}
	for _, body := range []string{"u+123", "u-123", "u12", "u12g4", "u 123", "u1_23"} {
		if got, ok := parsePyJSON(`"` + b + body + `"`); ok {
			t.Errorf("%q: got %q, want the document refused (json.loads raises JSONDecodeError)", body, got)
		}
	}
}
