package feedfetch_test

import (
	"os"
	"path/filepath"
	"testing"
)

// The corpus runner never holds a published copy over 1 MiB (#3989): a raised ceiling once published a 2 GiB
// extraction, and reading it back whole for the comparison and its failure message OOMed the host. A larger file
// still compares unequal to a different one.
func TestReadOrNilStaysBoundedAndDistinguishesLargeFiles(t *testing.T) {
	const limit = 1 << 20
	dir := t.TempDir()
	write := func(name string, size int64, last byte) string {
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt([]byte{last}, size-1); err != nil { // sparse: no disk or memory spent on the hole
			t.Fatal(err)
		}
		return p
	}

	over := int64(limit + 4<<20)
	a, b := readOrNil(write("a", over, 'a')), readOrNil(write("b", over, 'b'))
	for _, v := range []any{a, b} {
		if s, ok := v.(string); !ok || len(s) > limit {
			t.Fatalf("a %d-byte file reads back as %T of %d bytes; want a string of at most %d", over, v, len(s), limit)
		}
	}
	if a == b {
		t.Fatalf("two different %d-byte files read back equal: %q", over, a)
	}

	if got := readOrNil(write("at-cap", limit, 'z')); got != string(make([]byte, limit-1))+"z" {
		t.Fatalf("a file of exactly %d bytes must read back verbatim", limit)
	}
	if got := readOrNil(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("a missing file reads back as %q; want nil", got)
	}
}
