package feedparse

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCountContentOversizedLineSemantics(t *testing.T) {
	const limit = 1 << 20
	dir := t.TempDir()
	path := filepath.Join(dir, "feed")
	check := func(name string, input []byte, want int) {
		t.Helper()
		if err := os.WriteFile(path, input, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := CountContent(path); got != want {
			t.Errorf("%s: CountContent = %d, want %d", name, got, want)
		}
	}

	exact := append(bytes.Repeat([]byte{'x'}, limit-1), '\n')
	check("exactly 1 MiB including LF", exact, 1)
	check("1 MiB + 1 content bytes", append(bytes.Repeat([]byte{'x'}, limit), '\n'), 1)
	check("overlong comment", append(append([]byte{'#'}, bytes.Repeat([]byte{'x'}, limit)...), '\n'), 0)
	check("overlong whitespace only", bytes.Repeat([]byte{' '}, limit+1), 0)
	check("comment after reader boundary", append(bytes.Repeat([]byte{' '}, 64<<10+3), append([]byte("//"), bytes.Repeat([]byte{'x'}, limit)... )...), 0)
	check("content after reader boundary", append(bytes.Repeat([]byte{' '}, 64<<10+3), append([]byte{'x'}, bytes.Repeat([]byte{'y'}, limit)... )...), 1)
	check("single slash is content", append(bytes.Repeat([]byte{' '}, limit), '/'), 1)
	check("empty file is not probed", nil, NoProbe)
}
