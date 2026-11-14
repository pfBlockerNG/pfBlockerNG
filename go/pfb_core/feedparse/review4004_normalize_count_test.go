package feedparse

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
)

type normalizeCountingOutput struct {
	*os.File
	truncates int
	seeks     int
}

func (out *normalizeCountingOutput) Truncate(size int64) error {
	out.truncates++
	return out.File.Truncate(size)
}

func (out *normalizeCountingOutput) Seek(offset int64, whence int) (int64, error) {
	out.seeks++
	return out.File.Seek(offset, whence)
}

func TestNormalizeStreamSmallTrailingWhitespaceDoesNotTrimFilePerLine(t *testing.T) {
	var input bytes.Buffer
	for i := 0; i < 10_000; i++ {
		fmt.Fprintf(&input, "line-%05d \t\n", i)
	}
	want := Normalize(input.Bytes())

	file, err := os.CreateTemp(t.TempDir(), "normalized-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	out := &normalizeCountingOutput{File: file}
	if err := normalizeStream(bytes.NewReader(input.Bytes()), out); err != nil {
		t.Fatal(err)
	}
	if out.truncates != 0 {
		t.Errorf("Truncate calls = %d, want 0 for tails buffered with the output", out.truncates)
	}
	if out.seeks != 0 {
		t.Errorf("Seek calls = %d, want 0 for tails buffered with the output", out.seeks)
	}
	if _, err := out.File.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(out.File)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("normalized bytes differ: got %d bytes, want %d", len(got), len(want))
	}
}
