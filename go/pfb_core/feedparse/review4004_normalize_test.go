package feedparse

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

type reviewReadLimit struct {
	r   io.Reader
	max int
}

func (r reviewReadLimit) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	return r.r.Read(p)
}

func normalizeReviewStream(t *testing.T, out *os.File, input []byte, maxRead int) []byte {
	t.Helper()
	if err := out.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var in io.Reader = bytes.NewReader(input)
	if maxRead > 0 {
		in = reviewReadLimit{r: in, max: maxRead}
	}
	if err := normalizeStream(in, out); err != nil {
		t.Fatal(err)
	}
	info, err := out.Stat()
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, int(info.Size()))
	if len(got) > 0 {
		if _, err := out.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
	}
	return got
}

func utf16ReviewFeed(order binary.ByteOrder, bom []byte, text string) []byte {
	out := append([]byte(nil), bom...)
	for _, unit := range utf16.Encode([]rune(text)) {
		var pair [2]byte
		order.PutUint16(pair[:], unit)
		out = append(out, pair[:]...)
	}
	return out
}

func TestNormalizeStreamMatchesNormalizeCorpus(t *testing.T) {
	ids, inputs, expects := loadNormalizeCorpus(t)
	out, err := os.Create(filepath.Join(t.TempDir(), "feed.norm"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for _, maxRead := range []int{0, 1, 2, 3, 7, 64<<10 - 1} {
		for i, id := range ids {
			want := Normalize(inputs[i])
			if !bytes.Equal(want, expects[i]) {
				t.Fatalf("Normalize disagrees with its frozen corpus for %s", id)
			}
			got := normalizeReviewStream(t, out, inputs[i], maxRead)
			if !bytes.Equal(got, want) {
				t.Errorf("normalizeStream differs for %s with reader chunk %d", id, maxRead)
			}
		}
	}
}

func TestNormalizeStreamNonASCIIAndBoundaryBytes(t *testing.T) {
	bigEndian := utf16ReviewFeed(binary.BigEndian, []byte{0xFE, 0xFF}, strings.Repeat("a", 32766)+"😀 \t\n")
	littleEndian := utf16ReviewFeed(binary.LittleEndian, []byte{0xFF, 0xFE}, strings.Repeat("a", 32766)+"😀 \t\n")
	utf8Boundary := append(bytes.Repeat([]byte{'a'}, 64<<10-1), []byte("€\t \n")...)
	inputs := [][]byte{
		[]byte("1.2.3.4 \x00\nnext.example\n"),
		[]byte("a \u0085\nb \u00a0 \n"),
		{0x80, 0xFF, ' ', 0x01, 'x', ' ', 0x00},
		utf8Boundary,
		bigEndian,
		littleEndian,
		{0xFF, 0xFE, 0x61, 0x00, 0x00, 0xD8, 0xFF},
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "feed.norm"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for i, input := range inputs {
		want := Normalize(input)
		for _, maxRead := range []int{1, 7, 64<<10 - 1} {
			got := normalizeReviewStream(t, out, input, maxRead)
			if !bytes.Equal(got, want) {
				t.Errorf("case %d differs with reader chunk %d: got %x, want %x", i, maxRead, got, want)
			}
		}
	}
}
