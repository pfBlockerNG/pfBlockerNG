package feedfetch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

func runXLSXReview(t *testing.T, shared string) string {
	t.Helper()
	f, feed, req := xlsxIngest(t, xlsxWithSharedStrings(t, shared))
	raw := strings.TrimPrefix(req.URL, "file://")
	staged, err := f.xlsx(context.Background(), feed, raw)
	if err != nil {
		t.Fatalf("xlsx: %v", err)
	}
	return staged
}

func TestXLSXMergeDeduplicatesAtChunkBoundary(t *testing.T) {
	const unique = 262_144
	previous := maxXLSXAddresses
	maxXLSXAddresses = unique
	t.Cleanup(func() { maxXLSXAddresses = previous })

	var shared strings.Builder
	shared.Grow(unique * 14)
	var wantSize int64
	for i := range unique {
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
		shared.WriteString(ip)
		shared.WriteByte(' ')
		wantSize += int64(len(ip) + 1)
	}
	shared.WriteString("10.0.0.0 ") // duplicate the first chunk's first address in the next chunk
	staged := runXLSXReview(t, shared.String())
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != wantSize {
		t.Errorf("published size = %d, want %d bytes for %d unique addresses", info.Size(), wantSize, unique)
	}
}

func TestXLSXKeepsDistinctPaddedAddressSpelling(t *testing.T) {
	staged := runXLSXReview(t, "1.2.3.04 1.2.3.4")
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("1.2.3.04\n1.2.3.4\n"); !bytes.Equal(got, want) {
		t.Errorf("xlsx output = %q, want both distinct source spellings sorted bytewise", got)
	}
}
