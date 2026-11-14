package feedfetch

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type zipMember struct {
	name string
	data []byte
}

func zipMembers(t *testing.T, members ...zipMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, member := range members {
		w, err := zw.Create(member.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func xlsxWithSharedStrings(t *testing.T, shared string) []byte {
	t.Helper()
	book := zipMembers(t, zipMember{"xl/sharedStrings.xml", []byte("<sst><si><t>" + shared + "</t></si></sst>")})
	return zipMembers(t, zipMember{"list.xlsx", book})
}

func xlsxIngest(t *testing.T, body []byte) (*Fetcher, Feed, Request) {
	t.Helper()
	dir, source := t.TempDir(), t.TempDir()
	feed := Feed{Dir: dir, Name: "FEED"}
	if err := os.WriteFile(feed.path(".orig"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(source, "source.zip")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return &Fetcher{Policy: Policy{LocalDirs: []string{source}}}, feed, Request{URL: "file://" + path}
}

func TestXLSXRefusesPastTheDistinctAddressLimit(t *testing.T) {
	previous := maxXLSXAddresses
	maxXLSXAddresses = 2
	t.Cleanup(func() { maxXLSXAddresses = previous })
	f, feed, req := xlsxIngest(t, xlsxWithSharedStrings(t, "192.0.2.1 192.0.2.2 192.0.2.3"))
	res := f.Ingest(context.Background(), feed, req)
	published, err := os.ReadFile(feed.path(".orig"))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Reason != "xlsx_too_many_addresses" || string(published) != "old\n" {
		t.Fatalf("a workbook past the distinct-address cap must refuse with its reason and keep last-known-good: %+v, published %q", res, published)
	}
}

func TestXLSXCountsDuplicateAddressesOnceAtTheLimit(t *testing.T) {
	previous := maxXLSXAddresses
	maxXLSXAddresses = 2
	t.Cleanup(func() { maxXLSXAddresses = previous })
	f, feed, req := xlsxIngest(t, xlsxWithSharedStrings(t, "192.0.2.1 192.0.2.1 192.0.2.2"))
	res := f.Ingest(context.Background(), feed, req)
	published, err := os.ReadFile(feed.path(".orig"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || string(published) != "192.0.2.1\n192.0.2.2\n" {
		t.Fatalf("duplicate addresses must count once at the distinct-address limit: %+v, published %q", res, published)
	}
}

func TestXLSXChoosesTheSmallestWorkbookName(t *testing.T) {
	z := zipMembers(t, zipMember{"xl/sharedStrings.xml", []byte("<sst><si><t>192.0.2.2</t></si></sst>")})
	a := zipMembers(t, zipMember{"xl/sharedStrings.xml", []byte("<sst><si><t>192.0.2.1</t></si></sst>")})
	body := zipMembers(t, zipMember{"z.xlsx", z}, zipMember{"a.xlsx", a})
	f, feed, req := xlsxIngest(t, body)
	res := f.Ingest(context.Background(), feed, req)
	published, err := os.ReadFile(feed.path(".orig"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || string(published) != "192.0.2.1\n" {
		t.Fatalf("the smallest top-level workbook name must win, not archive order: %+v, published %q", res, published)
	}
}

type cancelAtCheckContext struct {
	context.Context
	cancel context.CancelFunc
	at     int
	checks int
}

func (c *cancelAtCheckContext) Err() error {
	c.checks++
	if c.checks >= c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestXLSXCopyAndScanAnswerToTheirContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
		body []byte
	}{
		{"copy", 1, zipMembers(t, zipMember{"list.xlsx", zipMembers(t, zipMember{"xl/workbook.xml", []byte("x")})})},
		{"scan", 2, xlsxWithSharedStrings(t, "no addresses here")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			raw := filepath.Join(dir, "raw.zip")
			if err := os.WriteFile(raw, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			base, cancel := context.WithCancel(context.Background())
			ctx := &cancelAtCheckContext{Context: base, cancel: cancel, at: tc.at}
			defer cancel()
			_, err := (&Fetcher{}).xlsx(ctx, Feed{Dir: dir, Name: "FEED"}, raw)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("xlsx %s must return its context reason: %v (%d checks)", tc.name, err, ctx.checks)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "raw.zip" {
					t.Fatalf("xlsx %s left a staging file after cancellation: %s", tc.name, entry.Name())
				}
			}
		})
	}
}

// The shared strings are decompressed under the per-file ceiling too: a small workbook whose shared strings inflate
// past it is refused with the ceiling's text, not read on.
func TestXLSXSharedStringsPastTheCeilingAreRefused(t *testing.T) {
	shared := bytes.Repeat([]byte("192.0.2.1 "), 8192) // 80 KiB, compresses to well under the ceiling
	f, feed, req := xlsxIngest(t, xlsxWithSharedStrings(t, string(shared)))
	f.extractMax = 16 << 10
	res := f.Ingest(context.Background(), feed, req)
	published, err := os.ReadFile(feed.path(".orig"))
	if err != nil {
		t.Fatal(err)
	}
	want := "xlsx extraction failed (script exit 153) -- output exceeded the extraction size ceiling"
	if res.OK || res.Reason != want || string(published) != "old\n" {
		t.Fatalf("shared strings past the ceiling must be refused (want %q), keeping last-known-good: %+v, published %q", want, res, published)
	}
}
