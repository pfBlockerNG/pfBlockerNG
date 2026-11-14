package feedfetch_test

// ET IQRisk and xlsx behaviour the parity corpus cannot pin: a split directory that already holds files, a context that
// ends during the split, and a workbook past a lowered extraction ceiling.

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// etFeed is a seeded feed with an ET split directory and an ET IQRisk source holding csv.
func etFeed(t *testing.T, csv string) (*feedfetch.Fetcher, feedfetch.Feed, feedfetch.Request) {
	t.Helper()
	f, feed, src := seededFeed(t)
	f.ETDir, f.ETMatchFile, f.ETBlock = t.TempDir(), filepath.Join(t.TempDir(), "match.txt"), []string{"ET_Cnc"}
	p := filepath.Join(src, "iprepdata.txt")
	if err := os.WriteFile(p, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, feed, feedfetch.Request{URL: "file://" + p}
}

// A split replaces the ET_* files of the former one (rm -r "${etdir}/ET_"*), and leaves the directory's other files.
func TestAnETSplitReplacesTheFormerSplit(t *testing.T) {
	f, feed, req := etFeed(t, "192.0.2.10,1,127\n")
	for _, name := range []string{"ET_Retired.txt", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(f.ETDir, name), []byte("192.0.2.99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if res := f.Ingest(context.Background(), feed, req); !res.OK || published(t, feed) != "192.0.2.10\n" {
		t.Fatalf("%+v, published %q", res, published(t, feed))
	}
	if _, err := os.Stat(filepath.Join(f.ETDir, "ET_Retired.txt")); !os.IsNotExist(err) {
		t.Fatalf("the former split must go: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.ETDir, "notes.txt")); err != nil {
		t.Fatalf("a file that is no ET_ split must stay: %v", err)
	}
}

// existsCtx is cancelled from the moment a file exists at path.
type existsCtx struct {
	context.Context
	path string
}

func (c existsCtx) Err() error {
	if _, err := os.Stat(c.path); err == nil {
		return context.Canceled
	}
	return nil
}

// The split stops when its context ends, keeping the published copy.
func TestAnETSplitEndsWithItsContext(t *testing.T) {
	f, feed, req := etFeed(t, strings.Repeat("192.0.2.10,1,127\n", 1<<16))
	ctx := existsCtx{context.Background(), filepath.Join(f.ETDir, "ET_Cnc.txt")}
	if res := f.Ingest(ctx, feed, req); res.OK || res.Reason != context.Canceled.Error() || published(t, feed) != oldCopy {
		t.Fatalf("a split must end with its context: %+v, published %q", res, published(t, feed))
	}
}

// A workbook is extracted under the per-file ceiling, as tar -xf writes it: one past it is refused with the ceiling's
// status, keeping the published copy.
func TestAWorkbookPastTheCeilingIsRefused(t *testing.T) {
	zipOfMembers := func(members map[string][]byte) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		for name, data := range members {
			w, err := zw.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	book := zipOfMembers(map[string][]byte{"xl/sharedStrings.xml": []byte("<sst><si><t>192.0.2.1</t></si></sst>")})
	f, feed, src := seededFeed(t)
	f.SetExtractMax(int64(len(book)) - 1)
	res := f.Ingest(context.Background(), feed, localRequest(t, src, zipOfMembers(map[string][]byte{"list.xlsx": book})))
	if want := "xlsx extraction failed (script exit 153) -- output exceeded the extraction size ceiling"; res.OK || res.Reason != want || published(t, feed) != oldCopy {
		t.Fatalf("a workbook one byte past the ceiling must be refused: %+v (want %q), published %q", res, want, published(t, feed))
	}
	f.SetExtractMax(int64(len(book)))
	if res := f.Ingest(context.Background(), feed, localRequest(t, src, zipOfMembers(map[string][]byte{"list.xlsx": book}))); !res.OK || published(t, feed) != "192.0.2.1\n" {
		t.Fatalf("a workbook of exactly the ceiling must be read: %+v, published %q", res, published(t, feed))
	}
}
