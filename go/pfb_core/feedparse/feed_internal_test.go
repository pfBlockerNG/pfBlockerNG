package feedparse

import (
	"bytes"
	"encoding/hex"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// The NDJSON row the decider reads is what pfb_dnsbl_ndjson_emit_row() writes: json_encode() with JSON_UNESCAPED_SLASHES |
// JSON_UNESCAPED_UNICODE. Each row below is that function's answer (PHP 8.4.27, hex) for a text of one kind of character.
var ndjsonRows = []struct{ name, text, abp, domain string }{
	{"quote", "612262", "5b2261222c22615c2262225d0a", "5b2264222c22615c2262225d0a"},
	{"backslash", "615c62", "5b2261222c22615c5c62225d0a", "5b2264222c22615c5c62225d0a"},
	{"slash", "612f62", "5b2261222c22612f62225d0a", "5b2264222c22612f62225d0a"},
	{"html", "3c613e2627", "5b2261222c223c613e2627225d0a", "5b2264222c223c613e2627225d0a"},
	{"tab", "610962", "5b2261222c22615c7462225d0a", "5b2264222c22615c7462225d0a"},
	{"lf", "610a62", "5b2261222c22615c6e62225d0a", "5b2264222c22615c6e62225d0a"},
	{"cr", "610d62", "5b2261222c22615c7262225d0a", "5b2264222c22615c7262225d0a"},
	{"bs", "610862", "5b2261222c22615c6262225d0a", "5b2264222c22615c6262225d0a"},
	{"ff", "610c62", "5b2261222c22615c6662225d0a", "5b2264222c22615c6662225d0a"},
	{"ctl01", "610162", "5b2261222c22615c753030303162225d0a", "5b2264222c22615c753030303162225d0a"},
	{"ctl1f", "611f62", "5b2261222c22615c753030316662225d0a", "5b2264222c22615c753030316662225d0a"},
	{"nul", "610062", "5b2261222c22615c753030303062225d0a", "5b2264222c22615c753030303062225d0a"},
	{"del", "617f62", "5b2261222c22617f62225d0a", "5b2264222c22617f62225d0a"},
	{"ls", "61e280a862", "5b2261222c22615c753230323862225d0a", "5b2264222c22615c753230323862225d0a"},
	{"ps", "61e280a962", "5b2261222c22615c753230323962225d0a", "5b2264222c22615c753230323962225d0a"},
	{"e-acute", "c3a9", "5b2261222c22c3a9225d0a", "5b2264222c22c3a9225d0a"},
	{"euro", "e282ac", "5b2261222c22e282ac225d0a", "5b2264222c22e282ac225d0a"},
	{"emoji", "f09f9880", "5b2261222c22f09f9880225d0a", "5b2264222c22f09f9880225d0a"},
	{"bom", "efbbbf", "5b2261222c22efbbbf225d0a", "5b2264222c22efbbbf225d0a"},
	{"nbsp", "c2a0", "5b2261222c22c2a0225d0a", "5b2264222c22c2a0225d0a"},
	{"noncharacter", "efbfbf", "5b2261222c22efbfbf225d0a", "5b2264222c22efbfbf225d0a"},
	{"u0080", "c280", "5b2261222c22c280225d0a", "5b2264222c22c280225d0a"},
	{"u007f", "7f", "5b2261222c227f225d0a", "5b2264222c227f225d0a"},
}

func TestAppendRowMatchesJSONEncode(t *testing.T) {
	for _, c := range ndjsonRows {
		text, err := hex.DecodeString(c.text)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []struct {
			abp  bool
			want string
		}{{true, c.abp}, {false, c.domain}} {
			var b bytes.Buffer
			if err := newRowEncoder(&b)(DNSBLRow{ABP: kind.abp, Text: string(text)}); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(b.Bytes()); got != kind.want {
				t.Errorf("%s (abp=%v): row %s, want %s", c.name, kind.abp, got, kind.want)
			}
		}
	}
}

type repeatedByteReader struct {
	value     byte
	remaining  int64
}

func (r *repeatedByteReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := range p[:n] {
		p[i] = r.value
	}
	r.remaining -= int64(n)
	return n, nil
}

func heapGrowth(t *testing.T, run func()) uint64 {
	t.Helper()
	runtime.GC()
	old := debug.SetGCPercent(-1)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	run()
	runtime.ReadMemStats(&after)
	debug.SetGCPercent(old)
	runtime.GC()
	return after.HeapAlloc - before.HeapAlloc
}

func TestFeedLineCeilingSkipsAndBoundsLargeLines(t *testing.T) {
	const (
		largeLineBytes = 256 << 20
		maxHeapGrowth  = 8 << 20
	)
	t.Run("IP", func(t *testing.T) {
		in := io.MultiReader(
			strings.NewReader("1.2.3.4\n"),
			&repeatedByteReader{value: 'x', remaining: largeLineBytes},
			strings.NewReader("\n5.6.7.8\n"),
		)
		var out bytes.Buffer
		var fails []FailRecord
		var got IPFeed
		var err error
		growth := heapGrowth(t, func() {
			got, err = ParseIPFeed(in, IPConfig{VType: "_v4", PFType: "auto", FloorV4: "Disabled", FloorV6: "Disabled"}, "127.1.7.7", NoProbe, &out, Sink{
				Fail: func(rec FailRecord) { fails = append(fails, rec) },
			})
		})
		t.Logf("HeapAlloc growth: %d bytes", growth)
		if err != nil {
			t.Fatalf("ParseIPFeed failed the feed: %v", err)
		}
		if got.Entries != 2 || got.ParseFail != 1 {
			t.Errorf("IP result = %+v, want two entries and one oversized-line parse failure", got)
		}
		if want := "1.2.3.4\n5.6.7.8\n"; out.String() != want {
			t.Errorf("IP output = %q, want both surrounding lines %q", out.String(), want)
		}
		if len(fails) != 1 || fails[0] != (FailRecord{LineNo: 2, Line: "line over 1 MiB", Raw: "line over 1 MiB"}) {
			t.Errorf("IP failures = %+v, want one bounded oversized-line record", fails)
		}
		if growth > maxHeapGrowth {
			t.Errorf("heap grew by %d bytes for one 256 MiB line, want at most %d", growth, maxHeapGrowth)
		}
	})
	t.Run("DNSBL", func(t *testing.T) {
		in := io.MultiReader(
			strings.NewReader("||before.example.com^\n||"),
			&repeatedByteReader{value: 'x', remaining: largeLineBytes},
			strings.NewReader("^\n||after.example.com^\n"),
		)
		var out bytes.Buffer
		var fails []FailRecord
		var got DNSBLFeed
		var err error
		growth := heapGrowth(t, func() {
			got, err = ParseDNSBLFeed(in, DNSBLConfig{Lenient: true}, &out, Sink{
				Fail: func(rec FailRecord) { fails = append(fails, rec) },
			})
		})
		t.Logf("HeapAlloc growth: %d bytes", growth)
		if err != nil {
			t.Fatalf("ParseDNSBLFeed failed the feed: %v", err)
		}
		if got.Rows != 2 {
			t.Errorf("DNSBL rows = %d, want the two lines surrounding the oversized one", got.Rows)
		}
		want := []byte("[\"a\",\"||before.example.com^\"]\n[\"a\",\"||after.example.com^\"]\n")
		if !bytes.Equal(out.Bytes(), want) {
			t.Errorf("DNSBL output = %d bytes, want only the two surrounding rows (%d bytes)", out.Len(), len(want))
		}
		if len(fails) != 1 || fails[0] != (FailRecord{LineNo: 2, Line: "line over 1 MiB", Raw: "line over 1 MiB"}) {
			t.Errorf("DNSBL failures = %+v, want one bounded oversized-line record", fails)
		}
		if growth > maxHeapGrowth {
			t.Errorf("heap grew by %d bytes for one 256 MiB line, want at most %d", growth, maxHeapGrowth)
		}
	})
}
