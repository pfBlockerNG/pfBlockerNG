package feedfetch

// The text rules against the tables shared with PHP (tests/php/FeedFetchTextTablesTest.php runs them against
// pfb_text_sanity() and pfb_utf16_sample_to_utf8()): ADR-49's verdicts and the decoding of UTF-16/32 text.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func sharedTable(t *testing.T, name string, rows any) {
	t.Helper()
	raw, err := os.ReadFile("../../../tests/feedfetch/fixtures/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, rows); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheSanityVerdictIsTheSharedTables(t *testing.T) {
	var rows []struct {
		Name    string  `json:"name"`
		Sample  string  `json:"sample_b64"`
		Verdict *string `json:"verdict"`
	}
	sharedTable(t, "text_sanity", &rows)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		want := ""
		if r.Verdict != nil {
			want = *r.Verdict
		}
		if got := textSanity(unb64(t, r.Sample)); got != want {
			t.Errorf("%s: verdict %q, want %q", r.Name, got, want)
		}
	}
}

func TestTheDecodingIsTheSharedTables(t *testing.T) {
	var rows []struct {
		Name string `json:"name"`
		In   string `json:"in_b64"`
		Out  string `json:"out_b64"`
	}
	sharedTable(t, "utf_transcode", &rows)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, r := range rows {
		if got, want := toUTF8(unb64(t, r.In)), unb64(t, r.Out); string(got) != string(want) {
			t.Errorf("%s: decoded %x, want %x", r.Name, got, want)
		}
	}
}

func TestSanityReadsExactly64KiB(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		start        int
		want         string
	}{
		{"address ending at the last sample byte counts", "<html>  \n", 65529, ""},
		{"address completed by the next byte does not count", "<html>   \n", 65530, "html_error_page"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.prefix)
			for len(body)+2 <= tc.start {
				body = append(body, '#', '\n')
			}
			if len(body) != tc.start {
				t.Fatalf("fixture prefix ended at %d, want address at %d", len(body), tc.start)
			}
			body = append(body, []byte("1.2.3.4")...)
			path := t.TempDir() + "/body"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := sane(path); got != tc.want {
				t.Fatalf("sample-boundary verdict %q, want %q", got, tc.want)
			}
		})
	}
}
