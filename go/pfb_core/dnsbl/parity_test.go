package dnsbl_test

// The parity fixture of slice 7a (issue #4036): tests/core/fixtures/dnsbl_resources_parity.json, frozen against today's
// pfb_unbound_python_sources() and the DNSBL widget's group counts by tests/php/DnsblResourcesParityTest.php. This runner
// publishes each case through the assembler and reads the answer back from the store: the manifest's feed rows in
// position order, each with its body, and the manifest metadata's group counts. A staged line is a string, or
// {"b64": bytes} for one that is not UTF-8; "top1m": "missing" turns TOP1M on with no list.

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

type parityFeedOut struct {
	Feed       string   `json:"feed"`
	Group      string   `json:"group"`
	LogFlag    string   `json:"logFlag"`
	Provenance string   `json:"provenance"`
	Mode       string   `json:"mode"`
	Top1m      bool     `json:"top1m"`
	Rows       []string `json:"rows"`
}

type parityGroup struct {
	Name    string `json:"name"`
	Entries int    `json:"entries"`
}

type parityAnswer struct {
	Feeds  []parityFeedOut `json:"feeds,omitempty"`
	Groups []parityGroup   `json:"groups,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// stagedLine is a staged line: a JSON string, or {"b64": bytes}.
type stagedLine string

func (l *stagedLine) UnmarshalJSON(data []byte) error {
	var text string
	if json.Unmarshal(data, &text) == nil {
		*l = stagedLine(text)
		return nil
	}
	var b struct{ B64 []byte }
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	*l = stagedLine(b.B64)
	return nil
}

type parityCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Feeds       []struct {
		Header     string       `json:"header"`
		Group      string       `json:"group"`
		Log        string       `json:"log"`
		Provenance string       `json:"provenance"`
		Mode       string       `json:"mode"`
		Top1m      bool         `json:"top1m"`
		Staged     []stagedLine `json:"staged"`
	} `json:"feeds"`
	Top1m     string         `json:"top1m"`
	Expect    parityAnswer   `json:"expect"`
	OldExpect *parityAnswer  `json:"old_expect"`
	Refused   []string       `json:"refused"`
	Invalid   map[string]int `json:"invalid"`
	Dropped   map[string]int `json:"dropped"`
}

func TestAssemblerMatchesTheParityFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "dnsbl_resources_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      int          `json:"schema"`
		Description string       `json:"description"`
		Cases       []parityCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Schema != 1 || len(doc.Cases) < 10 {
		t.Fatalf("fixture: err %v, schema %d, %d cases", err, doc.Schema, len(doc.Cases))
	}
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.OldExpect != nil && reflect.DeepEqual(*c.OldExpect, c.Expect) {
				t.Fatal("old_expect equals expect: not a departure")
			}
			set := dnsbl.Set{Top1mEnabled: c.Top1m == "missing"}
			invalid := map[string]int{}
			for _, f := range c.Feeds {
				var staged strings.Builder
				for _, line := range f.Staged {
					staged.WriteString(string(line) + "\n")
				}
				rows, bad, err := dnsbl.ReadStaged(strings.NewReader(staged.String()))
				if err != nil {
					t.Fatal(err)
				}
				if bad > 0 {
					invalid[f.Header] = bad
				}
				set.Feeds = append(set.Feeds, dnsbl.Feed{Name: f.Header, Group: f.Group, LogFlag: f.Log, Provenance: f.Provenance, Mode: f.Mode, Top1m: f.Top1m, Rows: rows})
			}
			if !maps.Equal(invalid, c.Invalid) && (len(invalid) > 0 || len(c.Invalid) > 0) {
				t.Errorf("staged rows skipped = %v, want %v", invalid, c.Invalid)
			}

			store := resources.Open(t.TempDir())
			res, err := dnsbl.Publish(store, set)
			var got parityAnswer
			if err != nil {
				got.Error = err.Error()
			} else {
				got.Feeds = parityFeeds(t, store)
				reply, err := store.Get(dnsbl.ManifestID, nil)
				if err != nil {
					t.Fatal(err)
				}
				var meta struct{ Groups []parityGroup }
				if err := json.Unmarshal(reply.Metadata, &meta); err != nil {
					t.Fatal(err)
				}
				got.Groups = meta.Groups
			}
			if !reflect.DeepEqual(got, c.Expect) {
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(c.Expect)
				t.Errorf("answer\n got %s\nwant %s", g, w)
			}
			if !slices.Equal(res.Refused, c.Refused) {
				t.Errorf("Refused = %q, want %q", res.Refused, c.Refused)
			}
			if !maps.Equal(res.Dropped, c.Dropped) && (len(res.Dropped) > 0 || len(c.Dropped) > 0) {
				t.Errorf("Dropped = %v, want %v", res.Dropped, c.Dropped)
			}
		})
	}
}

// parityFeeds reads the manifest's feed rows, in position order, each with its body's lines.
func parityFeeds(t *testing.T, store *resources.Store) []parityFeedOut {
	t.Helper()
	type feedRow struct {
		Kind, Feed, Group, LogFlag, Provenance, Mode, Resource string
		Position                                               int
		Top1m                                                  bool
	}
	var rows []feedRow
	for _, line := range body(t, store, dnsbl.ManifestID) {
		var row feedRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row.Kind == "feed" {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Position < rows[j].Position })
	out := []parityFeedOut{}
	for i, row := range rows {
		if row.Position != i+1 || row.Resource != dnsbl.FeedPrefix+row.Feed {
			t.Errorf("feed row %+v: want position %d and resource %s", row, i+1, dnsbl.FeedPrefix+row.Feed)
		}
		lines := body(t, store, row.Resource)
		if lines == nil {
			lines = []string{}
		}
		out = append(out, parityFeedOut{row.Feed, row.Group, row.LogFlag, row.Provenance, row.Mode, row.Top1m, lines})
	}
	return out
}
