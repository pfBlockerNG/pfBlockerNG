package feedstage

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// corpusFile is the whole-feed corpus shared with today's per-feed blocks of sync_package_pfblockerng(), replayed there by
// tests/php/UpdateLoopFeedStageCorpusTest.php. Where Core differs on purpose a case keeps today's answer in old_expect and
// says why in departure; this runner asserts expect.
const corpusFile = "../../../../tests/updateloop/fixtures/feedstage/scenarios.json"

type corpusExpect struct {
	Outcome     string   `json:"outcome"`
	Stage       string   `json:"stage"`
	PostFailed  bool     `json:"postFailed"`
	Entries     []string `json:"entries"`
	Placeholder string   `json:"placeholder"`
	Orig        string   `json:"orig"`
}

type corpusCase struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Custom      bool            `json:"custom"`
	State       string          `json:"state"`      // hold, or absent: enabled
	DropList    bool            `json:"dropList"`   // the published list is removed after the baseline pass
	Unresolved  string          `json:"unresolved"` // pre or post: that script is set but is no file in the folder
	Baseline    *string         `json:"baseline"`
	Source      *string         `json:"source"`
	Pre         *string         `json:"pre"`
	Post        *string         `json:"post"`
	Expect      corpusExpect    `json:"expect"`
	OldExpect   json.RawMessage `json:"old_expect"`
	Departure   string          `json:"departure"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema      int          `json:"schema"`
		Placeholder string       `json:"placeholder"`
		Cases       []corpusCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Schema != 1 || len(doc.Cases) == 0 {
		t.Fatalf("scenarios.json: schema 1 and a case list, strictly (%v)", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if c.ID == "" || c.Description == "" || seen[c.ID] || (c.Kind != "ipv4" && c.Kind != "dnsbl") ||
			(len(c.OldExpect) != 0) != (c.Departure != "") || c.Expect.Entries == nil || (c.State != "" && c.State != "hold") ||
			(c.Unresolved != "" && c.Unresolved != "pre" && c.Unresolved != "post") {
			t.Fatalf("case %q: a unique id, a description, kind ipv4 or dnsbl, entries, old_expect only with a departure, "+
				"state hold and unresolved pre or post when present", c.ID)
		}
		seen[c.ID] = true
	}
	return doc.Cases
}

// logical is what a run leaves, in the corpus's words: the outcome, the failing stage, whether the post-script failed, the
// list standing after the run (IP entries, or DNSBL row payloads), the placeholder outcome and the download.
func logical(t *testing.T, dir string, kind, name string, r Result) corpusExpect {
	t.Helper()
	outcome := map[string]string{"changed": "updated", "reparsed": "updated"}[r.Disposition]
	if outcome == "" {
		outcome = r.Disposition
	}
	stage := ""
	if r.Disposition == "failed" {
		stage = map[string]string{"probe": "transfer", "fetch": "transfer", "script": "pre-script"}[r.Stage]
		if stage == "" {
			stage = r.Stage
		}
	}
	orig := filepath.Join(dir, name+".orig")
	if info, err := os.Lstat(orig); err == nil && !info.Mode().IsRegular() {
		t.Fatalf("the download %s is left a %v, never a regular file", orig, info.Mode().Type())
	}
	got := corpusExpect{Outcome: outcome, Stage: stage, PostFailed: r.PostScriptFailed, Entries: []string{},
		Placeholder: r.Placeholder}
	if data, err := os.ReadFile(orig); err == nil {
		got.Orig = string(data)
	}
	list := filepath.Join(dir, name+".parsed.ip")
	if kind == "dnsbl" {
		list = filepath.Join(dir, name+".parsed.ndjson")
	}
	data, _ := os.ReadFile(list)
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if kind == "dnsbl" {
			var row []string
			if err := json.Unmarshal([]byte(line), &row); err != nil || len(row) != 2 {
				t.Fatalf("%s: row %q is no [kind, payload] pair", filepath.Base(list), line)
			}
			line = row[1]
		}
		got.Entries = append(got.Entries, line)
	}
	return got
}

// TestCorpusMatchesTodaysFeedBlock runs each case as the PHP runner does: a baseline pass with the baseline source and no
// script, then the case's pass with its source (absent: the transfer fails) and scripts.
func TestCorpusMatchesTodaysFeedBlock(t *testing.T) {
	for _, c := range loadCorpus(t) {
		t.Run(c.ID, func(t *testing.T) {
			root := t.TempDir()
			feedDir, sourceDir, scriptDir := filepath.Join(root, "orig"), filepath.Join(root, "db"), filepath.Join(root, "scripts")
			for _, d := range []string{feedDir, sourceDir, scriptDir} {
				if err := os.Mkdir(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			stage := &Stage{
				Paths:   Paths{FeedDir: feedDir, ScriptDirs: []string{scriptDir}},
				Fetcher: &feedfetch.Fetcher{Policy: feedfetch.Policy{LocalDirs: []string{sourceDir}}},
			}
			source := filepath.Join(sourceDir, "feed.txt")
			feed := Feed{ID: c.Kind + ":Feed", Kind: c.Kind, Name: "Feed", State: "enabled", Format: "auto", Source: "file://" + source}
			if c.State != "" {
				feed.State = c.State
			}
			if c.Kind == "ipv4" {
				feed.ID, feed.Name = "ipv4:Feed_v4", "Feed_v4"
			}
			if c.Baseline != nil {
				writeFile(t, source, *c.Baseline)
				if r := run(stage, feed, "none"); r.Disposition != "changed" {
					t.Fatalf("the baseline pass = %+v, want changed", r)
				}
			}
			if c.DropList {
				for _, suffix := range []string{".parsed.ip", ".parsed.ndjson", ".parsed.v4.ip", ".parsed.v6.ip"} {
					os.Remove(filepath.Join(feedDir, feed.Name+suffix))
				}
			}
			os.Remove(source)
			if c.Custom {
				feed.Custom, feed.CustomText, feed.Source = true, *c.Source, ""
			} else if c.Source != nil {
				writeFile(t, source, *c.Source)
			}
			for name, body := range map[string]*string{"pre.sh": c.Pre, "post.sh": c.Post} {
				if body == nil && c.Unresolved+".sh" != name {
					continue
				}
				if body != nil {
					if err := os.WriteFile(filepath.Join(scriptDir, name), []byte("#!/bin/sh\n"+*body+"\n"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				if name == "pre.sh" {
					feed.PreScript = name
				} else {
					feed.PostScript = name
				}
			}
			r := run(stage, feed, "none")
			if got := logical(t, feedDir, c.Kind, feed.Name, r); !reflect.DeepEqual(got, c.Expect) {
				t.Fatalf("%s\n got  %+v\n want %+v\n result %+v", c.Description, got, c.Expect, r)
			}
		})
	}
}
