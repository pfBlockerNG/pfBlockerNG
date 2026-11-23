package ipset

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
)

// Issue #4038, owner decision of 2026-11-23 (question 1): Core writes no placeholder. An empty list stays empty and an empty
// set has no member; the Outpost pads its own mirror. The Core Updater runs the algebra with Placeholder "", which means none.

// WHEN the closing pass runs without a placeholder THEN an empty deny list stays empty and is not named empty; with today's
// placeholder the same list is refilled with it.
func TestClosingWithoutAPlaceholderLeavesAnEmptyListEmpty(t *testing.T) {
	deny := []Feed{{"A_v4", ""}, {"B_v4", "192.0.2.1\n"}, {"C_v6", ""}}
	today := Closing(ClosingIn{Deny: deny, Placeholder: defaultPH})
	if got := today.Lists[0].Lines; !slices.Equal(got, []string{defaultPH}) {
		t.Fatalf("with the placeholder: A_v4 = %q, want %q", got, []string{defaultPH})
	}
	core := Closing(ClosingIn{Deny: deny, Placeholder: ""})
	for i, want := range [][]string{{}, {"192.0.2.1"}, {}} {
		if got := core.Lists[i].Lines; len(got) != len(want) || !slices.Equal(got, want) && len(want) > 0 {
			t.Errorf("without a placeholder: %s = %q, want %q", core.Lists[i].Name, got, want)
		}
	}
	if core.Sanity.Empty != nil {
		t.Errorf("without a placeholder: empty lists = %q, want none", core.Sanity.Empty)
	}
}

// WHEN legacy pMax empties a feed without a placeholder THEN the feed's list stays empty; with today's placeholder it holds
// the placeholder.
func TestPMaxWithoutAPlaceholderLeavesAnEmptiedListEmpty(t *testing.T) {
	deny := []Feed{{"A_v4", "198.51.100.1\n198.51.100.2\n"}, {"B_v4", "198.51.100.3\n"}}
	today := PMax(deny, nil, 2, defaultPH)
	if got := today.Lists[1].Lines; !slices.Equal(got, []string{defaultPH}) {
		t.Fatalf("with the placeholder: B_v4 = %q, want %q", got, []string{defaultPH})
	}
	core := PMax(deny, nil, 2, "")
	if got := core.Lists[0].Lines; !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Errorf("without a placeholder: A_v4 = %q, want the /24", got)
	}
	if got := core.Lists[1].Lines; len(got) != 0 {
		t.Errorf("without a placeholder: B_v4 = %q, want no row", got)
	}
}

// placeholderDepartures is testdata/placeholder_departures.json: each list of the corpus that Core, running without a
// placeholder, writes differently from today, with today's list as old_expect.
const placeholderDeparturesPath = "testdata/placeholder_departures.json"

// WHEN Core runs the corpus cases that write the placeholder today (closing, pmax, pipeline) without a placeholder THEN every
// list is today's, or the departure fixture names it with today's list as old_expect and Core's as expect.
func TestCoreRunsTheCorpusWithoutAPlaceholderAsTheDepartureFixtureSays(t *testing.T) {
	raw, err := os.ReadFile(placeholderDeparturesPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Lists []struct {
			Case, List string
			Old        []string `json:"old_expect"`
			Expect     []string
			Departure  string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	listed := map[string]int{}
	for i, d := range doc.Lists {
		key := d.Case + " " + d.List
		if _, twice := listed[key]; twice || d.Departure == "" {
			t.Errorf("%s: listed twice or without its departure note", key)
		}
		listed[key] = i
	}
	seen := map[string]bool{}
	lists := 0
	check := func(c *corpusCase, list string, want listExp, got []string, ordered bool) {
		lists++
		key := c.ID + " " + list
		i, departs := listed[key]
		seen[key] = departs
		problem := want.problem(got, ordered)
		switch {
		case problem == "" && departs:
			t.Errorf("%s: listed as a departure, but Core writes today's list", key)
		case problem == "":
		case !departs:
			t.Errorf("%s: Core departs from today without a fixture row: %s", key, problem)
		case !slices.Equal(doc.Lists[i].Old, want.lines) || !slices.Equal(doc.Lists[i].Expect, got):
			t.Errorf("%s: today %q, Core %q; the fixture says %q and %q", key, want.lines, got, doc.Lists[i].Old, doc.Lists[i].Expect)
		}
	}
	checkDir := func(c *corpusCase, list string, want dirExp, got map[string][]string, ordered bool) {
		for _, name := range slices.Sorted(func(yield func(string) bool) {
			for k := range want {
				if !yield(k) {
					return
				}
			}
		}) {
			if want[name].digest != nil || want[name].null {
				continue // a digest pins a list too long to name; no such list holds the placeholder
			}
			check(c, list+"/"+name, want[name], got[name], ordered)
		}
	}
	for _, c := range theCorpus(t).Cases {
		switch c.Op {
		case "closing":
			in := closingInput(c.In.(closingIn))
			in.Placeholder = ""
			checkDir(c, "deny", c.Expect.dir("deny"), folder(Closing(in).Lists, ".txt"), false)
		case "pmax":
			in := c.In.(pmaxIn)
			checkDir(c, "deny", c.Expect.dir("deny"), folder(PMax(feeds(in.deny), rowsOf(in.master), in.max, "").Lists, ".txt"), false)
		case "pipeline":
			in := c.In.(pipeIn)
			cfg := PipelineConfig{Settings: Settings{Dup: in.dup, Agg: in.agg, Rep: in.rep, DRep: in.drep, PRep: in.prep, Supp: in.supp,
				Max: in.dmax, DMax: in.dmax, PMax: in.pmax, CC: in.cc, CCWhite: in.ccwhite, CCBlack: in.ccblack, Geo: in.geo.lookup()}, Union: in.union}
			if in.suppV4 != nil {
				s := in.suppV4.String()
				cfg.SuppV4 = &s
			}
			if in.suppV6 != nil {
				s := in.suppV6.String()
				cfg.SuppV6 = &s
			}
			for _, f := range in.feeds {
				cfg.Feeds = append(cfg.Feeds, PipelineFeed{Name: f.name, Alias: f.alias, Text: f.text.String()})
			}
			var passes []struct {
				Canonical dirExp `json:"canonical"`
				Deny      dirExp `json:"deny_final"`
			}
			if err := json.Unmarshal(c.Expect.m["passes"], &passes); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			p := NewPipeline(cfg)
			for i, ps := range in.passes {
				set := map[string]string{}
				for _, s := range ps.set {
					set[s.name] = s.text.String()
				}
				got := p.Pass(ps.changed, set)
				checkDir(c, fmt.Sprintf("passes[%d].canonical", i), passes[i].Canonical, got.Canonical, true)
				checkDir(c, fmt.Sprintf("passes[%d].deny_final", i), passes[i].Deny, folder(got.Deny, ".txt"), false)
			}
		}
	}
	for key := range listed {
		if !seen[key] {
			t.Errorf("%s: the fixture names a list the corpus does not write", key)
		}
	}
	if lists < 100 || len(doc.Lists) == 0 {
		t.Errorf("%d lists checked, %d departures: the corpus did not reach the placeholder", lists, len(doc.Lists))
	}
}
