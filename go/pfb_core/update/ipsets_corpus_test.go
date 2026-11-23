package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// The publication rows of #4038: each pipeline case of the ipset corpus (go/pfb_core/ipset/testdata/ipset.json), run
// pass by pass through the IP sets stage over files, publishes per group and family the mirror today's pass writes
// (/var/db/aliastables, the corpus's canonical set) and per selected class the Uber aggregate, or, where the member
// fixture (tests/core/fixtures/ip_members.json, ipset_departures) names the list, the body it gives as expect, today's
// mirror being its old_expect (one spelling per network and the address guard).

const ipsetCorpusPath = "../ipset/testdata/ipset.json"

type corpusPipeline struct {
	ID    string `json:"id"`
	Input struct {
		Switches struct {
			Dup, Agg, Rep, DRep, PRep, Supp bool
			DMax, PMax                      int64
			CC, CCWhite, CCBlack            string
			Geo                             map[string]string
		}
		Feeds  []struct{ Name, Alias, Text string }
		Passes []struct {
			Changed []string
			Set     map[string]struct{ Text string }
		}
		Suppression map[string]struct{ Text string }
		AggTypes    []string `json:"agg_types"`
	}
	Expect struct {
		Passes []struct {
			Canonical map[string][]string
			Aggregate json.RawMessage
		}
	}
}

func groupsOf(feeds []struct{ Name, Alias, Text string }, family string) []any {
	var groups []any
	for _, f := range feeds {
		header, ok := strings.CutSuffix(f.Name, "_"+short(family))
		if !ok {
			continue
		}
		row := map[string]any{"header": header, "state": "enabled", "url": "https://example.org/" + f.Name}
		if n := len(groups); n > 0 && groups[n-1].(map[string]any)["name"] == f.Alias {
			g := groups[n-1].(map[string]any)
			g["feeds"] = append(g["feeds"].([]any), row)
			continue
		}
		groups = append(groups, map[string]any{"name": f.Alias, "action": "Deny_Both", "listClass": "deny", "feeds": []any{row}})
	}
	return groups
}

func cidrs(text string) []any {
	var out []any
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if l != "" {
			out = append(out, map[string]any{"cidr": l})
		}
	}
	return out
}

// body is the published body of id, its members in order.
func body(t *testing.T, s *resources.Store, id string) []string {
	t.Helper()
	r, err := s.Get(id, nil)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	f, _, err := s.Body(id, r.Generation, resources.PartMembers, 0)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	defer f.Close()
	b := make([]byte, 0, 1024)
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	if len(b) == 0 {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// ipTree is an IPSets over temporary folders, with its feed folder.
func ipTree(t *testing.T) IPSets {
	t.Helper()
	root := t.TempDir()
	s := IPSets{FeedDirs: map[string]string{}, Folders: map[string]string{}, StateDir: filepath.Join(root, "state"),
		Store: resources.Open(filepath.Join(root, "store"))}
	for _, d := range []string{"feeds", "deny", "permit", "match", "native", "state", "store"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s.FeedDirs["ipv4"], s.FeedDirs["ipv6"] = filepath.Join(root, "feeds"), filepath.Join(root, "feeds")
	for _, c := range classes {
		s.Folders[c] = filepath.Join(root, c)
	}
	return s
}

// WHEN every pipeline case of the ipset corpus runs through the IP sets stage, pass by pass THEN each group's published
// body is today's mirror or the member fixture's expect, and so is each selected Uber aggregate.
func TestTheIPSetsPublishTheMirrorTodaysPassWrites(t *testing.T) {
	raw, err := os.ReadFile(ipsetCorpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []json.RawMessage }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("../../../tests/core/fixtures/ip_members.json")
	if err != nil {
		t.Fatal(err)
	}
	var members struct {
		Departures []struct {
			Case, List string
			Expect     []string
		} `json:"ipset_departures"`
	}
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	departs := map[string][]string{}
	for _, d := range members.Departures {
		departs[d.Case+" "+d.List] = d.Expect
	}
	cases, bodies, departures := 0, 0, 0
	for _, rc := range corpus.Cases {
		var op struct{ Op string }
		if err := json.Unmarshal(rc, &op); err != nil || op.Op != "pipeline" {
			continue
		}
		var c corpusPipeline
		if err := json.Unmarshal(rc, &c); err != nil {
			t.Fatal(err)
		}
		cases++
		sw := c.Input.Switches
		policy := map[string]any{"dedup": sw.Dup, "aggregate": sw.Agg, "max": sw.Rep, "dMax": sw.DRep, "pMax": sw.PRep,
			"maxLimit": sw.DMax, "dMaxLimit": sw.DMax, "pMaxLimit": sw.PMax, "countryWhitelistAction": sw.CCWhite, "countryBlacklistAction": sw.CCBlack,
			"countryWhitelist": []any{map[string]any{"code": sw.CC}}, "suppressionV4": cidrs(c.Input.Suppression["v4"].Text),
			"suppressionV6": cidrs(c.Input.Suppression["v6"].Text)}
		settings := map[string]map[string]any{"policy/ip": policy, "ingest": {"suppression": sw.Supp},
			"feeds/ipv4": {"groups": groupsOf(c.Input.Feeds, "ipv4")}, "feeds/ipv6": {"groups": groupsOf(c.Input.Feeds, "ipv6")}}
		s := ipTree(t)
		if sw.Geo != nil {
			s.Geo = func(octets string) string { return sw.Geo[octets] }
		}
		var aggregates []any
		for _, a := range c.Input.AggTypes {
			aggregates = append(aggregates, map[string]any{"class": strings.ToLower(a)})
		}
		policy["aggregates"] = aggregates
		texts := map[string]string{}
		for _, f := range c.Input.Feeds {
			texts[f.Name] = f.Text
		}
		for i, ps := range c.Input.Passes {
			for name, v := range ps.Set {
				texts[name] = v.Text
			}
			changed := map[string]bool{}
			for _, name := range ps.Changed {
				changed[name] = true
			}
			for name, text := range texts {
				if err := os.WriteFile(filepath.Join(s.FeedDirs["ipv4"], name+".parsed.ip"), []byte(text), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Build(context.Background(), IPInput{Settings: settings, Changed: changed}); err != nil {
				t.Fatalf("%s passes[%d]: %v", c.ID, i, err)
			}
			check := func(list, id string, mirror []string) {
				bodies++
				want, ok := departs[c.ID+" "+list]
				if ok {
					departures++
				} else {
					// the mirror is read as a set (pfb_canonical_alias_set): an aggregate's file is in address order
					want = slices.Compact(slices.Sorted(slices.Values(mirror)))
				}
				if got := body(t, s.Store, id); !slices.Equal(got, want) {
					t.Errorf("%s %s: published %q, want %q (departure listed: %v)", c.ID, list, got, want, ok)
				}
			}
			for alias, mirror := range c.Expect.Passes[i].Canonical {
				group, family := strings.TrimSuffix(strings.TrimSuffix(alias, "_v4"), "_v6"), "ipv"+alias[len(alias)-1:]
				check(fmt.Sprintf("passes[%d].canonical.%s", i, alias), "ip-set/"+group+"/"+family, mirror)
			}
			var aggs map[string]struct{ Aggregate []string }
			if string(c.Expect.Passes[i].Aggregate) != "[]" {
				if err := json.Unmarshal(c.Expect.Passes[i].Aggregate, &aggs); err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
			}
			for class, a := range aggs {
				name, fam, _ := strings.Cut(class, "_")
				check(fmt.Sprintf("passes[%d].aggregate.%s", i, class), "ip-aggregate/"+strings.ToLower(name)+"/ip"+fam, a.Aggregate)
			}
		}
	}
	if cases < 20 || bodies < 50 || departures == 0 {
		t.Errorf("%d cases, %d bodies, %d of them departures: the corpus was not replayed", cases, bodies, departures)
	}
}
