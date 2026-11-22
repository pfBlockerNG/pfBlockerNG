package ipset

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// Issue #4038 (slice 9b): Core publishes a set's members through apply.Member, one spelling per network and the address
// guard, so a body can differ from the list this corpus pins. The corpus keeps today's answers; the member fixture
// (tests/core/fixtures/ip_members.json, ipset_departures) names every list Core publishes differently, with today's answer as
// old_expect and the published body as expect. The algebra itself is unchanged: its callers still get today's lists.
const membersFixturePath = "../../../tests/core/fixtures/ip_members.json"

type departure struct {
	Case, List, Family string
	Old                []string `json:"old_expect"`
	Expect             []string
	Departure          string
}

// published is the body Core publishes from lines: each member in Core's spelling, the rows it leaves out dropped, sorted and
// unique.
func published(lines []string, family string) []string {
	var out []string
	for _, l := range lines {
		if m, err := apply.Member(l, family); err == nil {
			out = append(out, m)
		}
	}
	return sortUniq(out)
}

func ipFamily(f string) string { return "ip" + f }

// WHEN Core publishes every list of the corpus that is a body (a canonical set, an Uber aggregate, the canonical sets and
// aggregates of a pipeline pass) THEN the body is the list itself, sorted and unique, or the member fixture names the list
// with today's answer and the body Core publishes instead.
func TestCorePublishesTheCorpusListsAsTheMemberFixtureSays(t *testing.T) {
	raw, err := os.ReadFile(membersFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Departures []departure `json:"ipset_departures"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	listed := map[string]departure{}
	for _, d := range doc.Departures {
		key := d.Case + " " + d.List
		if _, twice := listed[key]; twice || d.Departure == "" {
			t.Errorf("%s: listed twice or without its departure note", key)
		}
		listed[key] = d
	}
	seen := map[string]bool{}
	bodies := 0
	check := func(c *corpusCase, list, family string, lines []string) {
		bodies++
		key := c.ID + " " + list
		body, today := published(lines, family), sortUniq(slices.Clone(lines))
		d, ok := listed[key]
		seen[key] = ok
		switch {
		case slices.Equal(body, today) && ok:
			t.Errorf("%s: listed as a departure, but Core publishes it as it is", key)
		case slices.Equal(body, today):
		case !ok:
			t.Errorf("%s: Core publishes %q from %q; the member fixture does not name it", key, body, lines)
		case !slices.Equal(d.Old, lines) || !slices.Equal(d.Expect, body) || d.Family != family:
			t.Errorf("%s: today %q publishes %q (%s); the fixture says %q publishes %q (%s)", key, lines, body, family, d.Old, d.Expect, d.Family)
		}
	}
	lines := func(c *corpusCase, raw json.RawMessage, what string) ([]string, bool) {
		var l listExp
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("%s %s: %v", c.ID, what, err)
		}
		return l.lines, l.digest == nil && !l.null
	}
	for _, c := range theCorpus(t).Cases {
		family := ipFamily(c.Family)
		switch c.Op {
		case "canonical":
			if l, ok := lines(c, c.Expect.m["set"], "set"); ok {
				check(c, "set", family, l)
			} else {
				check(c, "set", family, Canonical(c.In.(canonIn).members.String()))
			}
		case "union":
			if l, ok := lines(c, c.Expect.m["aggregate"], "aggregate"); ok {
				check(c, "aggregate", family, l)
			} else {
				in := c.In.(unionIn)
				check(c, "aggregate", family, Union(familyOf(c), in.collapsed, cmpOr(in.ph, defaultPH), classFolder(in.members, ".txt")).Aggregate)
			}
		case "pipeline":
			var passes []struct {
				Canonical map[string]listExp `json:"canonical"`
				Aggregate json.RawMessage    `json:"aggregate"`
			}
			if err := json.Unmarshal(c.Expect.m["passes"], &passes); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			for i, p := range passes {
				for _, alias := range slices.Sorted(func(yield func(string) bool) {
					for k := range p.Canonical {
						if !yield(k) {
							return
						}
					}
				}) {
					check(c, fmt.Sprintf("passes[%d].canonical.%s", i, alias), aliasFamily(alias), p.Canonical[alias].lines)
				}
				var aggregates map[string]struct {
					Aggregate listExp `json:"aggregate"`
				}
				if json.Unmarshal(p.Aggregate, &aggregates) != nil {
					continue // [] when the pass builds no aggregate
				}
				for class, a := range aggregates {
					check(c, fmt.Sprintf("passes[%d].aggregate.%s", i, class), aliasFamily(class), a.Aggregate.lines)
				}
			}
		}
	}
	for key := range listed {
		if !seen[key] {
			t.Errorf("%s: the member fixture names a list the corpus does not publish", key)
		}
	}
	if bodies < 100 {
		t.Errorf("%d bodies checked", bodies)
	}
}

func aliasFamily(alias string) string {
	if strings.HasSuffix(alias, "_v6") {
		return "ipv6"
	}
	return "ipv4"
}
