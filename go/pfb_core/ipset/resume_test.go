package ipset

import (
	"encoding/json"
	"slices"
	"testing"
)

// The Core Updater runs one pass per Update, each in a new process: it keeps the pipeline's state between them
// (ResumePipeline, Pipeline.State) and hands every feed its current text.

// WHEN every corpus pipeline case runs with the state carried from pass to pass through State and ResumePipeline THEN every
// pass gives the canonical sets and the deny folder the corpus records for one continuous run.
func TestAResumedPipelineGivesTheCorpusPasses(t *testing.T) {
	cases := 0
	for _, c := range theCorpus(t).Cases {
		if c.Op != "pipeline" {
			continue
		}
		cases++
		in := c.In.(pipeIn)
		cfg := PipelineConfig{Settings: Settings{Dup: in.dup, Agg: in.agg, Rep: in.rep, DRep: in.drep, PRep: in.prep, Supp: in.supp,
			DMax: in.dmax, PMax: in.pmax, CC: in.cc, CCWhite: in.ccwhite, CCBlack: in.ccblack, Geo: in.geo.lookup(), Placeholder: defaultPH},
			Union: in.union}
		if in.suppV4 != nil {
			s := in.suppV4.String()
			cfg.SuppV4 = &s
		}
		if in.suppV6 != nil {
			s := in.suppV6.String()
			cfg.SuppV6 = &s
		}
		texts := map[string]string{}
		for _, f := range in.feeds {
			texts[f.name] = f.text.String()
		}
		var passes []struct {
			Canonical dirExp `json:"canonical"`
			Deny      dirExp `json:"deny_final"`
		}
		if err := json.Unmarshal(c.Expect.m["passes"], &passes); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		var st State
		for i, ps := range in.passes {
			for _, s := range ps.set {
				texts[s.name] = s.text.String()
			}
			cfg.Feeds = nil
			for _, f := range in.feeds {
				cfg.Feeds = append(cfg.Feeds, PipelineFeed{Name: f.name, Alias: f.alias, Text: texts[f.name]})
			}
			p := ResumePipeline(cfg, st)
			got := p.Pass(ps.changed, nil)
			st = p.State()
			for _, d := range []struct {
				name    string
				want    dirExp
				got     map[string][]string
				ordered bool
			}{{"canonical", passes[i].Canonical, got.Canonical, true}, {"deny_final", passes[i].Deny, folder(got.Deny, ".txt"), false}} {
				for k, w := range d.want {
					if msg := w.problem(d.got[k], d.ordered); msg != "" {
						t.Errorf("%s passes[%d].%s/%s: %s", c.ID, i, d.name, k, msg)
					}
				}
			}
		}
	}
	if cases < 10 {
		t.Errorf("%d pipeline cases ran", cases)
	}
}

// WHEN a feed leaves the configuration between two runs THEN the resumed pipeline drops its snapshot, its deny file and its
// masterfile rows, and keeps the others'.
func TestAFeedThatLeftIsDroppedWhenThePipelineResumes(t *testing.T) {
	cfg := PipelineConfig{Settings: Settings{Dup: true}, Feeds: []PipelineFeed{
		{Name: "A_v4", Alias: "A", Text: "192.0.2.1\n"}, {Name: "B_v4", Alias: "B", Text: "198.51.100.1\n"}}}
	p := NewPipeline(cfg)
	p.Pass([]string{"A_v4", "B_v4"}, nil)
	before := p.State()
	if !slices.Contains(before.Master, "B_v4 198.51.100.1") || before.Snap["B_v4"] == "" {
		t.Fatalf("before: master %q, snapshots %q; want B_v4 in both", before.Master, before.Snap)
	}
	cfg.Feeds = cfg.Feeds[:1]
	after := ResumePipeline(cfg, before).State()
	if _, ok := after.Snap["B_v4"]; ok {
		t.Errorf("B_v4's snapshot is kept")
	}
	if _, ok := after.Deny["B_v4"]; ok {
		t.Errorf("B_v4's deny file is kept")
	}
	if !slices.Equal(after.Master, []string{"A_v4 192.0.2.1"}) {
		t.Errorf("master = %q, want only A_v4's row", after.Master)
	}
}

// WHEN CIDR Aggregation is on and a changed IPv4 feed is Prepared THEN its text is snapshotted as it is, while the same text
// of a feed that is not Prepared goes through the per-feed stage.
func TestAPreparedFeedSkipsThePerFeedStage(t *testing.T) {
	text := "203.0.113.0/25\n203.0.113.128/25\n"
	for _, tc := range []struct {
		prepared bool
		want     []string
	}{{false, []string{"203.0.113.0/24"}}, {true, []string{"203.0.113.0/25", "203.0.113.128/25"}}} {
		p := NewPipeline(PipelineConfig{Settings: Settings{Agg: true}, Feeds: []PipelineFeed{{Name: "pfB_Asia_v4", Alias: "Asia", Text: text, Prepared: tc.prepared}}})
		got := p.Pass([]string{"pfB_Asia_v4"}, nil)
		if !slices.Equal(got.Canonical["Asia_v4"], tc.want) {
			t.Errorf("prepared %v: canonical %q, want %q", tc.prepared, got.Canonical["Asia_v4"], tc.want)
		}
	}
}

// WHEN suppression is on and a hole covers a member of two feeds THEN the feed marked NoSuppress keeps it and the other loses it.
func TestANoSuppressFeedIsNotSuppressed(t *testing.T) {
	holes := "192.0.2.0/24\n"
	p := NewPipeline(PipelineConfig{Settings: Settings{Supp: true}, SuppV4: &holes, Feeds: []PipelineFeed{
		{Name: "A_v4", Alias: "A", Text: "192.0.2.1\n198.51.100.1\n"},
		{Name: "A_custom_v4", Alias: "Custom", Text: "192.0.2.1\n", NoSuppress: true}}})
	got := p.Pass([]string{"A_v4", "A_custom_v4"}, nil)
	for alias, want := range map[string][]string{"A_v4": {"198.51.100.1"}, "Custom_v4": {"192.0.2.1"}} {
		if !slices.Equal(got.Canonical[alias], want) {
			t.Errorf("%s = %q, want %q", alias, got.Canonical[alias], want)
		}
	}
}
