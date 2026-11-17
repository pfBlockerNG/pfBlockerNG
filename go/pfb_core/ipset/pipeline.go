package ipset

import (
	"slices"
	"strconv"
	"strings"
)

// Matrix is how a pass runs the recompute: which families, the dedup flag, the reputation mode and whether the legacy pMax pass
// follows.
type Matrix struct {
	InvokeV4, InvokeV6 bool
	Dedup              bool
	Mode               RepMode
	LegacyPMax         bool
}

// RecomputeMatrix is pfb_ip_recompute_matrix.
func RecomputeMatrix(dedupOn, repTrigger, dRepOn, pRepOn bool) Matrix {
	m := Matrix{Mode: RepOff}
	switch {
	case repTrigger && dRepOn:
		m.Mode, m.LegacyPMax = RepDMax, pRepOn
	case repTrigger && pRepOn:
		m.Mode = RepPMax
	}
	switch {
	case dedupOn:
		m.InvokeV4, m.InvokeV6, m.Dedup = true, true, true
	case repTrigger && (dRepOn || pRepOn):
		m.InvokeV4 = true
	default:
		return Matrix{Mode: RepOff}
	}
	return m
}

// ClosingPass is pfb_ip_closing_pass_active: whether the closing verb runs and with dedup on or off.
func ClosingPass(dupOn, ranV4 bool) (invoke, dedup bool) {
	if dupOn {
		return true, true
	}
	return ranV4, false
}

// Settings are the switches of one update run. Dup, Agg, Rep, DRep, PRep and Supp are the toggles of the same names, DMax and
// PMax the two thresholds, CC, CCWhite, CCBlack and Geo the dMax country setting, Placeholder the v4 spelling.
type Settings struct {
	Dup, Agg, Rep, DRep, PRep, Supp bool
	DMax, PMax                      int
	CC, CCWhite, CCBlack            string
	Geo                             GeoLookup
	Placeholder                     string
}

// PipelineFeed is a configured deny feed: Name ends "_v4" or "_v6", Alias is its logical set and Text its first parse.
type PipelineFeed struct{ Name, Alias, Text string }

// PipelineConfig is a run: Feeds in config order (the priority order), the suppression lists of both families (nil for no
// list), and whether the Uber union of the deny class is built.
type PipelineConfig struct {
	Settings
	Feeds          []PipelineFeed
	SuppV4, SuppV6 *string
	Union          bool
}

// Pipeline carries the state that survives from pass to pass: each feed's parsed text, its snapshot and row count, the deny
// folder and the masterfile.
type Pipeline struct {
	cfg              PipelineConfig
	text, snap, deny map[string]string
	rows             map[string]int
	master           []string
}

// NewPipeline starts a run with an empty deny folder and masterfile.
func NewPipeline(cfg PipelineConfig) *Pipeline {
	p := &Pipeline{cfg: cfg, text: map[string]string{}, snap: map[string]string{}, deny: map[string]string{}, rows: map[string]int{}}
	for _, f := range cfg.Feeds {
		p.text[f.Name] = f.Text
	}
	return p
}

// fileOf is rows as a file: one per line, each terminated.
func fileOf(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return strings.Join(rows, "\n") + "\n"
}

// folder is the deny folder as feeds, in config order.
func (p *Pipeline) folder() []Feed {
	var out []Feed
	for _, f := range p.cfg.Feeds {
		if text, ok := p.deny[f.Name]; ok {
			out = append(out, Feed{f.Name, text})
		}
	}
	return out
}

func (p *Pipeline) store(lists []List) {
	for _, l := range lists {
		p.deny[l.Name] = fileOf(l.Lines)
	}
}

// PassOut is one pass. Canonical is the canonical set per alias and family ("AliasA_v4"), Union the Uber union per family (nil
// without PipelineConfig.Union), Closing the verdict (nil when closing did not run) and Deny the deny folder after the pass.
type PassOut struct {
	Matrix       Matrix
	RanV4, RanV6 bool
	Canonical    map[string][]string
	Union        map[Family]UnionOut
	Closing      *Sanity
	Deny         []List
}

// Pass is one update pass. A feed in set takes the new text; a feed in changed is preprocessed and snapshotted. Then, in order:
// the recompute per RecomputeMatrix and the legacy pMax pass, per alias the suppression and the canonical set, the Uber union,
// and the closing pass.
func (p *Pipeline) Pass(changed []string, set map[string]string) PassOut {
	cfg := p.cfg
	rep := Reputation{Max: cfg.DMax, CC: cfg.CC, CCWhite: cfg.CCWhite, CCBlack: cfg.CCBlack, Geo: cfg.Geo}
	trigger := false
	for _, f := range cfg.Feeds {
		if text, ok := set[f.Name]; ok {
			p.text[f.Name] = text
		}
		if !slices.Contains(changed, f.Name) {
			continue
		}
		trigger = true
		text := p.text[f.Name]
		if strings.HasSuffix(f.Name, "_v4") {
			// A stage that leaves the rows as they are leaves the file as it is.
			if pre := Preprocess(text, PrepIn{Dup: cfg.Dup, Agg: cfg.Agg, Rep: cfg.Rep, DRep: cfg.DRep, Reputation: rep}); !slices.Equal(pre.Members, textRows(text)) {
				text = fileOf(pre.Members)
			}
		}
		p.deny[f.Name], p.snap[f.Name], p.rows[f.Name] = text, text, len(textRows(text))
	}

	out := PassOut{Matrix: RecomputeMatrix(cfg.Dup && trigger, trigger, cfg.DRep, cfg.PRep), Canonical: map[string][]string{}}
	for _, family := range []Family{V4, V6} {
		if family == V4 && !out.Matrix.InvokeV4 || family == V6 && !out.Matrix.InvokeV6 {
			continue
		}
		in := RecomputeIn{Family: family, Master: p.master, Dedup: out.Matrix.Dedup, Mode: RepOff, Rep: rep, Placeholder: cfg.Placeholder}
		if family == V4 {
			in.Mode = out.Matrix.Mode
		}
		if in.Mode == RepPMax {
			in.Rep.Max = cfg.PMax
		}
		for _, f := range cfg.Feeds {
			if !strings.HasSuffix(f.Name, "_"+string(family)) {
				continue
			}
			// A feed that never changed has no snapshot and no deny file, and is left out.
			if snap, ok := p.snap[f.Name]; ok {
				in.Feeds = append(in.Feeds, Feed{f.Name, snap})
			}
		}
		rec := Recompute(in)
		p.store(rec.Lists)
		p.master = rec.Master
		out.RanV4, out.RanV6 = out.RanV4 || family == V4, out.RanV6 || family == V6
	}
	if out.Matrix.LegacyPMax {
		pm := PMax(p.folder(), p.master, cfg.PMax, cfg.Placeholder)
		p.store(pm.Lists)
		p.master = pm.Master
	}

	// Suppression comes after the recompute, which rewrote every feed of the family from its pre-suppression snapshot.
	for _, family := range []Family{V4, V6} {
		holes, ran := cfg.SuppV4, out.RanV4
		if family == V6 {
			holes, ran = cfg.SuppV6, out.RanV6
		}
		touched := map[string]bool{}
		for _, f := range cfg.Feeds {
			touched[f.Alias] = touched[f.Alias] || strings.HasSuffix(f.Name, "_"+string(family)) && slices.Contains(changed, f.Name)
		}
		for _, f := range cfg.Feeds {
			text, ok := p.deny[f.Name]
			if !strings.HasSuffix(f.Name, "_"+string(family)) {
				continue
			}
			key := f.Alias + "_" + string(family)
			if out.Canonical[key] == nil {
				out.Canonical[key] = []string{}
			}
			if !ok {
				continue
			}
			if cfg.Supp && trigger && (touched[f.Alias] || ran) && holes != nil && *holes != "" {
				if s := Suppress(SuppressIn{Family: family, Alias: f.Name, Members: text, Holes: holes, Master: p.master, Dedup: cfg.Dup}); s.Applied {
					text = fileOf(s.Members)
					p.deny[f.Name], p.master = text, s.Master
				}
			}
			out.Canonical[key] = append(out.Canonical[key], text)
		}
	}
	for key, texts := range out.Canonical {
		out.Canonical[key] = Canonical(strings.Join(texts, ""))
	}

	if cfg.Union {
		out.Union = map[Family]UnionOut{}
		for _, family := range []Family{V4, V6} {
			out.Union[family] = Union(family, cfg.Agg, cfg.Placeholder, p.folder())
		}
	}
	if invoke, dedup := ClosingPass(cfg.Dup, out.RanV4); trigger && invoke {
		in := ClosingIn{Deny: p.folder(), Master: p.master, Dedup: dedup, Placeholder: cfg.Placeholder}
		for _, f := range in.Deny {
			if strings.HasSuffix(f.Name, "_v4") {
				in.AggCounts = append(in.AggCounts, strconv.Itoa(p.rows[f.Name])+"\n")
			}
		}
		c := Closing(in)
		p.store(c.Lists)
		p.master = c.Master
		out.Closing = &c.Sanity
	}
	for _, f := range p.folder() {
		out.Deny = append(out.Deny, List{f.Name, textRows(f.Text)})
	}
	return out
}
