package ipset

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// One test per corpus group. The Core Updater's file work is stood in for by plain data handling here: the name of a file is
// its alias plus an extension, a folder is a name-to-lines map, and the lines of a masterfile are the rows.

// ---- decoded inputs ----

type cidrIn struct{ members *textObj }

type prepIn struct {
	members              *textObj
	dup, agg, rep, drep  bool
	max                  int
	cc, ccwhite, ccblack string
	geo                  geoTable
}

type recMember struct {
	name    string
	missing bool
	text    *textObj
}

type recIn struct {
	members              []recMember
	dedup                bool
	repmode              string
	max                  int
	cc, ccwhite, ccblack string
	geo                  geoTable
	master               *textObj
	denyPre, matchPre    []namedText
	ph                   string
}

type pmaxIn struct {
	deny   []namedText
	max    int
	master *textObj
}

type suppIn struct {
	members, supp, master *textObj
	dedup                 bool
}

type removeIn struct {
	headers []string
	dirs    map[string][]namedText
	master  *textObj
}

type closingIn struct {
	deny, orig []namedText
	dedup      bool
	master     *textObj
	ph         string
}

type canonIn struct{ members *textObj }

type unionIn struct {
	typ       string
	members   []namedText
	collapsed bool
	ph        string
}

type dnsIn struct {
	files []namedText
	ph    string
}

type matrixIn struct {
	fn         string
	a, b, c, d bool
}

type pipeFeed struct {
	name, alias string
	text        *textObj
}

type pipePass struct {
	changed []string
	set     []namedText
}

type pipeIn struct {
	feeds                []pipeFeed
	suppV4, suppV6       *textObj
	passes               []pipePass
	union                bool
	dup, agg, rep, drep  bool
	prep, supp           bool
	dmax, pmax           int
	cc, ccwhite, ccblack string
	geo                  geoTable
}

var removeDirs = []string{"deny", "original", "match", "matchgen", "permit", "native"}

func decodeInput(c *corpusCase, in *obj) (any, error) {
	var v any
	switch c.Variant {
	case "cidr_aggregate":
		v = cidrIn{in.text("members")}
	case "preprocess":
		v = prepIn{members: in.text("members"), dup: in.flag("dup"), agg: in.flag("agg"), rep: in.flag("rep"), drep: in.flag("drep"),
			max: in.num("max"), cc: in.str("cc"), ccwhite: in.str("ccwhite"), ccblack: in.str("ccblack"), geo: in.geo("geo")}
	case "recompute":
		r := recIn{dedup: in.onOff("dedup"), repmode: in.str("repmode"), max: in.num("max"), cc: in.str("cc"), ccwhite: in.str("ccwhite"),
			ccblack: in.str("ccblack"), geo: in.geo("geo"), master: in.nullText("master"), denyPre: in.texts("deny_pre"),
			matchPre: in.texts("match_pre"), ph: in.str("ph")}
		var raws []json.RawMessage
		in.fail("members", json.Unmarshal(in.m["members"], &raws))
		for i, raw := range raws {
			m, err := objOf(raw, fmt.Sprintf("%s.members[%d]", in.what, i), []string{"name"}, append(slices.Clone(textKeys), "missing"))
			if err != nil {
				return nil, err
			}
			t, err := parseTextMap(m.m, m.what, []string{"name", "missing"})
			if err != nil {
				return nil, err
			}
			r.members = append(r.members, recMember{m.str("name"), m.has("missing") && m.flag("missing"), t})
			if m.err != nil {
				return nil, m.err
			}
		}
		v = r
	case "pmax":
		in.geo("geo") // recorded with every case; the legacy pmax verb classifies no country
		v = pmaxIn{deny: in.texts("deny"), max: in.num("max"), master: in.nullText("master")}
	case "suppress/v4":
		v = suppIn{members: in.text("members"), supp: in.nullText("suppression"), master: in.nullText("master"), dedup: in.onOff("dedup")}
	case "suppress/v6":
		v = suppIn{members: in.text("members"), supp: in.nullText("suppression")}
	case "remove":
		r := removeIn{headers: in.strs("headers"), dirs: map[string][]namedText{}, master: in.nullText("master")}
		for _, d := range removeDirs {
			r.dirs[d] = in.texts(d)
		}
		v = r
	case "closing":
		v = closingIn{deny: in.texts("deny"), orig: in.texts("orig"), dedup: in.onOff("dedup"), master: in.nullText("master"), ph: in.str("ph")}
	case "canonical":
		v = canonIn{in.text("members")}
	case "union":
		v = unionIn{typ: in.str("type"), members: in.texts("members"), collapsed: in.onOff("collapsed"), ph: in.str("ph")}
	case "dnsblip":
		v = dnsIn{files: in.texts("ip_files"), ph: in.str("ip_ph")}
	case "matrix/recompute_matrix":
		v = matrixIn{fn: in.str("fn"), a: in.flag("dedup_on"), b: in.flag("rep_trigger"), c: in.flag("drep_on"), d: in.flag("prep_on")}
	case "matrix/closing_pass_active":
		v = matrixIn{fn: in.str("fn"), a: in.flag("dup_on"), b: in.flag("ran_v4")}
	case "pipeline":
		return decodePipeline(in)
	default:
		return nil, fmt.Errorf("%s: no input decoder for %q", c.ID, c.Variant)
	}
	return v, in.err
}

func decodePipeline(in *obj) (any, error) {
	sw, err := objOf(in.m["switches"], in.what+".switches",
		[]string{"dup", "agg", "rep", "drep", "prep", "supp", "dmax", "pmax", "cc", "ccwhite", "ccblack", "geo"}, nil)
	if err != nil {
		return nil, err
	}
	p := pipeIn{dup: sw.flag("dup"), agg: sw.flag("agg"), rep: sw.flag("rep"), drep: sw.flag("drep"), prep: sw.flag("prep"), supp: sw.flag("supp"),
		dmax: sw.num("dmax"), pmax: sw.num("pmax"), cc: sw.str("cc"), ccwhite: sw.str("ccwhite"), ccblack: sw.str("ccblack"), geo: sw.geo("geo")}
	if sw.err != nil {
		return nil, sw.err
	}
	var raws []json.RawMessage
	in.fail("feeds", json.Unmarshal(in.m["feeds"], &raws))
	for i, raw := range raws {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%s.feeds[%d]: %v", in.what, i, err)
		}
		f := &obj{what: fmt.Sprintf("%s.feeds[%d]", in.what, i), m: m}
		for _, k := range []string{"name", "alias"} {
			if !f.has(k) {
				return nil, fmt.Errorf("%s: missing key %q", f.what, k)
			}
		}
		t, err := parseTextMap(m, f.what, []string{"name", "alias"})
		if err != nil {
			return nil, err
		}
		p.feeds = append(p.feeds, pipeFeed{f.str("name"), f.str("alias"), t})
		if f.err != nil {
			return nil, f.err
		}
	}
	supp, err := objOf(in.m["suppression"], in.what+".suppression", nil, []string{"v4", "v6"})
	if err != nil {
		return nil, err
	}
	p.suppV4, p.suppV6 = supp.nullText("v4"), supp.nullText("v6")
	raws = nil
	in.fail("passes", json.Unmarshal(in.m["passes"], &raws))
	for i, raw := range raws {
		po, err := objOf(raw, fmt.Sprintf("%s.passes[%d]", in.what, i), []string{"changed"}, []string{"set"})
		if err != nil {
			return nil, err
		}
		p.passes = append(p.passes, pipePass{changed: po.strs("changed"), set: po.texts("set")})
		if po.err != nil {
			return nil, po.err
		}
	}
	for _, typ := range in.strs("agg_types") {
		if typ != "Deny" {
			return nil, fmt.Errorf("%s: agg_types %q is not modelled: only the Deny class is a pipeline folder", in.what, typ)
		}
		p.union = true
	}
	if supp.err != nil {
		return nil, supp.err
	}
	return p, in.err
}

// ---- expectation readers ----

func (o *obj) list(k string) listExp {
	var l listExp
	o.fail(k, json.Unmarshal(o.m[k], &l))
	return l
}

func (o *obj) dir(k string) dirExp {
	var d dirExp
	o.fail(k, json.Unmarshal(o.m[k], &d))
	return d
}

// ints reads a list of integers, or nil for null.
func (o *obj) ints(k string) []int {
	var v []int
	o.fail(k, json.Unmarshal(o.m[k], &v))
	return v
}

func (o *obj) must(t *testing.T) {
	t.Helper()
	if o.err != nil {
		t.Fatalf("expect: %v", o.err)
	}
}

func checkInts(t *testing.T, name string, want, got []int) {
	t.Helper()
	if !slices.Equal(want, got) {
		t.Errorf("%s: expected %v, actual %v", name, want, got)
	}
}

func checkBool(t *testing.T, name string, want, got bool) {
	t.Helper()
	if want != got {
		t.Errorf("%s: expected %v, actual %v", name, want, got)
	}
}

func checkStr(t *testing.T, name, want, got string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: expected %q, actual %q", name, want, got)
	}
}

func checkStrs(t *testing.T, name string, want, got []string, ordered bool) {
	t.Helper()
	if msg := listDiff(want, got, ordered); msg != "" {
		t.Errorf("%s: %s", name, msg)
	}
}

// folder is a name-to-lines map of lists, each file named by its alias and ext.
func folder(lists []List, ext string) map[string][]string {
	m := make(map[string][]string, len(lists))
	for _, l := range lists {
		m[l.Name+ext] = l.Lines
	}
	return m
}

func feeds(nt []namedText) []Feed {
	out := make([]Feed, len(nt))
	for i, n := range nt {
		out[i] = Feed{n.name, n.text.String()}
	}
	return out
}

func rowsOf(t *textObj) []string {
	if t == nil {
		return []string{}
	}
	return splitLines(t.String())
}

func familyOf(c *corpusCase) Family { return Family(c.Family) }

// ---- cidr_aggregate ----

func TestCIDRAggregateCorpus(t *testing.T) { runGroup(t, "cidr_aggregate", runCIDRAggregate) }

func runCIDRAggregate(t *testing.T, c *corpusCase) {
	text := c.In.(cidrIn).members.String()
	got := CIDRAggregate(text)
	e := c.Expect
	rcOK(t, e)
	e.list("members").check(t, "members", got, false)
	checkBool(t, "unchanged", e.flag("unchanged"), joinLines(got) == text)
	var stats []int
	if before, after := len(splitLines(text)), len(got); before != after {
		stats = []int{before, after}
	}
	checkInts(t, "stats", e.ints("stats"), stats)
	e.must(t)
}

// ---- preprocess ----

func TestPreprocessCorpus(t *testing.T) { runGroup(t, "preprocess", runPreprocess) }

func runPreprocess(t *testing.T, c *corpusCase) {
	in := c.In.(prepIn)
	got := Preprocess(in.members.String(), PrepIn{Dup: in.dup, Agg: in.agg, Rep: in.rep, DRep: in.drep,
		Reputation: Reputation{Max: in.max, CC: in.cc, CCWhite: in.ccwhite, CCBlack: in.ccblack, Geo: in.geo.lookup()}})
	e := c.Expect
	rcOK(t, e)
	e.list("members").check(t, "members", got.Members, false)
	m := e.list("match_rep")
	if !m.null && m.digest == nil && len(m.lines) == 0 {
		t.Errorf("match_rep: an empty match file cannot be told from no file")
	}
	m.check(t, "match_rep", got.Match, false)
	args := ""
	if got.Ran.Full24 {
		args += "_255"
	}
	if got.Ran.Aggregate {
		args += "_agg"
	}
	if got.Ran.Rep {
		args += "_rep"
	}
	checkStr(t, "args", e.str("args"), args)
	checkBool(t, "ran", e.flag("ran"), args != "")
	e.must(t)
}

// ---- recompute ----

func TestRecomputeCorpus(t *testing.T) { runGroup(t, "recompute", runRecompute) }

func texts(nt []namedText) map[string]string {
	m := map[string]string{}
	for _, n := range nt {
		m[n.name] = n.text.String()
	}
	return m
}

func runRecompute(t *testing.T, c *corpusCase) {
	in := c.In.(recIn)
	e := c.Expect
	denyPre, matchPre := texts(in.denyPre), texts(in.matchPre)
	// The Updater's part: a member with no snapshot falls back to its live deny file, or is skipped.
	var members []Feed
	var wantLog []string
	for _, m := range in.members {
		switch live, ok := denyPre[m.name]; {
		case !m.missing:
			members = append(members, Feed{m.name, m.text.String()})
		case ok:
			members = append(members, Feed{m.name, live})
			wantLog = append(wantLog, fmt.Sprintf("recompute [ %s ]: snapshot missing for [ %s ]; falling back to the live deny file", c.Family, m.name))
		default:
			wantLog = append(wantLog, fmt.Sprintf("recompute [ %s ]: snapshot missing for [ %s ] and no live deny file to fall back to; skipping", c.Family, m.name))
		}
	}
	ph := cmpOr(in.ph, defaultPH)
	got := Recompute(RecomputeIn{Family: familyOf(c), Feeds: members, Master: rowsOf(in.master), Dedup: in.dedup, Mode: repMode(t, in.repmode),
		Rep: Reputation{Max: in.max, CC: in.cc, CCWhite: in.ccwhite, CCBlack: in.ccblack, Geo: in.geo.lookup()}, Placeholder: ph})
	rcOK(t, e)

	if len(got.Lists) != len(members) {
		t.Fatalf("lists: expected one per feed (%d), actual %d", len(members), len(got.Lists))
	}
	deny := map[string][]string{}
	for name, text := range denyPre {
		deny[name+".txt"] = splitLines(text)
	}
	var counts []string
	for i, l := range got.Lists {
		if l.Name != members[i].Name {
			t.Errorf("lists[%d]: expected feed %q, actual %q (the lists follow the feeds)", i, members[i].Name, l.Name)
		}
		deny[l.Name+".txt"] = l.Lines
		counts = append(counts, l.Name+" "+strconv.Itoa(len(l.Lines)))
	}
	e.dir("deny").check(t, "deny", deny, false)
	e.list("master").check(t, "master", got.Master, false)
	e.list("mastercat").check(t, "mastercat", catIf(in.dedup, got.Master), false)
	e.list("counts").check(t, "counts", counts, true)
	if want := e.num("processed"); want != len(got.Lists) {
		t.Errorf("processed: expected %d, actual %d", want, len(got.Lists))
	}

	// The Updater's part: the match folder is what it held, minus the superseded lists, plus the lists written.
	match := map[string][]string{}
	for name, text := range matchPre {
		match[name] = splitLines(text)
	}
	for _, name := range got.DropRep {
		delete(match, "pfB_Match_Rep_"+name+".txt")
	}
	if got.DropExempt {
		delete(match, "pfB_Match_Exempt_v4.txt")
	}
	for _, l := range got.MatchRep {
		match["pfB_Match_Rep_"+l.Name+".txt"] = l.Lines
	}
	if got.MatchExempt != nil {
		match["pfB_Match_Exempt_v4.txt"] = got.MatchExempt
	}
	e.dir("match").check(t, "match", match, false)

	gotLog := e.strs("log")
	for _, line := range wantLog {
		if !slices.Contains(gotLog, line) {
			t.Errorf("log: the fallback decision of the runner is not in the recorded log: expected a line %q in %q", line, gotLog)
		}
	}
	e.must(t)
}

// repMode is the corpus's repmode as the package's named mode.
func repMode(t *testing.T, s string) RepMode {
	switch s {
	case "off":
		return RepOff
	case "dmax":
		return RepDMax
	case "pmax":
		return RepPMax
	}
	t.Fatalf("repmode: unknown mode %q", s)
	return RepOff
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- pmax ----

func TestPMaxCorpus(t *testing.T) { runGroup(t, "pmax", runPMax) }

func runPMax(t *testing.T, c *corpusCase) {
	in := c.In.(pmaxIn)
	got := PMax(feeds(in.deny), rowsOf(in.master), in.max, defaultPH)
	e := c.Expect
	rcOK(t, e)
	e.dir("deny").check(t, "deny", folder(got.Lists, ".txt"), false)
	e.list("master").check(t, "master", got.Master, false)
	e.list("mastercat").check(t, "mastercat", catIf(got.Applied, got.Master), false)
	e.must(t)
}

// catIf is the category file after a verb: cut from the masterfile it rewrote, else the file as the corpus left it, which never
// seeds one.
func catIf(rewritten bool, master []string) []string {
	if rewritten {
		return MasterCat(master)
	}
	return []string{}
}

// ---- suppress ----

func TestSuppressCorpus(t *testing.T) { runGroup(t, "suppress", runSuppress) }

var (
	supp4Hole    = regexp.MustCompile(`^ Suppression Feed_v4: dropping malformed suppression entry \[ (.*) \]$`)
	supp4Members = regexp.MustCompile(`^ Suppression Feed_v4: dropped (\d+) malformed member-file line\(s\) before iprange$`)
)

const supp6Prefix = "IPv6 Suppression: dropping malformed entry [ "

func runSuppress(t *testing.T, c *corpusCase) {
	in := c.In.(suppIn)
	e := c.Expect
	members := in.members.String()
	var holes *string
	if in.supp != nil {
		h := in.supp.String()
		holes = &h
	}
	if c.Family == "v6" {
		runSuppressV6(t, e, members, holes)
		return
	}
	rcOK(t, e)
	got := Suppress(SuppressIn{Family: V4, Alias: "Feed_v4", Members: members, Holes: holes, Master: rowsOf(in.master), Dedup: in.dedup})
	e.list("members").check(t, "members", got.Members, false)
	e.list("master").check(t, "master", got.Master, false)
	var stats []int
	if got.Applied {
		stats = []int{len(splitLines(members)), len(got.Members), len(got.Master)}
	}
	checkInts(t, "stats", e.ints("stats"), stats)

	var badHoles []string
	badMembers := 0
	for _, line := range e.strs("log") {
		switch m := supp4Hole.FindStringSubmatch(line); {
		case m != nil:
			badHoles = append(badHoles, m[1])
		case supp4Members.MatchString(line):
			badMembers, _ = strconv.Atoi(supp4Members.FindStringSubmatch(line)[1])
		default:
			t.Errorf("log: line %q is neither a dropped hole nor a dropped member count", line)
		}
	}
	checkStrs(t, "log: dropped suppression entries", badHoles, got.BadHoles, false)
	if len(got.BadMembers) != badMembers {
		t.Errorf("log: expected %d dropped member rows, actual %d: %q", badMembers, len(got.BadMembers), first(got.BadMembers, 5))
	}
	e.must(t)
}

func runSuppressV6(t *testing.T, e *obj, members string, holes *string) {
	got := Suppress(SuppressIn{Family: V6, Members: members, Holes: holes})
	checkBool(t, "ok", e.flag("ok"), got.Applied)
	e.list("members").check(t, "members", got.Members, false)
	// The messages carry no newline, so they weld into one line; each names one dropped token.
	var tokens []string
	if joined := strings.Join(e.strs("log"), "\n"); joined != "" {
		parts := strings.Split(joined, supp6Prefix)
		if parts[0] != "" {
			t.Errorf("log: unexpected text before the first dropped entry: %q", parts[0])
		}
		for _, p := range parts[1:] {
			tok, ok := strings.CutSuffix(p, " ]")
			if !ok {
				t.Errorf("log: a dropped entry does not end with %q: %q", " ]", p)
			}
			tokens = append(tokens, tok)
		}
	}
	// pfb_cidr_subtract_v6 pools the member tokens first, then the hole tokens, each in file order.
	checkStrs(t, "log: dropped entries", tokens, slices.Concat(got.BadMembers, got.BadHoles), true)
	e.must(t)
}

// ---- remove ----

func TestRemoveCorpus(t *testing.T) { runGroup(t, "remove", runRemove) }

// A folder that must be deleted when it holds no rows is null in the corpus.
func checkFile(t *testing.T, name string, want listExp, got []string) {
	t.Helper()
	if len(got) == 0 && !want.null {
		t.Errorf("%s: expected a file, actual no rows (the file is deleted when empty)", name)
		return
	}
	want.check(t, name, got, false)
}

func runRemove(t *testing.T, c *corpusCase) {
	in := c.In.(removeIn)
	e := c.Expect
	rcOK(t, e)
	// matchgen is not a folder the verb cleans: it is not handed in.
	cleaned := []string{"deny", "original", "match", "permit", "native"}
	names := func(dir string) []string {
		out := []string{}
		for _, n := range in.dirs[dir] {
			out = append(out, n.name)
		}
		return out
	}
	dirs := make([][]string, len(cleaned))
	for i, d := range cleaned {
		dirs[i] = names(d)
	}
	got := Remove(in.headers, rowsOf(in.master), dirs)

	var files map[string][]string
	e.fail("files", json.Unmarshal(e.m["files"], &files))
	if len(got.Kept) != len(cleaned) {
		t.Fatalf("kept: expected one list per directory (%d), actual %d", len(cleaned), len(got.Kept))
	}
	for i, d := range cleaned {
		checkStrs(t, "files/"+d, files[d], got.Kept[i], false)
	}
	checkStrs(t, "files/matchgen", files["matchgen"], names("matchgen"), false)
	if len(files) != len(removeDirs) {
		t.Errorf("files: expected the directories %v, actual %d keys", removeDirs, len(files))
	}
	checkFile(t, "master", e.list("master"), got.Master)
	checkFile(t, "mastercat", e.list("mastercat"), MasterCat(got.Master))
	var msgs []string
	for _, h := range got.Removed {
		msgs = append(msgs, "The Following List has been REMOVED [ "+h+" ]")
	}
	for _, h := range got.Invalid {
		msgs = append(msgs, "Invalid header [ "+h+" ], *skipping*")
	}
	checkStrs(t, "messages", e.strs("messages"), msgs, false)
	e.must(t)
}

// ---- closing ----

func TestClosingCorpus(t *testing.T) { runGroup(t, "closing", runClosing) }

// closingInput is the Updater's part: the deny folder by alias, and the original folder sorted into the count files and the
// original feeds of v4.
func closingInput(in closingIn) ClosingIn {
	ci := ClosingIn{Deny: feeds(in.deny), Dedup: in.dedup, Placeholder: cmpOr(in.ph, defaultPH), Master: rowsOf(in.master)}
	for _, o := range in.orig {
		switch {
		case strings.HasSuffix(o.name, "_v4.aggcount"):
			ci.AggCounts = append(ci.AggCounts, o.text.String())
		case strings.HasSuffix(o.name, "_v4.orig"):
			ci.Origs = append(ci.Origs, o.text.String())
		}
	}
	return ci
}

func runClosing(t *testing.T, c *corpusCase) {
	in := c.In.(closingIn)
	got := Closing(closingInput(in))
	e := c.Expect
	rcOK(t, e)
	e.dir("deny").check(t, "deny", folder(got.Lists, ".txt"), false)
	e.list("master").check(t, "master", got.Master, false)
	if got.Sanity.Final != len(got.Master) && in.dedup {
		t.Errorf("sanity: Final is %d but the masterfile has %d rows", got.Sanity.Final, len(got.Master))
	}
	checkSanity(t, "sanity", e.m["sanity"], in.dedup, got.Sanity)
	e.must(t)
}

// checkSanity compares the printed sanity block with the verdict. With dedup off the report prints no masterfile check.
func checkSanity(t *testing.T, name string, raw json.RawMessage, dedup bool, s Sanity) {
	t.Helper()
	o, err := objOf(raw, name, sanityKeys, nil)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	var strOrNull = func(k string) *string {
		var p *string
		o.fail(k, json.Unmarshal(o.m[k], &p))
		return p
	}
	checkNullable := func(k string, want *string, ok bool, got string) {
		switch {
		case !ok && want != nil:
			t.Errorf("%s.%s: expected %q, actual null", name, k, *want)
		case ok && want == nil:
			t.Errorf("%s.%s: expected null, actual %q", name, k, got)
		case ok && *want != got:
			t.Errorf("%s.%s: expected %q, actual %q", name, k, *want, got)
		}
	}
	checkStr(t, name+".original", o.str("original"), strconv.Itoa(s.Original))
	checkNullable("final", strOrNull("final"), dedup, strconv.Itoa(s.Final))
	verdict := "FAILED"
	if s.Passed {
		verdict = "PASSED"
	}
	checkNullable("verdict", strOrNull("verdict"), dedup, verdict)
	checkNullable("masterfile_count", strOrNull("masterfile_count"), dedup && !s.Passed, strconv.Itoa(s.MasterCat))
	checkNullable("deny_count", strOrNull("deny_count"), dedup && !s.Passed, strconv.Itoa(s.Deny))
	if dedup && s.Passed && s.MasterCat != s.Deny {
		t.Errorf("%s: passed with unequal counts: masterfile %d, deny %d", name, s.MasterCat, s.Deny)
	}
	if !dedup && (s.Final != 0 || s.MasterCat != 0 || s.Deny != 0 || s.Passed || len(s.DupMaster) != 0 || len(s.DupDeny) != 0) {
		t.Errorf("%s: with dedup off the report holds no masterfile check, actual %+v", name, s)
	}
	checkStrs(t, name+".uniq_master", o.strs("uniq_master"), s.DupMaster, false)
	checkStrs(t, name+".uniq_deny", o.strs("uniq_deny"), s.DupDeny, false)
	var empty []string
	for _, n := range s.Empty {
		empty = append(empty, n+".txt")
	}
	checkStrs(t, name+".empty_lists", o.strs("empty_lists"), empty, false)
	if o.err != nil {
		t.Errorf("%v", o.err)
	}
}

// ---- canonical ----

func TestCanonicalCorpus(t *testing.T) { runGroup(t, "canonical", runCanonical) }

func runCanonical(t *testing.T, c *corpusCase) {
	got := Canonical(c.In.(canonIn).members.String())
	set := c.Expect.list("set")
	set.check(t, "set", got, true)
	if !slices.IsSorted(got) {
		t.Errorf("set: not in byte order, first rows %q", first(got, 5))
	}
	c.Expect.must(t)
}

// ---- union ----

func TestUnionCorpus(t *testing.T) { runGroup(t, "union", runUnion) }

// classFolder is the Updater's part: the files of a class folder that are member lists, by alias.
func classFolder(files []namedText, ext string) []Feed {
	var out []Feed
	for _, f := range files {
		if a, ok := strings.CutSuffix(f.name, ext); ok {
			out = append(out, Feed{a, f.text.String()})
		}
	}
	return out
}

func runUnion(t *testing.T, c *corpusCase) {
	in := c.In.(unionIn)
	got := Union(familyOf(c), in.collapsed, cmpOr(in.ph, defaultPH), classFolder(in.members, ".txt"))
	e := c.Expect
	rcOK(t, e)
	var kept []string
	for _, k := range got.Kept {
		kept = append(kept, k+".txt")
	}
	e.list("kept").check(t, "kept", kept, true)
	e.list("aggregate").check(t, "aggregate", got.Aggregate, false)
	e.list("consumer").check(t, "consumer", got.Consumer, false)
	checkInts(t, "stats", e.ints("stats"), []int{got.Before, len(got.Aggregate)})
	e.must(t)
}

// ---- dnsblip ----

func TestDNSBLIPCorpus(t *testing.T) { runGroup(t, "dnsblip", runDNSBLIP) }

func runDNSBLIP(t *testing.T, c *corpusCase) {
	in := c.In.(dnsIn)
	got := DNSBLIP(familyOf(c), cmpOr(in.ph, defaultPH), classFolder(in.files, ".ip"))
	e := c.Expect
	e.list("content").check(t, "content", splitLines(got.Content), true)
	checkBool(t, "final_newline", e.flag("final_newline"), strings.HasSuffix(got.Content, "\n"))
	var sources []string
	for _, s := range got.Sources {
		sources = append(sources, s+".ip")
	}
	e.list("sources").check(t, "sources", sources, true)
	e.must(t)
}

// ---- matrix ----

func TestMatrixCorpus(t *testing.T) { runGroup(t, "matrix", runMatrix) }

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func checkMatrix(t *testing.T, name string, o *obj, m Matrix) {
	t.Helper()
	checkBool(t, name+".invoke_v4", o.flag("invoke_v4"), m.InvokeV4)
	checkBool(t, name+".invoke_v6", o.flag("invoke_v6"), m.InvokeV6)
	checkStr(t, name+".dedup", o.str("dedup"), onOff(m.Dedup))
	checkStr(t, name+".repmode", o.str("repmode"), string(m.Mode))
	checkBool(t, name+".legacy_pmax_followup", o.flag("legacy_pmax_followup"), m.LegacyPMax)
	if o.err != nil {
		t.Errorf("%v", o.err)
	}
}

func runMatrix(t *testing.T, c *corpusCase) {
	in := c.In.(matrixIn)
	e := c.Expect
	if in.fn == "recompute_matrix" {
		checkMatrix(t, "matrix", e, RecomputeMatrix(in.a, in.b, in.c, in.d))
	} else {
		invoke, dedup := ClosingPass(in.a, in.b)
		checkBool(t, "invoke", e.flag("invoke"), invoke)
		checkStr(t, "alias_arg", e.str("alias_arg"), onOff(dedup))
	}
	e.must(t)
}

// ---- pipeline ----

func TestPipelineCorpus(t *testing.T) { runGroup(t, "pipeline", runPipeline) }

var passKeys = []string{"matrix", "ran", "canonical", "aggregate", "closing", "deny_final"}

func runPipeline(t *testing.T, c *corpusCase) {
	in := c.In.(pipeIn)
	cfg := PipelineConfig{
		Settings: Settings{Dup: in.dup, Agg: in.agg, Rep: in.rep, DRep: in.drep, PRep: in.prep, Supp: in.supp, Max: in.dmax, DMax: in.dmax, PMax: in.pmax,
			CC: in.cc, CCWhite: in.ccwhite, CCBlack: in.ccblack, Geo: in.geo.lookup(), Placeholder: defaultPH},
		Union: in.union,
	}
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
	var expected []json.RawMessage
	c.Expect.fail("passes", json.Unmarshal(c.Expect.m["passes"], &expected))
	c.Expect.must(t)
	if len(expected) != len(in.passes) {
		t.Fatalf("passes: the corpus records %d passes for %d run", len(expected), len(in.passes))
	}
	p := NewPipeline(cfg)
	for i, ps := range in.passes {
		set := map[string]string{}
		for _, s := range ps.set {
			set[s.name] = s.text.String()
		}
		got := p.Pass(ps.changed, set)
		name := fmt.Sprintf("passes[%d]", i)
		e, err := objOf(expected[i], name, passKeys, nil)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if m, err := objOf(e.m["matrix"], name+".matrix", []string{"invoke_v4", "invoke_v6", "dedup", "repmode", "legacy_pmax_followup"}, nil); err != nil {
			t.Errorf("%v", err)
		} else {
			checkMatrix(t, name+".matrix", m, got.Matrix)
		}
		if r, err := objOf(e.m["ran"], name+".ran", []string{"v4", "v6"}, nil); err != nil {
			t.Errorf("%v", err)
		} else {
			checkBool(t, name+".ran.v4", r.flag("v4"), got.RanV4)
			checkBool(t, name+".ran.v6", r.flag("v6"), got.RanV6)
		}
		e.dir("canonical").check(t, name+".canonical", canonicalFolder(got.Canonical), true)
		checkUnion(t, name+".aggregate", e.m["aggregate"], got.Union)
		switch {
		case e.isNull("closing") && got.Closing != nil:
			t.Errorf("%s.closing: expected the closing pass not to run, actual %+v", name, *got.Closing)
		case !e.isNull("closing") && got.Closing == nil:
			t.Errorf("%s.closing: expected the closing pass to run, actual none", name)
		case got.Closing != nil:
			checkSanity(t, name+".closing", e.m["closing"], in.dup, *got.Closing)
		}
		e.dir("deny_final").check(t, name+".deny_final", folder(got.Deny, ".txt"), false)
		if e.err != nil {
			t.Errorf("%v", e.err)
		}
	}
}

func canonicalFolder(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}

// checkUnion compares the recorded Uber unions ([] or {"<Class>_<family>": {kept, aggregate, consumer}}) with the pass's.
func checkUnion(t *testing.T, name string, raw json.RawMessage, got map[Family]UnionOut) {
	t.Helper()
	var want map[string]json.RawMessage
	if s := strings.TrimSpace(string(raw)); s != "[]" {
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
	}
	for _, f := range []Family{V4, V6} {
		key := "Deny_" + string(f)
		u, ran := got[f]
		w, recorded := want[key]
		switch {
		case recorded && !ran:
			t.Errorf("%s: expected the %s union, actual none", name, key)
		case !recorded && ran:
			t.Errorf("%s: expected no %s union, actual %+v", name, key, u)
		case recorded:
			o, err := objOf(w, name+"."+key, []string{"kept", "aggregate", "consumer"}, nil)
			if err != nil {
				t.Errorf("%v", err)
				continue
			}
			var kept []string
			for _, k := range u.Kept {
				kept = append(kept, k+".txt")
			}
			o.list("kept").check(t, name+"."+key+".kept", kept, true)
			o.list("aggregate").check(t, name+"."+key+".aggregate", u.Aggregate, false)
			o.list("consumer").check(t, name+"."+key+".consumer", u.Consumer, false)
		}
	}
	if len(want) != len(got) {
		t.Errorf("%s: expected %d unions, actual %d", name, len(want), len(got))
	}
}
