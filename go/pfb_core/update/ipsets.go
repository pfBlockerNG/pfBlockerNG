package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/ipset"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// IPSets is the group-level part of stage 12 and stages 13 to 16 of the Update loop (docs/specs/go-updater-pipeline.md §3):
// each IP group's set from its feeds' parsed lists, the continent sets of stage 11 and DNSBLIP, through ipset.Pipeline for
// the deny class (per-feed stage of a changed feed, recompute, pMax, suppression), the canonical set per group and family,
// the selected Uber unions (ADR-11), and their publication as ip-set/<group>/<family> and ip-aggregate/<class>/<family>.
//
// Departures from today: no placeholder (#4038 owner question 1), so an empty list and an empty set have no member and
// an enabled group whose lists hold nothing is published empty; members are published in apply.Member's spelling, a row
// it refuses left out with an issue; a continent's set is taken after the recompute, as every other set (today the GeoIP
// block writes its mirror before the recompute). The pipeline's state is Core's own (StateDir); the lists the Outpost's
// pages read are copies of it, and a continent's list stays the GeoIP stage's.
type IPSets struct {
	FeedDirs map[string]string // the feed folder of each kind, ipv4 and ipv6, holding <name>.parsed.ip (feedstage)
	Folders  map[string]string // the folder of each list class, deny, permit, match and native: <name>.txt for the Outpost
	StateDir string            // Core's own: ipsets.state, the pipeline's state from one Update to the next
	Store    *resources.Store
	Geo      ipset.GeoLookup // the country lookup of dMax and of a feed's reputation stage (CountryLookup); nil: none
}

// IPInput is what one Update hands the IP sets.
type IPInput struct {
	// Settings are the snapshot's projections: feeds/ipv4, feeds/ipv6, policy/ip and ingest.
	Settings map[string]map[string]any
	// Changed are the feeds (their file stems) the per-feed stage parsed this Update.
	Changed map[string]bool
	GeoSets []GeoSet // stage 11's continent sets
	// DNSBLIP are the DNSBLIP_v4 and _v6 lists (sub-slice 9g fills it), each a set the loop builds and a list like a feed's:
	// joined after its family's groups and custom lists, which is where today's pass puts it in the recompute's member order
	// ($pfb['existing'], pfblockerng_apply.inc:1833-1844) and in the IP stage (:3710, :4411).
	DNSBLIP []GeoSet
}

// IPOut is what the IP sets published.
type IPOut struct {
	Resources []apply.Resource // every ip-set and ip-aggregate the store holds now, in id order
	Removed   []string         // every ip-set and ip-aggregate the store holds as removed, in id order
	Issues    []apply.Issue
	Closing   *ipset.Sanity // the closing pass's verdict, nil when it did not run: the closing report's
}

// ipList is one list of a set: its file stem, its text, whether the GeoIP stage built it, and whether it changed.
type ipList struct {
	name, text      string
	geo, changed    bool
	custom, dnsblip bool
}

// ipGroup is one set before publication.
type ipGroup struct {
	group, family, class, action string
	generated                    bool // a continent or DNSBLIP: its id wins over a configured group's
	lists                        []ipList
}

const ipStateName = "ipsets.state"

// ipState is ipsets.state: the deny members in their order, a digest of each one's list and of the policy they were built
// under, and the pipeline's state.
type ipState struct {
	Order  []string          `json:"order"`
	Inputs map[string]string `json:"inputs"`
	Policy string            `json:"policy"`
	Snap   map[string]string `json:"snap"`
	Deny   map[string]string `json:"deny"`
	Master []string          `json:"master"`
}

var classes = []string{"deny", "permit", "match", "native"}

// Build builds and publishes every IP set of the snapshot. An id the store held under ip-set/ or ip-aggregate/ that this
// Update does not publish is removed. A store that fails a write fails Build; the sets published before stay published.
func (s IPSets) Build(ctx context.Context, in IPInput) (IPOut, error) {
	var out IPOut
	for _, dir := range []string{s.FeedDirs["ipv4"], s.FeedDirs["ipv6"], s.Folders["deny"], s.Folders["permit"],
		s.Folders["match"], s.Folders["native"], s.StateDir} {
		if !filepath.IsAbs(dir) {
			return out, fmt.Errorf("the IP sets need every folder given as an absolute path, not %q", dir)
		}
	}
	policy, ingest := in.Settings["policy/ip"], in.Settings["ingest"]
	cfg := ipset.PipelineConfig{Settings: ipset.Settings{Dup: flag(policy, "dedup"), Agg: flag(policy, "aggregate"),
		Rep: flag(policy, "max"), DRep: flag(policy, "dMax"), PRep: flag(policy, "pMax"), Supp: flag(ingest, "suppression"),
		Max: num(policy, "maxLimit"), DMax: num(policy, "dMaxLimit"), PMax: num(policy, "pMaxLimit"), CCWhite: str(policy, "countryWhitelistAction"),
		CCBlack: str(policy, "countryBlacklistAction"), Geo: s.Geo}}
	var cc []string
	for _, r := range rows(policy["countryWhitelist"]) {
		cc = append(cc, str(r, "code"))
	}
	cfg.CC = strings.Join(cc, ",")
	cfg.SuppV4, cfg.SuppV6 = holes(policy["suppressionV4"]), holes(policy["suppressionV6"])

	groups, err := s.groups(in, cfg.Agg, &out)
	if err != nil {
		return out, err
	}
	st := s.loadState()
	var order, changed []string
	inputs := map[string]string{}
	for i, g := range groups {
		if g.class != "deny" {
			continue
		}
		for _, l := range g.lists {
			cfg.Feeds = append(cfg.Feeds, ipset.PipelineFeed{Name: l.name, Alias: strconv.Itoa(i), Text: l.text, Prepared: l.geo,
				NoSuppress: l.geo || l.custom})
			order = append(order, l.name)
			// a change the caller did not name (an Update that failed before its state was saved) is found here
			if inputs[l.name] = digestOf(l.text); l.changed || st.Inputs[l.name] != inputs[l.name] {
				changed = append(changed, l.name)
			}
		}
	}
	// A member that came, left or moved changes the recompute's ownership, which follows the member order, and a policy
	// change changes every member's processing: every member is changed. A lost state has no order, so the first Update and
	// the one after a loss build every member. Today's pass waits for a feed change or a Force Reload after a policy change.
	settings := cfg.Settings
	settings.Geo = nil
	policyDigest := digestOf(fmt.Sprintf("%+v %q %q", settings, deref(cfg.SuppV4), deref(cfg.SuppV6)))
	if !slices.Equal(order, st.Order) || policyDigest != st.Policy {
		changed = order
	}
	p := ipset.ResumePipeline(cfg, ipset.State{Snap: st.Snap, Deny: st.Deny, Master: st.Master})
	pass := p.Pass(changed, nil)
	out.Closing = pass.Closing
	next := p.State()
	if err := s.saveState(ipState{Order: order, Inputs: inputs, Policy: policyDigest, Snap: next.Snap, Deny: next.Deny, Master: next.Master}); err != nil {
		return out, err
	}

	// Each set's lists as they stand after the recompute and the suppression.
	final := map[string]map[string]string{} // class: list name: text
	for _, c := range classes {
		final[c] = map[string]string{}
	}
	bodies := make([][]string, len(groups))
	for i, g := range groups {
		if g.class == "deny" {
			for _, l := range g.lists {
				final["deny"][l.name] = next.Deny[l.name]
			}
			bodies[i] = pass.Canonical[strconv.Itoa(i)+"_"+short(g.family)]
			continue
		}
		var all string
		for _, l := range g.lists {
			final[g.class][l.name] = l.text
			all += l.text
		}
		bodies[i] = ipset.Canonical(all)
	}
	for _, g := range groups {
		for _, l := range g.lists {
			if !l.geo { // a continent's list is the GeoIP stage's
				if err := writeList(filepath.Join(s.Folders[g.class], l.name+".txt"), final[g.class][l.name]); err != nil {
					return out, err
				}
			}
		}
	}
	if err := s.prune(final); err != nil {
		return out, err
	}

	type pub struct {
		id      string
		members []string
		meta    map[string]any
	}
	var pubs []pub
	builtBy := map[string]bool{} // each id published, and whether a set the loop builds holds it
	for _, generated := range []bool{true, false} {
		for i, g := range groups {
			if g.generated != generated {
				continue
			}
			id, ok := apply.SetID(g.group, g.family)
			byLoop, taken := builtBy[id]
			switch {
			case !ok:
				out.Issues = append(out.Issues, apply.Issue{Resource: "ip-set/" + g.group + "/" + g.family, Stage: "apply",
					Code: "set_unpublishable", Message: "the group's name maps to no alias the Outpost can load"})
				continue
			case taken:
				msg := "another group of this family takes this id; the group is not published"
				if byLoop {
					msg = "a set the Core Updater builds itself takes this id; the group is not published"
				}
				out.Issues = append(out.Issues, apply.Issue{Resource: id, Stage: "apply", Code: "set_id_taken", Message: msg})
				continue
			}
			builtBy[id] = generated
			action, direction := actionOf(g.action)
			meta := map[string]any{"action": action}
			if direction != nil {
				meta["direction"] = direction
			}
			pubs = append(pubs, pub{id, members(&out, id, g.family, bodies[i]), meta})
		}
	}
	var aggregates []string
	for _, r := range rows(policy["aggregates"]) {
		aggregates = append(aggregates, str(r, "class"))
	}
	for _, c := range classes {
		if !slices.Contains(aggregates, c) {
			continue
		}
		for _, family := range []string{"ipv4", "ipv6"} {
			var lists []ipset.Feed
			for name, text := range final[c] {
				lists = append(lists, ipset.Feed{Name: name, Text: text})
			}
			u := ipset.Union(ipset.Family(short(family)), cfg.Agg, "", lists)
			id := "ip-aggregate/" + c + "/" + family
			pubs = append(pubs, pub{id, members(&out, id, family, u.Aggregate), map[string]any{"action": "alias_only"}})
		}
	}

	if err := ctx.Err(); err != nil {
		return out, err
	}
	published := map[string]bool{}
	for _, p := range pubs {
		g, err := s.Store.Publish(p.id, p.members, p.meta)
		if err != nil {
			return out, fmt.Errorf("%s: %w", p.id, err)
		}
		published[p.id] = true
		r := apply.Resource{ID: p.id, Generation: g, Action: p.meta["action"].(string), Entries: len(p.members)}
		r.Direction, _ = p.meta["direction"].([]string)
		out.Resources = append(out.Resources, r)
	}
	slices.SortFunc(out.Resources, func(a, b apply.Resource) int { return strings.Compare(a.ID, b.ID) })
	for _, prefix := range []string{"ip-aggregate/", "ip-set/"} {
		current, err := s.Store.IDs(prefix)
		if err != nil {
			return out, err
		}
		removed, err := s.Store.RemovedIDs(prefix)
		if err != nil {
			return out, err
		}
		for _, id := range current {
			if !published[id] {
				if err := s.Store.Remove(id); err != nil {
					return out, err
				}
				removed = append(removed, id)
			}
		}
		slices.Sort(removed)
		out.Removed = append(out.Removed, removed...)
	}
	return out, nil
}

// groups are the sets of the snapshot, IPv4 then IPv6: per family the continents in the package's order, then the
// groups in config order (each group's feed rows, then its custom list), then DNSBLIP, as today's pass registers them.
// A group that is Disabled, has no list class or has neither a feed row nor a custom list builds no set.
func (s IPSets) groups(in IPInput, agg bool, res *IPOut) ([]ipGroup, error) {
	var out []ipGroup
	generatedName := map[string]bool{} // the lists of the sets the loop builds: no feed may take one's name
	for _, g := range slices.Concat(in.GeoSets, in.DNSBLIP) {
		generatedName[g.Alias] = true
	}
	for _, kind := range []string{"ipv4", "ipv6"} {
		suffix := "_" + short(kind)
		geoGroup := func(g GeoSet, dnsblip bool) error {
			text, err := readList(g.Path)
			if err != nil {
				return err
			}
			// a continent is aggregated in any class (the GeoIP block), DNSBLIP as a feed is: outside deny
			if agg && kind == "ipv4" && (!dnsblip || g.ListClass != "deny") {
				text = lines(ipset.CIDRAggregate(text))
			}
			out = append(out, ipGroup{g.Group, kind, g.ListClass, g.Action, true,
				[]ipList{{name: g.Alias, text: text, geo: !dnsblip, changed: g.Changed, dnsblip: dnsblip}}})
			return nil
		}
		for _, g := range in.GeoSets {
			if g.Family == kind && slices.Contains(classes, g.ListClass) {
				if err := geoGroup(g, false); err != nil {
					return nil, err
				}
			}
		}
		for _, group := range rows(in.Settings["feeds/"+kind]["groups"]) {
			g := ipGroup{group: str(group, "name"), family: kind, class: str(group, "listClass"), action: str(group, "action")}
			if g.action == "" || g.action == "Disabled" || !slices.Contains(classes, g.class) {
				continue
			}
			var names []string
			for _, row := range rows(group["feeds"]) {
				if str(row, "state") != "disabled" && str(row, "url") != "" {
					names = append(names, str(row, "header")+suffix)
				}
			}
			custom := str(group, "customList") != ""
			if custom {
				names = append(names, g.group+"_custom"+suffix)
			}
			for j, name := range names {
				if generatedName[name] {
					res.Issues = append(res.Issues, apply.Issue{Resource: "feed/" + kind + ":" + name, Stage: "apply", Code: "list_name_taken",
						Message: "a set the Core Updater builds itself owns this list's name; the feed is left out of its group"})
					continue
				}
				text, err := readList(filepath.Join(s.FeedDirs[kind], name+".parsed.ip"))
				if err != nil {
					return nil, err
				}
				// Today's per-feed stage aggregates a list of another class than deny (cidr_aggregate).
				if agg && kind == "ipv4" && g.class != "deny" {
					text = lines(ipset.CIDRAggregate(text))
				}
				g.lists = append(g.lists, ipList{name: name, text: text, changed: in.Changed[name], custom: custom && j == len(names)-1})
			}
			if len(names) > 0 {
				out = append(out, g)
			}
		}
		for _, g := range in.DNSBLIP {
			if g.Family == kind && slices.Contains(classes, g.ListClass) {
				if err := geoGroup(g, true); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

// prune deletes each list of a class folder that no list of that class names now, as today's orphan prune does
// (pfblockerng_apply.inc:1962-2035, the <folder>/<name>.txt of a header $pfb['existing'] no longer holds). A continent's list
// is the GeoIP stage's and is left to it.
func (s IPSets) prune(final map[string]map[string]string) error {
	for class, lists := range final {
		files, err := filepath.Glob(filepath.Join(s.Folders[class], "*.txt"))
		if err != nil {
			return err
		}
		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".txt")
			if _, ok := lists[name]; ok || slices.Contains(continents, strings.TrimSuffix(strings.TrimSuffix(name, "_v4"), "_v6")) {
				continue
			}
			if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// members is a body in Core's spelling (apply.Member): a row it refuses is left out, with one issue for the set.
func members(out *IPOut, id, family string, body []string) []string {
	kept := make([]string, 0, len(body))
	var refused []string
	for _, row := range body {
		if m, err := apply.Member(row, family); err == nil {
			kept = append(kept, m)
		} else {
			refused = append(refused, row)
		}
	}
	if len(refused) > 0 {
		out.Issues = append(out.Issues, apply.Issue{Resource: id, Stage: "apply", Code: "member_refused",
			Message: fmt.Sprintf("%d rows are left out, being no address or prefix Core publishes, the first %q", len(refused), refused[0])})
	}
	slices.Sort(kept)
	return slices.Compact(kept)
}

// actionOf is a group action's resource action and direction, as pfb_outpost_expected_aliases() reads it: an Alias_*
// action is alias_only without a direction.
func actionOf(action string) (string, []string) {
	verb, way, _ := strings.Cut(action, "_")
	if verb == "Alias" {
		return "alias_only", nil
	}
	return strings.ToLower(verb), map[string][]string{"Inbound": {"ingress"}, "Outbound": {"egress"}, "Both": {"egress", "ingress"}}[way]
}

func (s IPSets) loadState() ipState {
	var st ipState
	if b, err := os.ReadFile(filepath.Join(s.StateDir, ipStateName)); err == nil && json.Unmarshal(b, &st) == nil {
		return st
	}
	return ipState{} // a lost or unreadable state rebuilds every set from its lists
}

func (s IPSets) saveState(st ipState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeList(filepath.Join(s.StateDir, ipStateName), string(b))
}

// writeList replaces path with text by a rename, unless it holds text already.
func writeList(path, text string) error {
	if sameContent(path, []byte(text)) {
		return nil
	}
	staged, err := stageFile(path, []byte(text))
	if err != nil {
		return err
	}
	if err := os.Rename(staged, path); err != nil {
		os.Remove(staged)
		return err
	}
	return nil
}

// readList is a list file's text, its last line terminated; a list that does not exist is empty (a feed that parsed to
// nothing on its first run publishes no list).
func readList(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	return string(b), nil
}

// holes is a suppression list of the policy as the list file today's pass writes; nil for an empty list.
func holes(v any) *string {
	var text string
	for _, r := range rows(v) {
		text += str(r, "cidr") + "\n"
	}
	if text == "" {
		return nil
	}
	return &text
}

func digestOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func lines(rows []string) string {
	if len(rows) == 0 {
		return ""
	}
	return strings.Join(rows, "\n") + "\n"
}

func short(family string) string { return "v" + strings.TrimPrefix(family, "ipv") }

func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }

func flag(m map[string]any, k string) bool { v, _ := m[k].(bool); return v }

func num(m map[string]any, k string) int { v, _ := m[k].(int64); return int(v) }

// CountryLookup opens the MaxMind country database at path as the lookup dMax and a feed's reputation stage take: the ISO
// code of the address "<octets>.1", as today's mmdblookup of "country iso_code" prints it, "" when the database has none.
// The caller closes the reader after the IP sets are built.
func CountryLookup(path string) (ipset.GeoLookup, io.Closer, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return func(octets string) string {
		addr, err := netip.ParseAddr(octets + ".1")
		if err != nil || !addr.Is4() {
			return ""
		}
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if db.Lookup(addr).Decode(&rec) != nil {
			return ""
		}
		return rec.Country.ISOCode
	}, db, nil
}
