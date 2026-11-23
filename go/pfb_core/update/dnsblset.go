package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/ipset"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// DNSBLSet is the group-level DNSBL work of an Update (spec section 3, stages 8 to 10; issue #4038, sub-slice 9g): the
// dnsbl/* publication through slice 7a's assembler with the feeds the per-feed stage parsed, the settings' whitelist, TLD
// and logging inputs, TOP1M, SafeSearch and the PSL; the removed-list cleanup of the DNSBL feed folder; DNSBLIP's lists.
// Every path is the caller's.
type DNSBLSet struct {
	Store         *resources.Store
	FeedDir       string // the DNSBL feed folder: the per-feed stage's Paths.FeedDir for dnsbl feeds ($pfb['dnsdir'])
	ListDir       string // where DNSBLIP_v4.txt and DNSBLIP_v6.txt are written ($pfb['dbdir'])
	Top1m         string // the TOP1M whitelist the Extras stage writes (pfbalexawhitelist.txt)
	PSL           string // the PSL authority the package ships
	SafeSearchDir string // the folder of the package's SafeSearch lists, pfb_dnsbl.<name>.conf
}

// DNSBLInput is what one Update hands the DNSBL build.
type DNSBLInput struct {
	// Settings are the snapshot's projections: feeds/dnsbl, policy/dnsbl, dns and schedule (the Blacklist categories).
	Settings map[string]map[string]any
	Changed  map[string]bool // the DNSBL feeds (their names) the per-feed stage parsed this Update
}

// DNSBLOut is what the DNSBL build gives the rest of the Update.
type DNSBLOut struct {
	// DNSBL is the apply request's dnsbl: the manifest's generation and the groups; nil while DNSBL is not active. A group's
	// Changed (a feed of it was parsed this Update) only drives statistics and is not recovered after a failure.
	DNSBL *apply.DNSBL
	// DNSBLIP is IPInput.DNSBLIP for the IP sets (sub-slice 9h): never nil, empty while DNSBLIP is off or DNSBL is not
	// active, so that the IP sets' prune removes its lists from the class folders. A set's Changed is whether this Update
	// rewrote its list: after a failed write it is not recovered (the next Update finds the list as written), so a consumer
	// detects a content change itself, as the IP sets do by their inputs' digests.
	DNSBLIP []GeoSet
	Issues  []apply.Issue
}

// dnsblRemove removes, and dnsblLstat inspects, a file of the removed-list cleanup: a test's fault seams.
var dnsblRemove, dnsblLstat = os.Remove, os.Lstat

// dnsblipList is a DNSBLIP list Build writes once every step that can fail has passed.
type dnsblipList struct {
	set  GeoSet
	body []byte
}

// Build runs the DNSBL build of one Update. DNSBL is active only while policy/dnsbl.enabled and dns.pfbDnsEnabled are on, as
// pfb_dnsbl_active() decides (pfBlockerNG's own switch holds whenever an Update runs); while it is not, the build publishes
// nothing, removes every dnsbl/* resource and DNSBLIP's lists. Every read and check runs before the first change, so a
// cancelled Update, settings that are absent or of the wrong type, or a read error change nothing. The publication writes
// the bodies before the manifest: if it fails, the store may hold new bodies, but the manifest, and so the data a client
// assembles, is the one before. A failure after the publication (the feed folder's cleanup, a DNSBLIP list's write) is
// returned too, and the next Update finishes it: both compare what is there.
func (s DNSBLSet) Build(ctx context.Context, in DNSBLInput) (DNSBLOut, error) {
	out := DNSBLOut{DNSBLIP: []GeoSet{}}
	if err := checkDNSBLSettings(in.Settings); err != nil {
		return out, err
	}
	policy := in.Settings["policy/dnsbl"]
	enabled := settingBool(policy, "enabled") && settingBool(in.Settings["dns"], "pfbDnsEnabled")
	feeds := dnsblFeeds(in.Settings)
	var lists []dnsblipList
	if enabled {
		var err error
		if lists, err = s.dnsblipLists(feeds, settingText(policy, "dnsblIpAction")); err != nil {
			return out, err
		}
	}

	var set dnsbl.Set
	var ssRefused []string
	invalid, refused := map[string]int{}, map[string]bool{}
	if enabled {
		set = dnsbl.Set{BuiltinLogFlag: mechanismFlag(settingText(policy, "logging")), Top1mEnabled: settingBool(policy, "top1m"),
			Whitelist: settingItems(policy["whitelist"], "domain"), TLDWildcard: settingBool(in.Settings["dns"], "tldWildcard"),
			TLDBlacklist: settingItems(policy["tldBlacklist"], "tld"), TLDExclusions: settingItems(policy["tldExclusions"], "domain")}
		if set.Top1mEnabled {
			b, err := os.ReadFile(s.Top1m)
			switch {
			case err == nil:
				set.Top1m = slices.DeleteFunc(strings.Split(string(b), "\n"), func(l string) bool { return l == "" })
			case !errors.Is(err, fs.ErrNotExist): // a missing list fails the publication, as today's writer does
				return out, err
			}
		}
		var err error
		if set.PSL, err = os.ReadFile(s.PSL); err != nil {
			return out, err
		}
		set.SafeSearch, ssRefused = dnsbl.SafeSearchTable(s.SafeSearchDir, dnsbl.SafeSearchPolicy{Enable: settingBool(policy, "safeSearch"),
			YouTube: settingText(policy, "safeSearchYoutube"), DoH: settingBool(policy, "safeSearchDoh"),
			DoHList: settingItems(policy["safeSearchDohList"], "host")})
		for _, f := range feeds {
			if !feedstage.ValidName(f.Name) {
				refused[f.Name] = true // never joined into a path
				continue
			}
			file, err := os.Open(filepath.Join(s.FeedDir, f.Name+".parsed.ndjson"))
			if errors.Is(err, fs.ErrNotExist) {
				continue // not parsed yet, or parsed to nothing on its first run: today's writer skips it too
			}
			if err != nil {
				return out, err
			}
			var bad int
			f.Rows, bad, err = dnsbl.ReadStaged(file)
			file.Close()
			if err != nil {
				return out, fmt.Errorf("%s: %w", f.Name, err)
			}
			invalid[f.Name] += bad
			set.Feeds = append(set.Feeds, f)
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}

	if !enabled {
		held, err := s.Store.IDs("dnsbl/")
		for _, id := range held {
			err = errors.Join(err, s.Store.Remove(id))
		}
		if err != nil {
			return out, err
		}
	} else {
		res, err := publishDNSBL(s.Store, set)
		if err != nil {
			return out, err
		}
		if out.DNSBL, err = s.groups(res.Generation, set.Feeds, in.Changed); err != nil {
			return out, err
		}
		for _, name := range res.Refused {
			refused[name] = true
		}
		out.Issues = publishIssues(feeds, refused, invalid, res.Dropped, ssRefused)
	}

	removed, err := s.cleanup(feeds)
	for _, name := range removed {
		out.Issues = append(out.Issues, apply.Issue{Resource: "feed/dnsbl:" + name, Stage: "parse", Code: "feed_files_removed",
			Message: "no configured feed names it, so its files are removed (a row the settings do not project counts as removed)"})
	}
	if err != nil {
		return out, err
	}
	out.DNSBLIP, err = s.writeDNSBLIP(lists)
	return out, err
}

// groups is the apply request's dnsbl: the manifest's generation and its groups, each changed when a feed of it was parsed
// this Update.
func (s DNSBLSet) groups(generation uint64, feeds []dnsbl.Feed, changed map[string]bool) (*apply.DNSBL, error) {
	reply, err := s.Store.Get(dnsbl.ManifestID, nil)
	if err != nil {
		return nil, err
	}
	var meta struct{ Groups []apply.Group }
	if err := json.Unmarshal(reply.Metadata, &meta); err != nil {
		return nil, err
	}
	for i, g := range meta.Groups {
		meta.Groups[i].Changed = slices.ContainsFunc(feeds, func(f dnsbl.Feed) bool { return f.Group == g.Name && changed[f.Name] })
	}
	return &apply.DNSBL{Generation: generation, Groups: meta.Groups}, nil
}

// publishIssues are the publication's issues: a feed refused or with rows left out, in walk order; rows a fixed body left
// out; SafeSearch hosts of the wrong shape.
func publishIssues(feeds []dnsbl.Feed, refused map[string]bool, invalid, dropped map[string]int, ssRefused []string) []apply.Issue {
	var issues []apply.Issue
	issue := func(resource, code, message string) {
		issues = append(issues, apply.Issue{Resource: resource, Stage: "parse", Code: code, Message: message})
	}
	reported := map[string]bool{}
	for _, f := range feeds {
		if reported[f.Name] {
			continue
		}
		reported[f.Name] = true
		if refused[f.Name] {
			issue("feed/dnsbl:"+f.Name, "feed_name_refused", "the feed's name cannot name a dnsbl resource: the feed is left out")
		} else if n := invalid[f.Name] + dropped[dnsbl.FeedPrefix+f.Name]; n > 0 {
			issue("feed/dnsbl:"+f.Name, "rows_left_out", fmt.Sprintf("%d rows are left out: the store cannot hold them", n))
		}
	}
	for _, id := range []string{dnsbl.Top1mID, dnsbl.SafeSearchID, dnsbl.PSLID} {
		if n := dropped[id]; n > 0 {
			issue(id, "rows_left_out", fmt.Sprintf("%d rows are left out: the store cannot hold them", n))
		}
	}
	for _, host := range ssRefused {
		issue(dnsbl.SafeSearchID, "safesearch_row_refused", fmt.Sprintf("a SafeSearch row of the wrong shape is left out: host %q", host))
	}
	return issues
}

// checkDNSBLSettings refuses settings a build cannot take for what they say: a projection it reads that is absent, or a
// field of the wrong type among those that decide whether DNSBL is active and which feeds are configured. Taking them would
// read a configured feed as removed and delete its files (today's $config_complete guard, pfblockerng_apply.inc).
func checkDNSBLSettings(settings map[string]map[string]any) error {
	type field struct{ name, kind string }
	check := func(where string, m map[string]any, fields ...field) error {
		for _, f := range fields {
			v := m[f.name]
			_, isBool := v.(bool)
			_, isText := v.(string)
			if f.kind == "bool" && !isBool || f.kind == "text" && !isText || f.kind == "list" && !objectList(v) {
				return fmt.Errorf("%s.%s is not a %s", where, f.name, f.kind)
			}
		}
		return nil
	}
	for _, p := range []struct {
		id     string
		fields []field
	}{
		{"feeds/dnsbl", []field{{"groups", "list"}}},
		{"policy/dnsbl", []field{{"enabled", "bool"}, {"groups", "list"}, {"whitelist", "list"}, {"tldBlacklist", "list"},
			{"tldExclusions", "list"}, {"top1m", "bool"}, {"safeSearchDohList", "list"}, {"dnsblIpAction", "text"}}},
		{"dns", []field{{"tldWildcard", "bool"}, {"pfbDnsEnabled", "bool"}}},
		{"schedule", []field{{"categoryUpdates", "bool"}, {"categoryProviders", "list"}}},
	} {
		m, ok := settings[p.id]
		if !ok {
			return fmt.Errorf("the DNSBL build needs the %s settings", p.id)
		}
		if err := check(p.id, m, p.fields...); err != nil {
			return err
		}
	}
	for i, g := range rows(settings["feeds/dnsbl"]["groups"]) {
		where := fmt.Sprintf("feeds/dnsbl.groups[%d]", i)
		if err := check(where, g, field{"name", "text"}, field{"action", "text"}, field{"customList", "text"}, field{"feeds", "list"}); err != nil {
			return err
		}
		for j, row := range rows(g["feeds"]) {
			if err := check(fmt.Sprintf("%s.feeds[%d]", where, j), row, field{"header", "text"}, field{"state", "text"}, field{"url", "text"}); err != nil {
				return err
			}
		}
	}
	for i, p := range rows(settings["schedule"]["categoryProviders"]) {
		if err := check(fmt.Sprintf("schedule.categoryProviders[%d]", i), p, field{"title", "text"}, field{"selected", "bool"},
			field{"categories", "text"}); err != nil {
			return err
		}
	}
	return nil
}

// objectList: v is a list of objects.
func objectList(v any) bool {
	list, ok := v.([]any)
	return ok && !slices.ContainsFunc(list, func(item any) bool { _, ok := item.(map[string]any); return !ok })
}

// dnsblFeeds are the configured DNSBL feeds, without rows, in today's walk order ($lists, pfblockerng_apply.inc): each
// primary group put first, so the last primary group leads; then the selected Blacklist categories; then the other groups.
// A group's feeds are its rows that are not disabled and have a source, then its custom list; a group is DNSBL_<name>.
// Departure: today a group whose first row has no source loses all its rows ("If only the 'customlist' is defined"); Core
// takes its other rows. Only a hand-edited configuration holds such a group: the Groups page and Core's write refuse it.
func dnsblFeeds(settings map[string]map[string]any) []dnsbl.Feed {
	policy := settings["policy/dnsbl"]
	var categories []dnsbl.Feed
	if settingBool(settings["schedule"], "categoryUpdates") {
		flag := mechanismFlag(settingText(policy, "blacklistLogging"))
		for _, p := range rows(settings["schedule"]["categoryProviders"]) {
			title := settingText(p, "title")
			if !settingBool(p, "selected") || !feedstage.ValidName(title) {
				continue
			}
			for _, c := range strings.Split(settingText(p, "categories"), ",") {
				if c != "" {
					categories = append(categories, dnsbl.Feed{Name: title + "_" + strings.ReplaceAll(c, "-", "_"), Group: "DNSBL_" + title, LogFlag: flag})
				}
			}
		}
	}
	byName := map[string]map[string]any{}
	for _, g := range rows(policy["groups"]) {
		byName[settingText(g, "name")] = g
	}
	lists := [][]dnsbl.Feed{categories}
	for _, g := range rows(settings["feeds/dnsbl"]["groups"]) {
		if settingText(g, "action") != "unbound" {
			continue
		}
		name, gp := settingText(g, "name"), byName[settingText(g, "name")]
		f := dnsbl.Feed{Group: "DNSBL_" + name, LogFlag: mechanismFlag(settingText(gp, "logging")), Top1m: settingBool(gp, "top1mFilter")}
		var list []dnsbl.Feed
		for _, row := range rows(g["feeds"]) {
			if settingText(row, "state") != "disabled" && settingText(row, "url") != "" {
				f.Name, f.Mode = settingText(row, "header"), settingText(row, "action")
				list = append(list, f)
			}
		}
		if settingText(g, "customList") != "" {
			f.Name, f.Mode, f.Provenance = name+"_custom", "deny", "user"
			list = append(list, f)
		}
		if settingBool(gp, "primary") {
			lists = slices.Insert(lists, 0, list)
		} else {
			lists = append(lists, list)
		}
	}
	return slices.Concat(lists...)
}

// cleanup is today's removed-list cleanup of the DNSBL feed folder: every file of a feed whose parsed rows are there and
// that is no configured feed now is removed, the parsed rows last, so a failed removal leaves the feed for the next Update
// to find; the names of the feeds removed whole are returned. Its resource left the store with the publication.
// Departure: a stored row the settings do not project (a header repeated in an earlier group, a hidden group) is still
// configured today and keeps its files; Core cannot see it, so it counts as removed, and the caller raises an issue for it.
func (s DNSBLSet) cleanup(feeds []dnsbl.Feed) ([]string, error) {
	parsed, err := filepath.Glob(filepath.Join(s.FeedDir, "*.parsed.ndjson"))
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, p := range parsed {
		name := strings.TrimSuffix(filepath.Base(p), ".parsed.ndjson")
		if !feedstage.ValidName(name) || slices.ContainsFunc(feeds, func(f dnsbl.Feed) bool { return f.Name == name }) {
			continue
		}
		files, err := filepath.Glob(filepath.Join(s.FeedDir, name+".*"))
		if err != nil {
			return removed, err
		}
		files = append(slices.DeleteFunc(files, func(f string) bool { return f == p }), p)
		for _, f := range files {
			info, err := dnsblLstat(f)
			if errors.Is(err, fs.ErrNotExist) || err == nil && info.IsDir() {
				continue
			}
			if err != nil { // before the parsed rows, which come last: the next Update finds the feed again
				return removed, err
			}
			if err := dnsblRemove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return removed, err
			}
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// dnsblipLists reads DNSBLIP's lists (pfblockerng_apply.inc, "Collect all DNSBL IP feeds"): each family's side lists of
// the configured feeds concatenated in the order of today's <feed>_<v4|v6>.ip names, empty when there is none (no
// placeholder, owner 2026-11-23), in the class folder of DNSBLIP's action; none with the action Disabled.
func (s DNSBLSet) dnsblipLists(feeds []dnsbl.Feed, action string) ([]dnsblipList, error) {
	class := dnsblipClass(action)
	if class == "" {
		return nil, nil
	}
	var lists []dnsblipList
	for _, fam := range []struct {
		family string
		v      ipset.Family
	}{{"ipv4", ipset.V4}, {"ipv6", ipset.V6}} {
		var files []ipset.Feed
		read := map[string]bool{}
		for _, f := range feeds {
			if !feedstage.ValidName(f.Name) || read[f.Name] {
				continue
			}
			read[f.Name] = true
			b, err := os.ReadFile(filepath.Join(s.FeedDir, f.Name+".parsed."+string(fam.v)+".ip"))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			files = append(files, ipset.Feed{Name: f.Name + "_" + string(fam.v), Text: string(b)})
		}
		var body []byte
		if len(files) > 0 {
			body = []byte(ipset.DNSBLIP(fam.v, "", files).Content)
		}
		lists = append(lists, dnsblipList{GeoSet{Alias: "DNSBLIP_" + string(fam.v), Group: "DNSBLIP", Family: fam.family,
			Action: action, ListClass: class, Path: filepath.Join(s.ListDir, "DNSBLIP_"+string(fam.v)+".txt")}, body})
	}
	return lists, nil
}

// dnsblipClass is the list class of DNSBLIP's action, "" for none (Disabled).
func dnsblipClass(action string) string {
	verb, _, _ := strings.Cut(strings.TrimPrefix(action, "Alias_"), "_")
	return map[string]string{"Deny": "deny", "Permit": "permit", "Match": "match", "Native": "native"}[verb]
}

// standingDNSBLIP is DNSBLIP's sets as the last DNSBL build wrote their lists in listDir, for an Update that builds no
// DNSBL (an ip scope): unchanged; none while DNSBL is not active or DNSBLIP's action is Disabled, and none of a family
// whose list no build wrote.
func standingDNSBLIP(settings map[string]map[string]any, listDir string) []GeoSet {
	policy := settings["policy/dnsbl"]
	action := settingText(policy, "dnsblIpAction")
	class := dnsblipClass(action)
	sets := []GeoSet{}
	if !settingBool(policy, "enabled") || !settingBool(settings["dns"], "pfbDnsEnabled") || class == "" {
		return sets
	}
	for _, v := range []ipset.Family{ipset.V4, ipset.V6} {
		if _, err := os.Stat(filepath.Join(listDir, "DNSBLIP_"+string(v)+".txt")); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		sets = append(sets, GeoSet{Alias: "DNSBLIP_" + string(v), Group: "DNSBLIP", Family: "ip" + string(v), Action: action,
			ListClass: class, Path: filepath.Join(listDir, "DNSBLIP_"+string(v)+".txt")})
	}
	return sets
}

// writeDNSBLIP writes each list that changed, or removes both lists when there are none, and returns the sets.
func (s DNSBLSet) writeDNSBLIP(lists []dnsblipList) ([]GeoSet, error) {
	sets := []GeoSet{}
	if len(lists) == 0 {
		var err error
		for _, v := range []ipset.Family{ipset.V4, ipset.V6} {
			if e := os.Remove(filepath.Join(s.ListDir, "DNSBLIP_"+string(v)+".txt")); !errors.Is(e, fs.ErrNotExist) {
				err = errors.Join(err, e)
			}
		}
		return sets, err
	}
	for _, l := range lists {
		l.set.Changed = !sameContent(l.set.Path, l.body)
		if l.set.Changed {
			staged, err := stageFile(l.set.Path, l.body)
			if err != nil {
				return sets, err
			}
			if err := os.Rename(staged, l.set.Path); err != nil {
				os.Remove(staged)
				return sets, err
			}
		}
		sets = append(sets, l.set)
	}
	return sets, nil
}

// mechanismFlag is pfb_dnsbl_mechanism_flag(): a DNSBL logging mechanism as the manifest's log flag.
func mechanismFlag(mechanism string) string {
	if flag, ok := map[string]string{"disabled": "2", "nxdomain_log": "3", "nxdomain": "4", "nodata_log": "5", "nodata": "6"}[mechanism]; ok {
		return flag
	}
	return "0"
}

func settingText(m map[string]any, key string) string { v, _ := m[key].(string); return v }

func settingBool(m map[string]any, key string) bool { v, _ := m[key].(bool); return v }

// settingItems is the key of each item of a list field.
func settingItems(v any, key string) []string {
	var out []string
	for _, item := range rows(v) {
		out = append(out, settingText(item, key))
	}
	return out
}
