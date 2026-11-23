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
// removed-list cleanup of the DNSBL feed folder, DNSBLIP's lists, and the dnsbl/* publication through slice 7a's assembler
// with the feeds the per-feed stage parsed, the settings' whitelist, TLD and logging inputs, TOP1M, SafeSearch and the PSL.
// Every path is the caller's.
type DNSBLSet struct {
	Store         *resources.Store
	FeedDir       string         // the DNSBL feed folder: the per-feed stage's Paths.FeedDir for dnsbl feeds ($pfb['dnsdir'])
	ListDir       string         // where DNSBLIP_v4.txt and DNSBLIP_v6.txt are written ($pfb['dbdir'])
	Top1m         string         // the TOP1M whitelist the Extras stage writes (pfbalexawhitelist.txt)
	PSL           string         // the PSL authority the package ships
	SafeSearchDir string         // the folder of the package's SafeSearch lists, pfb_dnsbl.<name>.conf
	Resolve       dnsbl.Resolver // the SafeSearch CNAME targets' lookup; nil resolves nothing
}

// DNSBLInput is what one Update hands the DNSBL build.
type DNSBLInput struct {
	// Settings are the snapshot's projections: feeds/dnsbl, policy/dnsbl, dns and schedule (the Blacklist categories).
	Settings map[string]map[string]any
	Changed  map[string]bool // the DNSBL feeds (their names) the per-feed stage parsed this Update
}

// DNSBLOut is what the DNSBL build gives the rest of the Update.
type DNSBLOut struct {
	DNSBL *apply.DNSBL // the apply request's dnsbl: the manifest's generation and the groups; nil while DNSBL is off
	// DNSBLIP is IPInput.DNSBLIP for the IP sets (sub-slice 9h): never nil, empty while DNSBLIP is off, so that the IP sets'
	// prune removes its lists from the class folders.
	DNSBLIP []GeoSet
	Issues  []apply.Issue
}

// Build runs the DNSBL build of one Update. With policy/dnsbl.enabled off it publishes nothing and removes every dnsbl/*
// resource. An error leaves the published DNSBL data as it was.
func (s DNSBLSet) Build(ctx context.Context, in DNSBLInput) (DNSBLOut, error) {
	policy := in.Settings["policy/dnsbl"]
	feeds := dnsblFeeds(in.Settings)
	out := DNSBLOut{}
	if err := s.cleanup(feeds); err != nil {
		return out, err
	}
	var err error
	if out.DNSBLIP, err = s.dnsblip(feeds, settingText(policy, "dnsblIpAction")); err != nil {
		return out, err
	}
	if !settingBool(policy, "enabled") {
		held, err := s.Store.IDs("dnsbl/")
		for _, id := range held {
			err = errors.Join(err, s.Store.Remove(id))
		}
		return out, err
	}

	set := dnsbl.Set{BuiltinLogFlag: mechanismFlag(settingText(policy, "logging")), Top1mEnabled: settingBool(policy, "top1m"),
		Whitelist: settingItems(policy["whitelist"], "domain"), TLDWildcard: settingBool(in.Settings["dns"], "tldWildcard"),
		TLDBlacklist: settingItems(policy["tldBlacklist"], "tld"), TLDExclusions: settingItems(policy["tldExclusions"], "domain")}
	if set.Top1mEnabled {
		if b, err := os.ReadFile(s.Top1m); err == nil { // a missing list fails the publication, as today's writer does
			set.Top1m = slices.DeleteFunc(strings.Split(string(b), "\n"), func(l string) bool { return l == "" })
		}
	}
	if set.PSL, err = os.ReadFile(s.PSL); err != nil {
		return out, err
	}
	var ssRefused []string
	set.SafeSearch, ssRefused = dnsbl.SafeSearchTable(ctx, s.SafeSearchDir, dnsbl.SafeSearchPolicy{Enable: settingBool(policy, "safeSearch"),
		YouTube: settingText(policy, "safeSearchYoutube"), DoH: settingBool(policy, "safeSearchDoh"),
		DoHList: settingItems(policy["safeSearchDohList"], "host")}, s.Resolve)

	invalid, refused := map[string]int{}, map[string]bool{}
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
	res, err := dnsbl.Publish(s.Store, set)
	if err != nil {
		return out, err
	}
	for _, name := range res.Refused {
		refused[name] = true
	}

	issue := func(resource, code, message string) {
		out.Issues = append(out.Issues, apply.Issue{Resource: resource, Stage: "parse", Code: code, Message: message})
	}
	reported := map[string]bool{}
	for _, f := range feeds {
		if reported[f.Name] {
			continue
		}
		reported[f.Name] = true
		if refused[f.Name] {
			issue("feed/dnsbl:"+f.Name, "feed_name_refused", "the feed's name cannot name a dnsbl resource: the feed is left out")
		} else if n := invalid[f.Name] + res.Dropped[dnsbl.FeedPrefix+f.Name]; n > 0 {
			issue("feed/dnsbl:"+f.Name, "rows_left_out", fmt.Sprintf("%d rows are left out: the store cannot hold them", n))
		}
	}
	for _, id := range []string{dnsbl.Top1mID, dnsbl.SafeSearchID, dnsbl.PSLID} {
		if n := res.Dropped[id]; n > 0 {
			issue(id, "rows_left_out", fmt.Sprintf("%d rows are left out: the store cannot hold them", n))
		}
	}
	for _, host := range ssRefused {
		issue(dnsbl.SafeSearchID, "safesearch_row_refused", fmt.Sprintf("a SafeSearch row of the wrong shape is left out: host %q", host))
	}

	reply, err := s.Store.Get(dnsbl.ManifestID, nil)
	if err != nil {
		return out, err
	}
	var meta struct{ Groups []apply.Group }
	if err := json.Unmarshal(reply.Metadata, &meta); err != nil {
		return out, err
	}
	for i, g := range meta.Groups {
		meta.Groups[i].Changed = slices.ContainsFunc(set.Feeds, func(f dnsbl.Feed) bool { return f.Group == g.Name && in.Changed[f.Name] })
	}
	out.DNSBL = &apply.DNSBL{Generation: res.Generation, Groups: meta.Groups}
	return out, nil
}

// dnsblFeeds are the configured DNSBL feeds, without rows, in today's walk order ($lists, pfblockerng_apply.inc): each
// primary group put first, so the last primary group leads; then the selected Blacklist categories; then the other groups.
// A group's feeds are its rows that are not disabled and have a source, then its custom list; a group is DNSBL_<name>.
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
// that is no configured feed now is removed. Its resource leaves the store when the next publication no longer names it.
func (s DNSBLSet) cleanup(feeds []dnsbl.Feed) error {
	parsed, err := filepath.Glob(filepath.Join(s.FeedDir, "*.parsed.ndjson"))
	if err != nil {
		return err
	}
	for _, p := range parsed {
		name := strings.TrimSuffix(filepath.Base(p), ".parsed.ndjson")
		if !feedstage.ValidName(name) || slices.ContainsFunc(feeds, func(f dnsbl.Feed) bool { return f.Name == name }) {
			continue
		}
		files, err := filepath.Glob(filepath.Join(s.FeedDir, name+".*"))
		if err != nil {
			return err
		}
		for _, f := range files {
			if info, err := os.Lstat(f); err == nil && !info.IsDir() {
				if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}
		}
	}
	return nil
}

// dnsblip writes DNSBLIP's lists (pfblockerng_apply.inc, "Collect all DNSBL IP feeds"): each family's side lists of the
// configured feeds concatenated in the order of today's <feed>_<v4|v6>.ip names, empty when there is none (no placeholder,
// owner 2026-11-23), in the class folder of DNSBLIP's action; with the action Disabled the lists are removed.
func (s DNSBLSet) dnsblip(feeds []dnsbl.Feed, action string) ([]GeoSet, error) {
	sets := []GeoSet{}
	verb := strings.TrimPrefix(action, "Alias_")
	verb, _, _ = strings.Cut(verb, "_")
	class := map[string]string{"Deny": "deny", "Permit": "permit", "Match": "match", "Native": "native"}[verb]
	for _, fam := range []struct {
		family string
		v      ipset.Family
	}{{"ipv4", ipset.V4}, {"ipv6", ipset.V6}} {
		path := filepath.Join(s.ListDir, "DNSBLIP_"+string(fam.v)+".txt")
		if class == "" {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			continue
		}
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
		list := ipset.DNSBLIP(fam.v, "", files)
		if list.Sources == nil {
			list.Content = ""
		}
		changed := !sameContent(path, []byte(list.Content))
		if changed {
			staged, err := stageFile(path, []byte(list.Content))
			if err != nil {
				return nil, err
			}
			if err := os.Rename(staged, path); err != nil {
				os.Remove(staged)
				return nil, err
			}
		}
		sets = append(sets, GeoSet{Alias: "DNSBLIP_" + string(fam.v), Group: "DNSBLIP", Family: fam.family, Action: action,
			ListClass: class, Path: path, Changed: changed})
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
