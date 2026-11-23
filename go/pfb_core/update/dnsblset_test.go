package update

// Sub-slice 9g (issue #4038): the group-level DNSBL work of an Update, DNSBLIP and the dnsbl/* publication. The feed order
// and attributes are today's pass (pfblockerng_apply.inc, the $lists walk and pfb_feed_manifest_row()); the bodies are
// slice 7a's assembler, checked against its parity fixture; the SafeSearch rows are dnsbl.SafeSearchTable's corpus.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

const testPSL = "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\nblogspot.com\n// ===END PRIVATE DOMAINS===\n"

// dnsblTree is a DNSBLSet over temporary folders: the feed folder, the list folder, the store, the shipped PSL and an empty
// SafeSearch folder.
func dnsblTree(t *testing.T) DNSBLSet {
	t.Helper()
	root := t.TempDir()
	s := DNSBLSet{Store: resources.Open(filepath.Join(root, "store")), FeedDir: filepath.Join(root, "dnsbl"),
		ListDir: filepath.Join(root, "db"), Top1m: filepath.Join(root, "db", "pfbalexawhitelist.txt"),
		PSL: filepath.Join(root, "psl.dat"), SafeSearchDir: filepath.Join(root, "pkg")}
	for _, d := range []string{s.FeedDir, s.ListDir, s.SafeSearchDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touch(t, s.PSL, testPSL)
	return s
}

// staged writes a feed's parsed rows as the per-feed stage publishes them.
func staged(t *testing.T, s DNSBLSet, name string, domains ...string) {
	t.Helper()
	var b strings.Builder
	for _, d := range domains {
		line, _ := json.Marshal([]string{"d", d})
		b.Write(append(line, '\n'))
	}
	touch(t, filepath.Join(s.FeedDir, name+".parsed.ndjson"), b.String())
}

func dnsblPolicy(extra map[string]any) map[string]any {
	p := map[string]any{"enabled": true, "logging": "disabled_log", "blacklistLogging": "disabled_log", "groups": []any{},
		"whitelist": []any{}, "top1m": false, "tldBlacklist": []any{}, "tldExclusions": []any{}, "safeSearch": false,
		"safeSearchYoutube": "Disable", "safeSearchDoh": false, "safeSearchDohList": []any{}, "dnsblIpAction": "Disabled"}
	maps.Copy(p, extra)
	return p
}

func dnsblSettings(groups []any, policy map[string]any) map[string]map[string]any {
	return map[string]map[string]any{"feeds/dnsbl": {"groups": groups}, "policy/dnsbl": policy, "dns": {"tldWildcard": false},
		"schedule": {"categoryUpdates": false, "categoryProviders": []any{}}}
}

func dnsblGroup(name, action string, custom string, feeds ...map[string]any) map[string]any {
	rows := []any{}
	for _, f := range feeds {
		rows = append(rows, f)
	}
	return map[string]any{"name": name, "action": action, "customList": custom, "feeds": rows}
}

func dnsblFeed(header, state, action string) map[string]any {
	return map[string]any{"header": header, "state": state, "url": "https://example.org/" + header, "action": action}
}

// manifest is dnsbl/manifest's rows by kind, the feed rows in position order.
func manifest(t *testing.T, store *resources.Store) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{}
	for _, line := range bodyLines(t, store, dnsbl.ManifestID) {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		kind := row["kind"].(string)
		delete(row, "kind")
		out[kind] = append(out[kind], row)
	}
	sort.SliceStable(out["feed"], func(i, j int) bool {
		return out["feed"][i]["position"].(float64) < out["feed"][j]["position"].(float64)
	})
	return out
}

func bodyLines(t *testing.T, store *resources.Store, id string) []string {
	t.Helper()
	reply, err := store.Get(id, nil)
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	f, _, err := store.Body(id, reply.Generation, "members", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return []string{}
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// WHEN DNSBL feeds are configured THEN they are published in today's walk order (primary groups first, the later one first;
// then the Blacklist categories; then the other groups), each group's rows then its custom list, with the group as
// DNSBL_<name>, its effective logging as the manifest flag, its TOP1M box, a permit row's mode and a custom list as user;
// a disabled group or row, and a feed without its parsed rows, are left out; the request's groups carry the entries and
// whether a feed of theirs was parsed this Update.
func TestTheFeedsArePublishedInTodaysWalkOrderWithTheirAttributes(t *testing.T) {
	s := dnsblTree(t)
	for _, name := range []string{"UT1_ads", "UT1_adult_x", "AdsA", "AdsP", "Ads_custom", "MalA", "PriA", "Pri2A", "OffA", "Gone"} {
		staged(t, s, name, strings.ToLower(name)+".example", "x."+strings.ToLower(name)+".example")
	}
	settings := dnsblSettings([]any{
		dnsblGroup("Ads", "unbound", "c.example", dnsblFeed("AdsA", "enabled", "deny"), dnsblFeed("AdsDis", "disabled", "deny"),
			dnsblFeed("AdsP", "hold", "permit"), dnsblFeed("AdsNone", "enabled", "deny")),
		dnsblGroup("Pri", "unbound", "", dnsblFeed("PriA", "flex", "deny")),
		dnsblGroup("Off", "Disabled", "", dnsblFeed("OffA", "enabled", "deny")),
		dnsblGroup("Mal", "unbound", "", dnsblFeed("MalA", "enabled", "deny")),
		dnsblGroup("Pri2", "unbound", "", dnsblFeed("Pri2A", "enabled", "deny")),
	}, dnsblPolicy(map[string]any{"logging": "nxdomain", "blacklistLogging": "nodata_log", "groups": []any{
		map[string]any{"name": "Ads", "logging": "disabled", "primary": false, "top1mFilter": true},
		map[string]any{"name": "Pri", "logging": "disabled_log", "primary": true, "top1mFilter": false},
		map[string]any{"name": "Mal", "logging": "nxdomain_log", "primary": false, "top1mFilter": false},
		map[string]any{"name": "Pri2", "logging": "nodata", "primary": true, "top1mFilter": false},
	}}))
	settings["schedule"] = map[string]any{"categoryUpdates": true, "categoryProviders": []any{
		map[string]any{"id": "ut1", "selected": true, "categories": "ads,adult-x", "title": "UT1"},
		map[string]any{"id": "sb", "selected": false, "categories": "a", "title": "SB"},
	}}

	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings, Changed: map[string]bool{"AdsP": true, "OffA": true}})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Feed, Group, LogFlag, Provenance, Mode string
		Top1m                                  bool
	}
	var got []row
	for _, f := range manifest(t, s.Store)["feed"] {
		got = append(got, row{f["feed"].(string), f["group"].(string), f["logFlag"].(string), f["provenance"].(string),
			f["mode"].(string), f["top1m"].(bool)})
	}
	want := []row{
		{"Pri2A", "DNSBL_Pri2", "6", "feed", "deny", false},
		{"PriA", "DNSBL_Pri", "0", "feed", "deny", false},
		{"UT1_ads", "DNSBL_UT1", "5", "feed", "deny", false},
		{"UT1_adult_x", "DNSBL_UT1", "5", "feed", "deny", false},
		{"AdsA", "DNSBL_Ads", "2", "feed", "deny", true},
		{"AdsP", "DNSBL_Ads", "2", "feed", "permit", true},
		{"Ads_custom", "DNSBL_Ads", "2", "user", "deny", true},
		{"MalA", "DNSBL_Mal", "3", "feed", "deny", false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("manifest feed rows\n got %+v\nwant %+v", got, want)
	}
	if lines := bodyLines(t, s.Store, dnsbl.FeedPrefix+"AdsP"); !slices.Equal(lines, []string{"adsp.example", "x.adsp.example"}) {
		t.Errorf("dnsbl/feed-AdsP = %q, want the parsed rows", lines)
	}
	wantGroups := []apply.Group{{Name: "DNSBL_Pri2", Entries: 2}, {Name: "DNSBL_Pri", Entries: 2}, {Name: "DNSBL_UT1", Entries: 4},
		{Name: "DNSBL_Ads", Entries: 6, Changed: true}, {Name: "DNSBL_Mal", Entries: 2}}
	reply, err := s.Store.Get(dnsbl.ManifestID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.DNSBL == nil || out.DNSBL.Generation != reply.Generation || !reflect.DeepEqual(out.DNSBL.Groups, wantGroups) {
		t.Errorf("DNSBL = %+v, want generation %d and groups %+v", out.DNSBL, reply.Generation, wantGroups)
	}
	// Gone is configured nowhere and OffA's group is Disabled: their files are removed, each with an issue
	var wantIssues []apply.Issue
	for _, name := range []string{"Gone", "OffA"} {
		wantIssues = append(wantIssues, apply.Issue{Resource: "feed/dnsbl:" + name, Stage: "parse", Code: "feed_files_removed",
			Message: "no configured feed names it, so its files are removed (a row the settings do not project counts as removed)"})
	}
	if !reflect.DeepEqual(out.Issues, wantIssues) {
		t.Errorf("issues\n got %+v\nwant %+v", out.Issues, wantIssues)
	}
}

// WHEN DNSBL is configured THEN the manifest's config, whitelist and TLD rows come from the settings: the built-in log flag is
// the global mechanism's, the TLD lists ride only while dns.tldWildcard is on, and the unlock set is empty (a full build
// clears it, as today's writer does).
func TestTheManifestConfigRowsComeFromTheSettings(t *testing.T) {
	for _, c := range []struct {
		logging, flag string
		wildcard      bool
	}{{"disabled_log", "0", true}, {"disabled", "2", false}, {"nxdomain_log", "3", true}, {"nxdomain", "4", false},
		{"nodata_log", "5", true}, {"nodata", "6", false}} {
		t.Run(c.logging, func(t *testing.T) {
			s := dnsblTree(t)
			settings := dnsblSettings([]any{}, dnsblPolicy(map[string]any{"logging": c.logging,
				"whitelist":     []any{map[string]any{"domain": ".w.example"}, map[string]any{"domain": "v.example"}},
				"tldBlacklist":  []any{map[string]any{"tld": "zip"}},
				"tldExclusions": []any{map[string]any{"domain": "ok.zip"}}}))
			settings["dns"] = map[string]any{"tldWildcard": c.wildcard}
			if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err != nil {
				t.Fatal(err)
			}
			m := manifest(t, s.Store)
			want := map[string][]map[string]any{
				"config":    {{"builtinLogFlag": c.flag, "top1mEnabled": false}},
				"whitelist": {{"domain": ".w.example"}, {"domain": "v.example"}},
				"member":    {{"resource": dnsbl.PSLID}},
			}
			if c.wildcard {
				want["tld_blacklist"] = []map[string]any{{"tld": "zip"}}
				want["tld_exclusion"] = []map[string]any{{"domain": "ok.zip"}}
			}
			for _, r := range m["member"] {
				for _, k := range []string{"generation", "digest", "entries"} {
					delete(r, k)
				}
			}
			if !reflect.DeepEqual(m, want) {
				t.Errorf("manifest rows\n got %v\nwant %v", m, want)
			}
			if lines := bodyLines(t, s.Store, dnsbl.PSLID); len(lines) != 2 {
				t.Errorf("dnsbl/psl = %q, want the shipped PSL's two rules", lines)
			}
		})
	}
}

// WHEN TOP1M is on THEN dnsbl/top1m is the Extras stage's list; WHEN its list is missing THEN the build fails and nothing
// is published, as today's writer fails closed; WHEN TOP1M is off THEN no TOP1M body is published, though the list is there.
func TestTop1mIsPublishedOnlyWhileItIsOn(t *testing.T) {
	s := dnsblTree(t)
	touch(t, s.Top1m, "a.example\nb.example\n")
	on := dnsblSettings([]any{}, dnsblPolicy(map[string]any{"top1m": true}))
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: on}); err != nil {
		t.Fatal(err)
	}
	if lines := bodyLines(t, s.Store, dnsbl.Top1mID); !slices.Equal(lines, []string{"a.example", "b.example"}) {
		t.Errorf("dnsbl/top1m = %q, want the TOP1M list", lines)
	}
	if c := manifest(t, s.Store)["config"]; c[0]["top1mEnabled"] != true {
		t.Errorf("config row %v, want top1mEnabled", c)
	}
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: dnsblSettings([]any{}, dnsblPolicy(nil))}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Get(dnsbl.Top1mID, nil); !errors.Is(err, resources.ErrNotFound) {
		t.Errorf("dnsbl/top1m with TOP1M off: %v, want not found", err)
	}

	before, _ := s.Store.Get(dnsbl.ManifestID, nil)
	os.Remove(s.Top1m)
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: on}); err == nil {
		t.Error("TOP1M on without its list: no error")
	}
	if after, _ := s.Store.Get(dnsbl.ManifestID, nil); after.Generation != before.Generation {
		t.Errorf("manifest generation %d after the failed build, want %d", after.Generation, before.Generation)
	}
}

// WHEN SafeSearch is on THEN dnsbl/safesearch holds its rows; a row of the wrong shape is left out with an issue; WHEN it is
// off THEN no SafeSearch body is published.
func TestSafeSearchIsPublishedWithAnIssueForARowOfTheWrongShape(t *testing.T) {
	s := dnsblTree(t)
	touch(t, filepath.Join(s.SafeSearchDir, "pfb_dnsbl.safesearch.conf"),
		"local-data: \"ok.example A 192.0.2.5\"\nlocal-data: \"a,b.example A 192.0.2.1\"\n")
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: dnsblSettings([]any{}, dnsblPolicy(nil))}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.Get(dnsbl.SafeSearchID, nil); !errors.Is(err, resources.ErrNotFound) {
		t.Errorf("dnsbl/safesearch with SafeSearch off: %v, want not found", err)
	}
	out, err := s.Build(context.Background(), DNSBLInput{Settings: dnsblSettings([]any{}, dnsblPolicy(map[string]any{"safeSearch": true}))})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`{"host":"ok.example","a":"192.0.2.5","aaaa":""}`, `{"host":"www.ok.example","a":"192.0.2.5","aaaa":""}`}
	if lines := bodyLines(t, s.Store, dnsbl.SafeSearchID); !slices.Equal(lines, want) {
		t.Errorf("dnsbl/safesearch = %q, want %q", lines, want)
	}
	wantIssues := []apply.Issue{{Resource: dnsbl.SafeSearchID, Stage: "parse", Code: "safesearch_row_refused",
		Message: `a SafeSearch row of the wrong shape is left out: host "a,b.example"`}}
	if !reflect.DeepEqual(out.Issues, wantIssues) {
		t.Errorf("issues = %+v, want %+v", out.Issues, wantIssues)
	}
}

// WHEN 7a's parity cases are staged as the per-feed stage publishes them THEN each feed body holds the fixture's rows, and
// every row left out (a staged line ReadStaged skips, a row the store cannot hold) and every refused name raises an issue.
func TestFeedBodiesAndLeftOutRowsMatchTheAssemblerParityFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "core", "fixtures", "dnsbl_resources_parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			ID    string
			Feeds []struct {
				Header string
				Staged []json.RawMessage
			}
			Top1m  string
			Expect struct {
				Feeds []struct {
					Feed string
					Rows []string
				}
				Error string
			}
			Refused []string
			Invalid map[string]int
			Dropped map[string]int
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Cases) < 10 {
		t.Fatalf("fixture: %v, %d cases", err, len(doc.Cases))
	}
	ran := 0
	for _, c := range doc.Cases {
		headers := map[string]bool{}
		dup := false
		for _, f := range c.Feeds {
			dup = dup || headers[f.Header]
			headers[f.Header] = true
		}
		if c.Expect.Error != "" || c.Top1m != "" || dup {
			continue // TOP1M without its list is TestTop1mIsPublishedOnlyWhileItIsOn's; one file cannot hold two feeds' rows
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			s := dnsblTree(t)
			var feeds []map[string]any
			for _, f := range c.Feeds {
				var text strings.Builder
				for _, line := range f.Staged {
					var str string
					var b struct{ B64 []byte }
					if json.Unmarshal(line, &str) != nil {
						if err := json.Unmarshal(line, &b); err != nil {
							t.Fatal(err)
						}
						str = string(b.B64)
					}
					text.WriteString(str + "\n")
				}
				if feedNameOK(f.Header) {
					touch(t, filepath.Join(s.FeedDir, f.Header+".parsed.ndjson"), text.String())
				}
				feeds = append(feeds, dnsblFeed(f.Header, "enabled", "deny"))
			}
			out, err := s.Build(context.Background(), DNSBLInput{Settings: dnsblSettings([]any{dnsblGroup("G", "unbound", "", feeds...)}, dnsblPolicy(nil))})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range c.Expect.Feeds {
				if lines := bodyLines(t, s.Store, dnsbl.FeedPrefix+f.Feed); !slices.Equal(lines, f.Rows) && len(lines)+len(f.Rows) > 0 {
					t.Errorf("dnsbl/feed-%s = %q, want %q", f.Feed, lines, f.Rows)
				}
			}
			want := []apply.Issue{}
			for _, f := range c.Feeds {
				if slices.Contains(c.Refused, f.Header) {
					want = append(want, apply.Issue{Resource: "feed/dnsbl:" + f.Header, Stage: "parse", Code: "feed_name_refused",
						Message: "the feed's name cannot name a dnsbl resource: the feed is left out"})
				} else if n := c.Invalid[f.Header] + c.Dropped[dnsbl.FeedPrefix+f.Header]; n > 0 {
					want = append(want, apply.Issue{Resource: "feed/dnsbl:" + f.Header, Stage: "parse", Code: "rows_left_out",
						Message: fmt.Sprintf("%d rows are left out: the store cannot hold them", n)})
				}
			}
			if got := append([]apply.Issue{}, out.Issues...); !reflect.DeepEqual(got, want) {
				t.Errorf("issues\n got %+v\nwant %+v", got, want)
			}
		})
	}
	if ran < 8 {
		t.Fatalf("%d parity cases ran, want at least 8", ran)
	}
}

func feedNameOK(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/.-")
}

// WHEN DNSBLIP is on THEN its lists are the DNSBL feeds' side lists concatenated in today's order (by the name of the
// <feed>_v4.ip file), in the folder of its action's class: no placeholder when there is none; Changed only when the list
// changed; WHEN it is off THEN its lists are removed and DNSBLIP is empty, not nil, so the IP sets prune its old lists.
func TestDNSBLIPIsBuiltFromTheFeedsSideLists(t *testing.T) {
	s := dnsblTree(t)
	staged(t, s, "A", "a.example")
	staged(t, s, "A_b", "ab.example")
	touch(t, filepath.Join(s.FeedDir, "A.parsed.v4.ip"), "192.0.2.1\n")
	touch(t, filepath.Join(s.FeedDir, "A_b.parsed.v4.ip"), "192.0.2.2\n")
	touch(t, filepath.Join(s.FeedDir, "A_b.parsed.v6.ip"), "2001:db8::2\n")
	settings := dnsblSettings([]any{dnsblGroup("G", "unbound", "", dnsblFeed("A", "enabled", "deny"), dnsblFeed("A_b", "enabled", "deny"))},
		dnsblPolicy(map[string]any{"dnsblIpAction": "Alias_Native"}))

	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	want := []GeoSet{
		{Alias: "DNSBLIP_v4", Group: "DNSBLIP", Family: "ipv4", Action: "Alias_Native", ListClass: "native", Path: filepath.Join(s.ListDir, "DNSBLIP_v4.txt"), Changed: true},
		{Alias: "DNSBLIP_v6", Group: "DNSBLIP", Family: "ipv6", Action: "Alias_Native", ListClass: "native", Path: filepath.Join(s.ListDir, "DNSBLIP_v6.txt"), Changed: true},
	}
	if !reflect.DeepEqual(out.DNSBLIP, want) {
		t.Errorf("DNSBLIP\n got %+v\nwant %+v", out.DNSBLIP, want)
	}
	// "A_b_v4.ip" sorts before "A_v4.ip": today's glob order
	for path, text := range map[string]string{want[0].Path: "192.0.2.2\n192.0.2.1\n", want[1].Path: "2001:db8::2\n"} {
		if b, err := os.ReadFile(path); err != nil || string(b) != text {
			t.Errorf("%s = %q (%v), want %q", path, b, err, text)
		}
	}

	out, err = s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if out.DNSBLIP[0].Changed || out.DNSBLIP[1].Changed {
		t.Errorf("DNSBLIP rebuilt unchanged: %+v, want Changed false", out.DNSBLIP)
	}

	os.Remove(filepath.Join(s.FeedDir, "A_b.parsed.v6.ip"))
	out, err = s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(want[1].Path); err != nil || len(b) != 0 || !out.DNSBLIP[1].Changed {
		t.Errorf("DNSBLIP_v6 without a side list = %q (%v), changed %v; want empty, no placeholder, changed", b, err, out.DNSBLIP[1].Changed)
	}

	settings["policy/dnsbl"]["dnsblIpAction"] = "Disabled"
	out, err = s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if out.DNSBLIP == nil || len(out.DNSBLIP) != 0 {
		t.Errorf("DNSBLIP off = %#v, want empty and not nil", out.DNSBLIP)
	}
	for _, p := range []string{want[0].Path, want[1].Path} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s with DNSBLIP off: %v, want removed", p, err)
		}
	}
}

// WHEN a DNSBL feed leaves the configuration (its row or group removed or disabled, or its Blacklist category deselected)
// THEN its files are removed from the feed folder, as today's removed-list cleanup does, and its body leaves the store;
// a configured feed's files, a file of no feed and another folder's files stay. WHEN DNSBL is off THEN every dnsbl/*
// resource leaves the store and no DNSBL object is given to the apply.
func TestARemovedFeedIsCleanedUpAndDNSBLOffRemovesEveryResource(t *testing.T) {
	s := dnsblTree(t)
	for _, name := range []string{"Keep", "Gone", "Dis", "UT1_x"} {
		staged(t, s, name, strings.ToLower(name)+".example")
		touch(t, filepath.Join(s.FeedDir, name+".orig"), "raw\n")
	}
	touch(t, filepath.Join(s.FeedDir, "README"), "not a feed\n")
	touch(t, filepath.Join(s.FeedDir, "Keep_b.orig"), "raw\n")
	settings := dnsblSettings([]any{dnsblGroup("G", "unbound", "", dnsblFeed("Keep", "enabled", "deny"), dnsblFeed("Gone", "enabled", "deny"),
		dnsblFeed("Dis", "enabled", "deny"))}, dnsblPolicy(nil))
	settings["schedule"] = map[string]any{"categoryUpdates": true, "categoryProviders": []any{
		map[string]any{"id": "ut1", "selected": true, "categories": "x", "title": "UT1"}}}
	if _, err := s.Build(context.Background(), DNSBLInput{Settings: settings}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"Keep", "Gone", "Dis", "UT1_x"} {
		if _, err := s.Store.Get(dnsbl.FeedPrefix+id, nil); err != nil {
			t.Fatalf("%s before the removal: %v", id, err)
		}
	}

	settings["feeds/dnsbl"]["groups"] = []any{dnsblGroup("G", "unbound", "", dnsblFeed("Keep", "enabled", "deny"), dnsblFeed("Dis", "disabled", "deny"))}
	settings["schedule"]["categoryProviders"] = []any{map[string]any{"id": "ut1", "selected": false, "categories": "x", "title": "UT1"}}
	out, err := s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(s.FeedDir, "*"))
	for i := range left {
		left[i] = filepath.Base(left[i])
	}
	if want := []string{"Keep.orig", "Keep.parsed.ndjson", "Keep_b.orig", "README"}; !slices.Equal(left, want) {
		t.Errorf("feed folder = %q, want %q", left, want)
	}
	held, _ := s.Store.IDs("dnsbl/")
	if want := []string{dnsbl.FeedPrefix + "Keep", dnsbl.ManifestID, dnsbl.PSLID}; !slices.Equal(held, want) {
		t.Errorf("store = %q, want %q", held, want)
	}
	if out.DNSBL == nil {
		t.Fatal("DNSBL on: no DNSBL object")
	}

	settings["policy/dnsbl"]["enabled"] = false
	out, err = s.Build(context.Background(), DNSBLInput{Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Store.IDs("dnsbl/"); len(held) != 0 || out.DNSBL != nil {
		t.Errorf("DNSBL off: store holds %q, DNSBL %+v; want nothing", held, out.DNSBL)
	}
	if _, err := os.Stat(filepath.Join(s.FeedDir, "Keep.parsed.ndjson")); err != nil {
		t.Errorf("DNSBL off removed a configured feed's rows: %v", err)
	}
}
