package worklist

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// corpusFile is the work-list corpus shared with today's pfblockerng_sync_cron() and pfb_update_check(), replayed there by
// tests/php/UpdateLoopWorklistCorpusTest.php through pfb_core_update_run(). Where Core differs on purpose a case keeps
// today's answer in old_expect and says why in departure; this runner asserts expect.
const corpusFile = "../../../../tests/updateloop/fixtures/worklist/scenarios.json"

type corpusFeed struct {
	Header string `json:"header"`
	State  string `json:"state"`
	Format string `json:"format"`
	// Source is the probe's answer for a remote feed (304, same, changed, failed), or a whois or asn feed's source.
	Source string `json:"source"`
}

type corpusGroup struct {
	Kind      string       `json:"kind"`
	Name      string       `json:"name"`
	Action    string       `json:"action"`
	Frequency string       `json:"frequency"`
	Feeds     []corpusFeed `json:"feeds"`
}

// corpusFiles is what a feed holds before the run: a baseline (true, false or "dir"), a published list and the markers.
type corpusFiles struct {
	Orig   any   `json:"orig"`
	List   *bool `json:"list"`
	Fail   bool  `json:"fail"`
	Update bool  `json:"update"`
}

type corpusExpect struct {
	Checked  []string          `json:"checked"`
	Outcomes map[string]string `json:"outcomes"`
	Changes  map[string]string `json:"changes"`
	Fail     []string          `json:"fail"`
	Stopped  []string          `json:"stopped"`
	Apply    string            `json:"apply"`
}

type corpusRequest struct {
	Trigger string   `json:"trigger"`
	Scope   string   `json:"scope"`
	Force   string   `json:"force"`
	Feeds   []string `json:"feeds"`
	Extras  []string `json:"extras"`
}

type corpusCase struct {
	ID            string                 `json:"id"`
	Description   string                 `json:"description"`
	Request       corpusRequest          `json:"request"`
	Groups        []corpusGroup          `json:"groups"`
	Files         map[string]corpusFiles `json:"files"`
	Window        string                 `json:"window"`
	PendingApply  bool                   `json:"pendingApply"`
	ExtrasChanged bool                   `json:"extrasChanged"`
	Continent     string                 `json:"continent"`
	SkipFeed      int                    `json:"skipfeed"`
	Failures      map[string]int         `json:"failures"`
	Folder        string                 `json:"folder"`
	Expect        corpusExpect           `json:"expect"`
	OldExpect     json.RawMessage        `json:"old_expect"`
	Departure     string                 `json:"departure"`
}

type corpusDoc struct {
	Schema   int          `json:"schema"`
	Baseline string       `json:"baseline"`
	Changed  string       `json:"changed"`
	ETag     string       `json:"etag"`
	Cases    []corpusCase `json:"cases"`
	NotValid []struct {
		Trigger string `json:"trigger"`
		Scope   string `json:"scope"`
		Force   string `json:"force"`
		Why     string `json:"why"`
	} `json:"notValid"`
}

func loadCorpus(t *testing.T) corpusDoc {
	t.Helper()
	raw, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc corpusDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Schema != 1 || len(doc.Cases) == 0 || doc.Baseline == "" || doc.ETag == "" {
		t.Fatalf("scenarios.json: schema 1, a baseline, an etag and a case list, strictly (%v)", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Cases {
		if c.ID == "" || c.Description == "" || seen[c.ID] || (len(c.OldExpect) != 0) != (c.Departure != "") ||
			c.Expect.Apply == "" || (c.Window != "" && c.Window != "outside") || (c.Folder != "" && c.Folder != "link") {
			t.Fatalf("case %q: a unique id, a description, an apply decision, old_expect only with a departure, window "+
				"outside and folder link when present", c.ID)
		}
		seen[c.ID] = true
	}
	return doc
}

// TestCorpusCoversTheRequestMatrix holds the corpus to the issue's matrix: every trigger by scope by force is a case or a
// recorded "not valid", never both and never neither.
func TestCorpusCoversTheRequestMatrix(t *testing.T) {
	doc := loadCorpus(t)
	cases := map[string]bool{}
	for _, c := range doc.Cases {
		r := c.Request
		if r.Trigger == "manual" {
			cases["manual/"+r.Scope+"/"+r.Force] = true
		} else {
			cases[r.Trigger] = true
		}
	}
	notValid := map[string]bool{}
	for _, n := range doc.NotValid {
		if n.Why == "" || n.Trigger == "manual" || (n.Scope == "") == (n.Force == "") {
			t.Fatalf("not valid %+v: a reason, a trigger other than manual, and one of scope or force", n)
		}
		notValid[n.Trigger+"/"+n.Scope+"/"+n.Force] = true
	}
	for _, trigger := range []string{"scheduled", "retry", "apply"} {
		if !cases[trigger] {
			t.Errorf("no case for trigger %s", trigger)
		}
		for _, scope := range []string{"ip", "dnsbl", "both"} {
			if !notValid[trigger+"/"+scope+"/"] {
				t.Errorf("trigger %s with scope %s is neither a case nor recorded as not valid", trigger, scope)
			}
		}
		for _, force := range []string{"none", "parse", "download", "both"} {
			if !notValid[trigger+"//"+force] {
				t.Errorf("trigger %s with force %s is neither a case nor recorded as not valid", trigger, force)
			}
		}
	}
	for _, scope := range []string{"ip", "dnsbl", "both"} {
		for _, force := range []string{"none", "parse", "download", "both"} {
			if !cases["manual/"+scope+"/"+force] {
				t.Errorf("no case for manual scope %s force %s", scope, force)
			}
		}
	}
}

// probeServer answers each feed's path as the case says, with the router semantics of the PHP runner
// (tests/php/support/FeedFetchCorpusRouter.php): an etag route is a 304 to a matching If-None-Match.
func probeServer(t *testing.T, doc corpusDoc, c corpusCase) *httptest.Server {
	answers := map[string]string{}
	for _, g := range c.Groups {
		for _, f := range g.Feeds {
			answers["/"+g.Kind+"_"+f.Header] = f.Source
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch answers[r.URL.Path] {
		case "304":
			w.Header().Set("ETag", doc.ETag)
			if r.Header.Get("If-None-Match") == doc.ETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(doc.Baseline))
		case "same":
			_, _ = w.Write([]byte(doc.Baseline))
		case "changed":
			_, _ = w.Write([]byte(doc.Changed))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("err\n"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// remotePolicy resolves every feed host as the PHP runner does: to the server and to an address that is not the box's, so
// the probe reaches the server as a remote feed. A host of the box's addresses alone is a self-hosted feed, never probed.
func remotePolicy() feedfetch.Policy {
	return feedfetch.Policy{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.5")}, nil
	}}
}

// remoteURL is the server's URL under the feed host name remotePolicy resolves.
func remoteURL(srv *httptest.Server) string {
	return "http://feed.example:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:]
}

func suffixOf(kind string) string {
	return map[string]string{"ipv4": "_v4", "ipv6": "_v6"}[kind]
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// listNames are the published lists a feed's run leaves (feedstage), which stand for today's "<header>.txt".
func listNames(kind, name string) []string {
	if kind == "dnsbl" {
		return []string{name + ".parsed.ndjson", name + ".parsed.v4.ip", name + ".parsed.v6.ip"}
	}
	return []string{name + ".parsed.ip"}
}

// corpusInput lays the case's files out in a temporary tree and builds the settings and stages Build reads.
func corpusInput(t *testing.T, doc corpusDoc, c corpusCase) (Input, map[string]string) {
	t.Helper()
	root := t.TempDir()
	ipDir, dnsblDir := filepath.Join(root, "ip"), filepath.Join(root, "dnsbl")
	for _, d := range []string{ipDir, dnsblDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if c.Folder == "link" {
		if err := os.Rename(ipDir, ipDir+".real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ipDir+".real", ipDir); err != nil {
			t.Fatal(err)
		}
	}
	dirs := map[string]string{"ipv4": ipDir, "ipv6": ipDir, "dnsbl": dnsblDir}
	srv := probeServer(t, doc, c)
	fetcher := &feedfetch.Fetcher{Policy: remotePolicy(), RetryDelay: 1}
	stages := map[string]*feedstage.Stage{}
	for kind, dir := range dirs {
		stages[kind] = &feedstage.Stage{Paths: feedstage.Paths{FeedDir: dir}, Fetcher: fetcher}
	}
	settings := map[string]map[string]any{}
	for _, kind := range []string{"ipv4", "ipv6", "dnsbl"} {
		settings["feeds/"+kind] = map[string]any{"groups": []any{}}
	}
	geoip := []any{}
	for _, name := range []string{"pfB_Top", "pfB_Africa", "pfB_Antarctica", "pfB_Asia", "pfB_Europe", "pfB_NAmerica",
		"pfB_Oceania", "pfB_SAmerica", "pfB_PS"} {
		action := "Disabled"
		if name == "pfB_Top" && c.Continent != "" {
			action = c.Continent
		}
		geoip = append(geoip, map[string]any{"name": name, "action": action, "listClass": "none", "countriesV4": []any{},
			"countriesV6": []any{}})
	}
	settings["feeds/geoip"] = map[string]any{"groups": geoip}
	digestBaseline := digest.Bytes([]byte(doc.Baseline))
	for _, g := range c.Groups {
		feeds := []any{}
		for _, f := range g.Feeds {
			id := g.Kind + ":" + f.Header + suffixOf(g.Kind)
			url := f.Source
			if f.Format == "auto" {
				url = remoteURL(srv) + "/" + g.Kind + "_" + f.Header
			}
			feeds = append(feeds, map[string]any{"header": f.Header, "state": f.State, "format": f.Format, "url": url,
				"credentials": ""})
			files := c.Files[id]
			dir, name := dirs[g.Kind], f.Header+suffixOf(g.Kind)
			base := filepath.Join(dir, name)
			switch files.Orig {
			case nil, true:
				writeFile(t, base+".orig", doc.Baseline)
			case "dir":
				if err := os.Mkdir(base+".orig", 0o700); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(t, base+".orig.xxhash128", digestBaseline)
			writeFile(t, base+".orig.etag", doc.ETag)
			if files.List == nil || *files.List {
				for _, list := range listNames(g.Kind, name) {
					writeFile(t, filepath.Join(dir, list), "1.2.3.4\n")
				}
			}
			if files.Fail {
				writeFile(t, base+".fail", "")
			}
			if files.Update {
				writeFile(t, base+".update", "")
			}
		}
		group := map[string]any{"name": g.Name, "action": g.Action, "updateFrequency": g.Frequency, "bindAddress": "",
			"preScript": "", "postScript": "", "customList": "", "feeds": feeds}
		if g.Kind != "dnsbl" {
			group["whoisConvert"], group["listClass"] = false, "deny"
		}
		if g.Kind == "ipv4" {
			group["suppressionCidr"] = int64(0)
		}
		p := settings["feeds/"+g.Kind]
		p["groups"] = append(p["groups"].([]any), group)
	}
	failures := map[string]int{}
	for id, n := range c.Failures {
		_, name, _ := strings.Cut(id, ":")
		failures[name] = n
	}
	in := Input{
		Request:  Request{Trigger: c.Request.Trigger, Scope: c.Request.Scope, Force: c.Request.Force, Feeds: c.Request.Feeds},
		Settings: settings, Stages: stages, InWindow: c.Window != "outside", ExtrasChanged: c.ExtrasChanged,
		PendingApply: c.PendingApply, SkipFeed: c.SkipFeed, Failures: failures,
	}
	return in, dirs
}

// logical is what Build decided, in the corpus's words: the feeds checked in order, their outcomes, the change each run
// feed is handed (its force, else its verdict), the fail markers standing afterwards, the feeds stopped and the decision.
func logical(c corpusCase, plan Plan, dirs map[string]string) corpusExpect {
	got := corpusExpect{Checked: []string{}, Outcomes: map[string]string{}, Changes: map[string]string{}, Fail: []string{},
		Stopped: []string{}, Apply: string(plan.Decision)}
	for _, item := range plan.Items {
		id := item.Feed.ID
		switch {
		case item.Stopped != "":
			got.Stopped = append(got.Stopped, id)
			continue
		case item.Checked:
			got.Checked = append(got.Checked, id)
		}
		if item.Outcome != "" {
			got.Outcomes[id] = item.Outcome
		}
		got.Changes[id] = string(item.Change.Verdict)
		if item.Change.Force != "none" {
			got.Changes[id] = item.Change.Force
		}
	}
	for _, kind := range []string{"ipv4", "ipv6", "dnsbl"} {
		for _, g := range c.Groups {
			if g.Kind != kind {
				continue
			}
			for _, f := range g.Feeds {
				name := f.Header + suffixOf(kind)
				base := filepath.Join(dirs[kind], name)
				if _, err := os.Lstat(base + ".fail"); err == nil {
					got.Fail = append(got.Fail, kind+":"+name)
				}
			}
		}
	}
	return got
}

// TestCorpusMatchesTodaysWorkList replays every case through Build: the settings, markers and probe answers of the case
// in a temporary tree, the probes against a local server.
func TestCorpusMatchesTodaysWorkList(t *testing.T) {
	doc := loadCorpus(t)
	for _, c := range doc.Cases {
		t.Run(c.ID, func(t *testing.T) {
			in, dirs := corpusInput(t, doc, c)
			plan, err := Build(context.Background(), in)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			got := logical(c, plan, dirs)
			if !reflect.DeepEqual(got, c.Expect) {
				t.Fatalf("%s\n got  %+v\n want %+v", c.Description, got, c.Expect)
			}
			// Every marker the run left is a whole file under its own name: no temporary stays behind. Core keeps no update
			// marker: one stands only where the case laid it out.
			seeded := map[string]bool{}
			for id, files := range c.Files {
				_, name, _ := strings.Cut(id, ":")
				seeded[name+".update"] = files.Update
			}
			for _, dir := range []string{dirs["ipv4"], dirs["dnsbl"]} { // ipv6 shares the IP folder
				entries, _ := os.ReadDir(dir)
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".part") || slices.Contains([]string{".fail", ".update"}, filepath.Ext(e.Name())) && !e.Type().IsRegular() {
						t.Errorf("%s: %s is left in the feed folder", c.ID, e.Name())
					}
					if filepath.Ext(e.Name()) == ".update" && !seeded[e.Name()] {
						t.Errorf("%s: Build wrote the update marker %s", c.ID, e.Name())
					}
				}
			}
		})
	}
}
