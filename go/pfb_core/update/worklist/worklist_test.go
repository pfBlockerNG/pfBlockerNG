package worklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/digest"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/feedstage"
)

// fixture is one IPv4 group "G4" with one feed "A" in a temporary feed folder, published once from baseline.
type fixture struct {
	dir   string
	stage *feedstage.Stage
	group map[string]any
}

func newFixture(t *testing.T, url string) *fixture {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "A_v4")
	writeFile(t, base+".orig", "1.2.3.4\n")
	writeFile(t, base+".orig.xxhash128", digest.Bytes([]byte("1.2.3.4\n")))
	writeFile(t, base+".parsed.ip", "1.2.3.4\n")
	fetcher := &feedfetch.Fetcher{Policy: remotePolicy(), RetryDelay: 1}
	return &fixture{
		dir:   dir,
		stage: &feedstage.Stage{Paths: feedstage.Paths{FeedDir: dir}, Fetcher: fetcher},
		group: map[string]any{"name": "G4", "action": "Deny_Inbound", "updateFrequency": "01hour", "bindAddress": "",
			"preScript": "", "postScript": "", "customList": "", "whoisConvert": false, "suppressionCidr": int64(0),
			"listClass": "deny", "feeds": []any{map[string]any{"header": "A", "state": "enabled", "format": "auto", "url": url,
				"credentials": ""}}},
	}
}

func (f *fixture) setURL(url string) {
	f.group["feeds"].([]any)[0].(map[string]any)["url"] = url
}

func (f *fixture) input(req Request) Input {
	empty := map[string]any{"groups": []any{}}
	return Input{Request: req, InWindow: true, Stages: map[string]*feedstage.Stage{"ipv4": f.stage},
		Settings: map[string]map[string]any{"feeds/ipv4": {"groups": []any{f.group}}, "feeds/ipv6": empty, "feeds/dnsbl": empty,
			"feeds/geoip": empty}}
}

func (f *fixture) path(suffix string) string { return filepath.Join(f.dir, "A_v4"+suffix) }

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func build(t *testing.T, in Input) Plan {
	t.Helper()
	plan, err := Build(context.Background(), in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return plan
}

func onlyItem(t *testing.T, plan Plan) Item {
	t.Helper()
	if len(plan.Items) != 1 {
		t.Fatalf("items = %+v, want one", plan.Items)
	}
	return plan.Items[0]
}

// servedBodies serves a fixed body per path.
func servedBodies(t *testing.T, bodies map[string]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Scenario: a probe body kept for one source is never published for another (issue #4038, note from the review of #4195).
// Given an Update outside the window probed the feed at /old and kept the changed body,
// When the feed's source is moved to /new and its fail marker adds it to the next walk, which runs it without a probe,
// Then the kept body is dropped before the stage runs, and the stage publishes what /new serves.
func TestKeptProbeOfAnotherSourceIsNeverPublished(t *testing.T) {
	srv := servedBodies(t, map[string]string{"/old": "9.9.9.9\n", "/new": "5.6.7.8\n"})
	f := newFixture(t, remoteURL(srv)+"/old")
	in := f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})
	in.InWindow = false
	if plan := build(t, in); plan.Decision != Pending {
		t.Fatalf("the first Update = %v, want pending", plan.Decision)
	}
	if !exists(f.path(".probe")) || !exists(f.path(".probe.src")) {
		t.Fatal("before: the changed probe body and the record of its source stand")
	}

	f.setURL(remoteURL(srv) + "/new")
	writeFile(t, f.path(".fail"), "")
	item := onlyItem(t, build(t, f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})))
	if exists(f.path(".probe")) {
		t.Fatal("the probe body kept for /old still stands after the work list for /new")
	}
	if item.Change.Verdict != feedstage.VerdictChanged {
		t.Fatalf("change = %+v, want changed from the fail marker", item.Change)
	}
	if r := f.stage.Run(context.Background(), item.Feed, item.Change); r.Disposition != "changed" {
		t.Fatalf("run = %+v, want changed", r)
	}
	if got, _ := os.ReadFile(f.path(".orig")); string(got) != "5.6.7.8\n" {
		t.Fatalf("published %q, want the body /new serves", got)
	}
}

// Scenario: a probe body kept for the same source is used once, as today's ingest uses the probe's body.
func TestKeptProbeOfTheSameSourceIsIngested(t *testing.T) {
	bodies := map[string]string{"/old": "9.9.9.9\n"}
	srv := servedBodies(t, bodies)
	f := newFixture(t, remoteURL(srv)+"/old")
	in := f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})
	in.InWindow = false
	build(t, in)
	if !exists(f.path(".probe")) {
		t.Fatal("before: the changed probe body stands")
	}
	bodies["/old"] = "1.1.1.1\n" // what the server serves now is not what the probe kept
	writeFile(t, f.path(".fail"), "")
	item := onlyItem(t, build(t, f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})))
	if !exists(f.path(".probe")) {
		t.Fatal("the probe body of the same source was dropped")
	}
	if r := f.stage.Run(context.Background(), item.Feed, item.Change); r.Disposition != "changed" {
		t.Fatalf("run = %+v, want changed", r)
	}
	if got, _ := os.ReadFile(f.path(".orig")); string(got) != "9.9.9.9\n" {
		t.Fatalf("published %q, want the kept probe body", got)
	}
}

// A probe body with no record of its source, or a record that is no regular file, is of an unknown source: dropped.
func TestProbeWithoutASourceRecordIsDropped(t *testing.T) {
	for _, record := range []string{"none", "dir"} {
		t.Run(record, func(t *testing.T) {
			f := newFixture(t, "http://192.0.2.1/list")
			writeFile(t, f.path(".probe"), "9.9.9.9\n")
			writeFile(t, f.path(".probe.etag"), "\"x\"")
			if record == "dir" {
				if err := os.Mkdir(f.path(".probe.src"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			build(t, f.input(Request{Trigger: "manual", Scope: "both", Force: "none"}))
			for _, suffix := range []string{".probe", ".probe.etag"} {
				if exists(f.path(suffix)) {
					t.Errorf("%s stands, want it dropped with the body of an unknown source", suffix)
				}
			}
		})
	}
}

// The source record of a kept probe holds no credential in clear: it names the source by a digest only.
func TestProbeSourceRecordHoldsNoCredential(t *testing.T) {
	var asked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(true)
		_, _ = w.Write([]byte("9.9.9.9\n"))
	}))
	t.Cleanup(srv.Close)
	f := newFixture(t, remoteURL(srv)+"/list")
	f.group["feeds"].([]any)[0].(map[string]any)["credentials"] = "operator:s3cret-pass"
	in := f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})
	build(t, in)
	if !asked.Load() {
		t.Fatal("the feed was not probed")
	}
	record, err := os.ReadFile(f.path(".probe.src"))
	if err != nil {
		t.Fatalf("no source record beside the kept probe body: %v", err)
	}
	for _, secret := range []string{"operator", "s3cret-pass", remoteURL(srv)} {
		if strings.Contains(string(record), secret) {
			t.Fatalf("the source record %q holds %q", record, secret)
		}
	}
}

// Stage 6 finishes what an earlier run left in the feed folder (feedstage.Recover) before it probes.
func TestRecoverRunsBeforeTheProbe(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	writeFile(t, f.path(".probe.part"), "half a body")
	writeFile(t, f.path(".fail"), "") // checked without a probe: no network
	build(t, f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}))
	if exists(f.path(".probe.part")) {
		t.Fatal("the probe's temporary from a killed run stands, want it removed by Recover before the probe")
	}
}

// A feed folder Recover refuses stops every feed in it: none is probed, run or given an outcome.
func TestUnrecoverableFolderStopsItsFeeds(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	writeFile(t, filepath.Join(f.dir, ".pfbrun-A_v4"), "") // a run folder that is no directory
	writeFile(t, f.path(".fail"), "")
	item := onlyItem(t, build(t, f.input(Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}})))
	if item.Stopped == "" || item.Outcome != "" || item.Checked {
		t.Fatalf("item = %+v, want stopped without a check or an outcome", item)
	}
}

// SkipFeedPassed is today's skipfeed limit against today's failures, as pfb_download_failure() reads it: the failure the
// run may add is counted, so a feed at the limit removes its marker instead of creating it.
func TestSkipFeedPassed(t *testing.T) {
	for _, c := range []struct {
		skip, failures int
		want           bool
	}{{0, 5, false}, {3, 2, false}, {2, 2, true}, {1, 3, true}} {
		f := newFixture(t, "http://192.0.2.1/list")
		in := f.input(Request{Trigger: "manual", Scope: "both", Force: "none"})
		in.SkipFeed, in.Failures = c.skip, map[string]int{"A_v4": c.failures}
		if got := onlyItem(t, build(t, in)).Feed.SkipFeedPassed; got != c.want {
			t.Errorf("skipfeed %d, failures %d: SkipFeedPassed = %v, want %v", c.skip, c.failures, got, c.want)
		}
	}
}

// A group's custom list is a feed of its own on a manual Update, which compares its text (feedstage); a scheduled
// or apply Update never runs it: today's scheduled pass does not select it, and Core's apply builds nothing.
func TestCustomListRunsOnManualOnly(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	f.group["customList"] = "198.51.100.7\n"
	f.group["whoisConvert"] = true
	for _, c := range []struct {
		req  Request
		want int
	}{
		{Request{Trigger: "manual", Scope: "ip", Force: "parse"}, 2},
		{Request{Trigger: "apply"}, 0},
		{Request{Trigger: "manual", Scope: "dnsbl", Force: "none"}, 0},
		{Request{Trigger: "scheduled", Feeds: []string{"ipv4:A_v4"}}, 1},
	} {
		writeFile(t, f.path(".fail"), "") // a scheduled check without a probe
		plan := build(t, f.input(c.req))
		if len(plan.Items) != c.want {
			t.Fatalf("%+v: items %+v, want %d", c.req, plan.Items, c.want)
		}
		if c.want != 2 {
			continue
		}
		custom := plan.Items[1]
		want := feedstage.Feed{ID: "custom:ipv4:G4", Kind: "ipv4", Name: "G4_custom_v4", State: "enabled", Format: "auto",
			Custom: true, CustomText: "198.51.100.7\n", WhoisConvert: true}
		if custom.Feed != want || custom.Change.Force != c.req.forceOrNone() {
			t.Fatalf("%+v: custom item %+v, want feed %+v with force %s", c.req, custom, want, c.req.forceOrNone())
		}
	}
}

func (r Request) forceOrNone() string {
	if r.Force == "" {
		return "none"
	}
	return r.Force
}

// A feed is resolved from its projection rows as the stage reads it.
func TestFeedResolvedFromTheSettings(t *testing.T) {
	f := newFixture(t, "https://feed.example/list")
	f.group["bindAddress"], f.group["preScript"], f.group["postScript"] = "192.0.2.7", "pre.sh", "post.sh"
	f.group["suppressionCidr"] = int64(20)
	row := f.group["feeds"].([]any)[0].(map[string]any)
	row["state"], row["format"], row["credentials"] = "flex", "regex", "user:p%40ss"
	got := onlyItem(t, build(t, f.input(Request{Trigger: "manual", Scope: "ip", Force: "parse"}))).Feed
	want := feedstage.Feed{ID: "ipv4:A_v4", Kind: "ipv4", Name: "A_v4", State: "flex", Format: "regex",
		Source: "https://feed.example/list", Username: "user", Password: "p@ss", BindAddress: netip.MustParseAddr("192.0.2.7"),
		PreScript: "pre.sh", PostScript: "post.sh", SuppressionCIDR: 20}
	if got != want {
		t.Fatalf("feed\n got  %+v\n want %+v", got, want)
	}
}

// A request the Core API never sends is refused whole: Build decides nothing for it.
func TestRequestOutsideTheProtocolIsRefused(t *testing.T) {
	f := newFixture(t, "http://192.0.2.1/list")
	for _, req := range []Request{{Trigger: "bogus"}, {Trigger: "manual", Scope: "all", Force: "none"},
		{Trigger: "manual", Scope: "ip", Force: "reload"}, {Trigger: ""}} {
		if _, err := Build(context.Background(), f.input(req)); err == nil {
			t.Errorf("%+v: accepted, want refused", req)
		}
	}
}
