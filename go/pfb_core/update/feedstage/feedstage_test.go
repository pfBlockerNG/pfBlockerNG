package feedstage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// testStage is a stage over a fresh feed folder whose fetcher reaches the loopback test servers by name: the feed URLs name
// feed.example, which the vetting resolver answers with 127.0.0.1 (allow-listed) and a public address.
func testStage(t *testing.T) *Stage {
	t.Helper()
	return &Stage{
		Paths: Paths{FeedDir: t.TempDir()},
		Fetcher: &feedfetch.Fetcher{
			Policy: feedfetch.Policy{
				Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Resolve: func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("1.1.1.1")}, nil
				},
			},
			RetryDelay: time.Nanosecond,
		},
	}
}

// testFeed is the feed "feed" of kind (ipv4, ipv6 or dnsbl), its file stem in the feed folder carrying the family suffix.
func testFeed(kind, state, format, source string) Feed {
	name := "feed"
	switch kind {
	case "ipv4":
		name += "_v4"
	case "ipv6":
		name += "_v6"
	}
	return Feed{
		ID: kind + ":" + name, Kind: kind, Name: name, State: state, Format: format,
		Source: strings.Replace(source, "127.0.0.1", "feed.example", 1),
	}
}

// detect is stage 6 for the tests: sub-slice 9d probes a transferred feed before the stage runs and hands Run its verdict.
func detect(s *Stage, f Feed, force string) Change {
	change := Change{Verdict: VerdictChanged, Force: force}
	if force != "none" || s.validate(f, change) != "" || f.Custom || f.WhoisConvert || f.Format == "whois" || f.Format == "asn" {
		return change
	}
	request, reason := s.request(f)
	if reason != "" {
		return change
	}
	probe := s.Fetcher.Probe(context.Background(), feedfetch.Feed{Dir: s.Paths.FeedDir, Name: f.Name}, request)
	switch {
	case !probe.OK || probe.Decision == feedfetch.Failed:
		return Change{Verdict: VerdictFailed, Reason: probe.Reason, Force: force}
	case probe.Decision == feedfetch.Unchanged:
		change.Verdict = VerdictUnchanged
	}
	return change
}

// run is one feed of an Update: stage 6's verdict, then the stage.
func run(s *Stage, f Feed, force string) Result {
	return s.Run(context.Background(), f, detect(s, f, force))
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", filepath.Base(path), err)
	}
	return string(data)
}

func TestProbeReuseAndForceModes(t *testing.T) {
	var requests, conditional atomic.Int32
	secret := "feed-secret-never-return"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			conditional.Add(1)
		}
		w.Header().Set("ETag", `"same"`)
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	var updateLog strings.Builder
	stage.Log = &updateLog
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	feed.Username, feed.Password = "user", secret
	dir := stage.Paths.FeedDir
	writeFile(t, filepath.Join(dir, "feed_v4.orig"), "203.0.113.2\n")

	first := run(stage, feed, "none")
	if first.Disposition != "changed" || first.Entries != 1 || requests.Load() != 1 {
		t.Fatalf("first probe+ingest = %+v after %d HTTP requests, want changed/one entry/one request", first, requests.Load())
	}
	if got := readFile(t, filepath.Join(dir, "feed_v4.orig.etag")); got != `"same"` {
		t.Fatalf("the changed probe's ETag = %q, want it beside the published baseline", got)
	}
	if got := readFile(t, filepath.Join(dir, "feed_v4.parsed.ip")); got != "203.0.113.1\n" {
		t.Fatalf("parsed IP artifact = %q", got)
	}
	if raw, _ := json.Marshal(first); strings.Contains(string(raw), secret) || strings.Contains(string(raw), server.URL) {
		t.Fatalf("the result exposed a secret or URL: %s", raw)
	}

	if got := run(stage, feed, "none"); got.Disposition != "unchanged" || requests.Load() != 2 || conditional.Load() != 1 {
		t.Fatalf("unchanged probe = %+v after %d requests (%d conditional), want one conditional request", got, requests.Load(), conditional.Load())
	}
	if got := run(stage, feed, "parse"); got.Disposition != "reparsed" || requests.Load() != 2 {
		t.Fatalf("parse force = %+v after %d HTTP requests, want reparsed without a request", got, requests.Load())
	}
	for suffix, body := range map[string]string{
		".probe": "stale.example\n", ".probe.etag": `"stale"`, ".probe.lastmod": "yesterday", ".probe.size": "12",
	} {
		writeFile(t, filepath.Join(dir, "feed_v4"+suffix), body)
	}
	if got := run(stage, feed, "download"); got.Disposition != "changed" || requests.Load() != 3 || conditional.Load() != 1 {
		t.Fatalf("download force = %+v after %d requests (%d conditional), want one unconditional fetch", got, requests.Load(), conditional.Load())
	}
	for _, suffix := range []string{".probe", ".probe.etag", ".probe.lastmod", ".probe.size"} {
		if _, err := os.Stat(filepath.Join(dir, "feed_v4"+suffix)); !os.IsNotExist(err) {
			t.Errorf("forced download left %s: %v", suffix, err)
		}
	}
	if got := run(stage, feed, "both"); got.Disposition != "changed" || requests.Load() != 4 || conditional.Load() != 1 {
		t.Fatalf("both force = %+v after %d requests (%d conditional), want one unconditional fetch", got, requests.Load(), conditional.Load())
	}
	if strings.Contains(updateLog.String(), secret) || strings.Contains(updateLog.String(), server.URL) {
		t.Fatalf("the log exposed a secret or URL: %s", updateLog.String())
	}
}

func TestProxyUnusableRefusesWithoutDialingAndKeepsLastGood(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	stage.Fetcher.ProxyUnusable = true
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	orig := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")
	parsed := filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")
	writeFile(t, orig, "203.0.113.1\n")
	writeFile(t, parsed, "203.0.113.1\n")
	for _, force := range []string{"none", "download"} {
		if got := run(stage, feed, force); got.Disposition != "failed" || got.Reason != "proxy_unusable" {
			t.Fatalf("run(%q) with an unusable proxy = %+v; want failed/proxy_unusable", force, got)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("a run with an unusable proxy sent %d direct requests, want none", requests.Load())
	}
	for path, want := range map[string]string{orig: "203.0.113.1\n", parsed: "203.0.113.1\n"} {
		if got := readFile(t, path); got != want {
			t.Fatalf("%s = %q after a proxy refusal, want last-known-good %q", filepath.Base(path), got, want)
		}
	}
}

// Hold is "download once" (spec §3 stage 3, "Hold with a published list"): a Hold feed is held while its published list
// exists, unless a resolved script asks for its download to be parsed again; without a list it parses its download, or
// downloads once when it has none.
func TestHoldsDisabledBaselineAndWithoutBaseline(t *testing.T) {
	for _, tc := range []struct {
		name, state, preScript, postScript, want string
		hasOrig, hasList                         bool
		verdict                                  Verdict
		requests                                 int32
	}{
		{name: "held with a list", state: "hold", hasList: true, want: "held"},
		{name: "held with a list and a download", state: "hold", hasList: true, hasOrig: true, want: "held"},
		{name: "held baseline with a pre-script", state: "hold", preScript: "pre.sh", hasOrig: true, hasList: true, want: "reparsed"},
		{name: "held baseline with a post-script", state: "hold", postScript: "post.sh", hasOrig: true, hasList: true, want: "reparsed"},
		{name: "hold without a list parses its download", state: "hold", hasOrig: true, want: "reparsed"},
		{name: "hold never downloaded downloads once", state: "hold", verdict: VerdictChanged, want: "changed", requests: 1},
		{name: "disabled row", state: "disabled", hasOrig: true, hasList: true, want: "held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				_, _ = w.Write([]byte("203.0.113.8\n"))
			}))
			defer server.Close()
			stage := testStage(t)
			dir := stage.Paths.FeedDir
			feed := testFeed("ipv4", tc.state, "auto", server.URL+"/feed")
			feed.PreScript, feed.PostScript = tc.preScript, tc.postScript
			if tc.hasOrig {
				writeFile(t, filepath.Join(dir, "feed_v4.orig"), "203.0.113.7\n")
			}
			if tc.hasList {
				writeFile(t, filepath.Join(dir, "feed_v4.parsed.ip"), "203.0.113.6\n")
			}
			scripts := t.TempDir()
			stage.Paths.ScriptDirs = []string{scripts}
			for _, name := range []string{tc.preScript, tc.postScript} {
				if name != "" {
					if err := os.WriteFile(filepath.Join(scripts, name), []byte("#!/bin/sh\ntrue\n"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			verdict := tc.verdict
			if verdict == "" {
				verdict = VerdictUnchanged
			}
			got := stage.Run(context.Background(), feed, Change{Verdict: verdict, Force: "none"})
			if got.Disposition != tc.want || requests.Load() != tc.requests {
				t.Fatalf("run for %s = %+v after %d requests; want %s after %d", tc.name, got, requests.Load(), tc.want, tc.requests)
			}
		})
	}
}

func TestParseWithoutBaselineIngestsThenParses(t *testing.T) {
	var requests, conditional atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			conditional.Add(1)
		}
		w.Header().Set("ETag", `"new"`)
		_, _ = w.Write([]byte("203.0.113.7\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	got := run(stage, testFeed("ipv4", "enabled", "auto", server.URL+"/feed"), "parse")
	if got.Disposition != "changed" || got.Stage != "parse" || !got.SourceChanged || got.Entries != 1 {
		t.Fatalf("run(parse) without a baseline = %+v; want a fetched and parsed changed feed", got)
	}
	if requests.Load() != 1 || conditional.Load() != 0 {
		t.Fatalf("run(parse) without a baseline made %d requests (%d conditional), want one unconditional ingest", requests.Load(), conditional.Load())
	}
	for _, name := range []string{"feed_v4.orig", "feed_v4.parsed.ip"} {
		if got := readFile(t, filepath.Join(stage.Paths.FeedDir, name)); got != "203.0.113.7\n" {
			t.Fatalf("%s = %q; want the fetched entry", name, got)
		}
	}
}

func TestDNSBLPublishesBothEmptyFamilySignalsAndRetainsThemOnFailure(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "rejected", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("example.test\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	stage.Config.DNSBLIP = true
	feed := testFeed("dnsbl", "enabled", "auto", server.URL+"/feed")
	result := run(stage, feed, "none")
	if result.Disposition != "changed" || result.DNSBLRows != 1 || result.IPv4Count != 0 || result.IPv6Count != 0 {
		t.Fatalf("DNSBL result = %+v, want one row and explicit empty IP families", result)
	}
	names := []string{"feed.parsed.ndjson", "feed.parsed.v4.ip", "feed.parsed.v6.ip"}
	before := make(map[string]string, len(names))
	for _, name := range names {
		before[name] = readFile(t, filepath.Join(stage.Paths.FeedDir, name))
		if strings.HasSuffix(name, ".ip") && before[name] != "" {
			t.Errorf("empty family side list %s = %q, want empty", name, before[name])
		}
	}
	fail.Store(true)
	if got := run(stage, feed, "none"); got.Disposition != "failed" {
		t.Fatalf("failed DNSBL run = %+v", got)
	}
	for _, name := range names {
		if got := readFile(t, filepath.Join(stage.Paths.FeedDir, name)); got != before[name] {
			t.Errorf("a failed DNSBL run changed %s: %q", name, got)
		}
	}
}

func TestWhoisKeepsPartialResolutionAndReportsFailure(t *testing.T) {
	stage := testStage(t)
	stage.Fetcher.Lookup = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "one.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
		}
		return nil, errors.New("lookup failed")
	}
	got := run(stage, testFeed("ipv4", "enabled", "whois", "one.example,bad.example"), "none")
	if got.Disposition != "failed" || got.Stage != "whois" || got.Reason != "whois_partial" || got.Entries != 1 {
		t.Fatalf("partial WHOIS result = %+v, want one kept entry and a whois-stage failure", got)
	}
	if data := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")); !strings.Contains(data, "203.0.113.19") {
		t.Fatalf("partial WHOIS baseline = %q, want the resolved address", data)
	}
	if data := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); data != "203.0.113.19\n" {
		t.Fatalf("partial WHOIS list = %q, want the resolved address published", data)
	}
}

func TestRunsPreScriptAndKeepsOldArtifactsWhenItFails(t *testing.T) {
	scriptDir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '203.0.113.88' > \"$1\"\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "rewrite.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	stage := testStage(t)
	stage.Paths.ScriptDirs = []string{scriptDir}
	feed := testFeed("ipv4", "enabled", "auto", "http://example.test/feed")
	feed.PreScript = "rewrite.sh"
	orig := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")
	writeFile(t, orig, "203.0.113.1\n")
	if got := run(stage, feed, "parse"); got.Disposition != "reparsed" || got.PreScriptFailed {
		t.Fatalf("successful pre-script run = %+v", got)
	}
	if data := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); data != "203.0.113.88\n" {
		t.Fatalf("pre-script parsed bytes = %q", data)
	}
	if data := readFile(t, orig); data != "203.0.113.1\n" {
		t.Fatalf("the pre-script changed the raw baseline: %q", data)
	}

	bad := testStage(t)
	bad.Paths.ScriptDirs = []string{scriptDir}
	if err := os.WriteFile(filepath.Join(scriptDir, "fails.sh"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed.PreScript = "fails.sh"
	badOrig := filepath.Join(bad.Paths.FeedDir, "feed_v4.orig")
	badParsed := filepath.Join(bad.Paths.FeedDir, "feed_v4.parsed.ip")
	writeFile(t, badOrig, "203.0.113.5\n")
	writeFile(t, badParsed, "203.0.113.6\n")
	if got := run(bad, feed, "parse"); got.Disposition != "failed" || !got.PreScriptFailed || got.Stage != "script" {
		t.Fatalf("failing pre-script run = %+v", got)
	}
	for path, want := range map[string]string{badOrig: "203.0.113.5\n", badParsed: "203.0.113.6\n"} {
		if data := readFile(t, path); data != want {
			t.Fatalf("a pre-script failure changed %s: %q", filepath.Base(path), data)
		}
	}

	// A pre-script that is no file in the folders is skipped with one log line, as today (apply.inc:4353): the feed parses
	// without it.
	missing := testStage(t)
	missing.Paths.ScriptDirs = []string{scriptDir}
	var log strings.Builder
	missing.Log = &log
	feed.PreScript = "missing.sh"
	writeFile(t, filepath.Join(missing.Paths.FeedDir, "feed_v4.orig"), "203.0.113.5\n")
	if got := run(missing, feed, "parse"); got.Disposition != "reparsed" || got.PreScriptFailed {
		t.Fatalf("missing pre-script run = %+v, want the feed parsed without it", got)
	}
	if data := readFile(t, filepath.Join(missing.Paths.FeedDir, "feed_v4.parsed.ip")); data != "203.0.113.5\n" {
		t.Fatalf("the list without the missing pre-script = %q, want the download's entry", data)
	}
	if strings.Count(log.String(), "missing.sh") != 1 {
		t.Fatalf("the log = %q, want one line naming the missing pre-script", log.String())
	}
}

func TestPublishesParsedArtifactsAtomically(t *testing.T) {
	dir := t.TempDir()
	names := []string{"first.parsed.ip", "second.parsed.ip"}
	for _, name := range names {
		writeFile(t, filepath.Join(dir, name), "old\n")
	}
	staged := filepath.Join(dir, ".staged-first")
	writeFile(t, staged, "new\n")
	err := publishStaged(dir, []stagedFeedFile{
		{name: names[0], temp: staged},
		{name: names[1], temp: filepath.Join(dir, ".missing-stage")},
	})
	if err == nil {
		t.Fatal("a publication with a missing staged artifact succeeded")
	}
	for _, name := range names {
		if got := readFile(t, filepath.Join(dir, name)); got != "old\n" {
			t.Errorf("a failed publication changed %s: %q", name, got)
		}
	}
}

// An unset or relative folder is refused before anything is touched: no default may name a host folder.
func TestUnsetPathsAreErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		paths  Paths
		feed   Feed
		reason string
	}{
		{"no feed folder", Paths{}, testFeed("ipv4", "enabled", "auto", "http://example.test/feed"), "feed_directory_missing"},
		{"relative feed folder", Paths{FeedDir: "feeds"}, testFeed("ipv4", "enabled", "auto", "http://example.test/feed"), "feed_directory_invalid"},
		{"geoip without its folder", Paths{FeedDir: t.TempDir()}, testFeed("ipv4", "enabled", "geoip", "US United States"), "geoip_directory_missing"},
		{"rsync without its program", Paths{FeedDir: t.TempDir()}, testFeed("ipv4", "enabled", "rsync", "rsync://feed.example/list"), "rsync_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := testStage(t)
			stage.Paths = tc.paths
			got := run(stage, tc.feed, "download")
			if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != tc.reason {
				t.Fatalf("run = %+v; want a settings failure %s", got, tc.reason)
			}
			if tc.paths.FeedDir != "" && filepath.IsAbs(tc.paths.FeedDir) {
				if entries, _ := os.ReadDir(tc.paths.FeedDir); len(entries) != 0 {
					t.Fatalf("a refused feed left %d files in its folder", len(entries))
				}
			}
		})
	}
}
