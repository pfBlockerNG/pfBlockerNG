package feedstage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A transfer that fails drops the validators: kept, they would let the next probe answer 304 for a body that was never
// published (#2820).
func TestFailedIngestDropsTheValidators(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "rejected", http.StatusBadGateway)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer server.Close()
	stage := testStage(t)
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	etag := filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.etag")
	writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), "203.0.113.2\n") // so that stage 6's probe keeps the body
	if got := run(stage, feed, "none"); got.Disposition != "changed" || !regularExists(etag) {
		t.Fatalf("the first run = %+v (ETag kept: %v), want changed with its ETag", got, regularExists(etag))
	}
	fail.Store(true)
	if got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"}); got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the failing transfer = %+v, want failed at the fetch", got)
	}
	if regularExists(etag) {
		t.Fatal("a failed transfer put the ETag back, want it dropped")
	}
	if got := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")); got != "203.0.113.1\n" {
		t.Fatalf("the download after a failed transfer = %q, want the last one", got)
	}
}

// A custom list whose run fails puts its last text back as the download.
func TestCustomListFailureKeepsTheLastList(t *testing.T) {
	stage := testStage(t)
	scripts := t.TempDir()
	stage.Paths.ScriptDirs = []string{scripts}
	if err := os.WriteFile(filepath.Join(scripts, "fails.sh"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	feed := Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled", Format: "auto", Custom: true,
		CustomText: "203.0.113.21\n"}
	if got := stage.Run(context.Background(), feed, Change{Force: "none"}); got.Disposition != "changed" {
		t.Fatalf("the first run = %+v", got)
	}
	feed.CustomText, feed.PreScript = "203.0.113.22\n", "fails.sh"
	if got := stage.Run(context.Background(), feed, Change{Force: "none"}); got.Disposition != "failed" {
		t.Fatalf("the run whose pre-script fails = %+v", got)
	}
	if got := readFile(t, filepath.Join(stage.Paths.FeedDir, "Test_custom_v4.orig")); got != "203.0.113.21\n" {
		t.Fatalf("the download after a failed custom run = %q, want the last list kept", got)
	}
}

// A custom list replaces the download, so the digest of the last transfer, which no longer describes it, goes.
func TestCustomListDropsTheTransferDigest(t *testing.T) {
	stage := testStage(t)
	dir := stage.Paths.FeedDir
	writeFile(t, filepath.Join(dir, "Test_custom_v4.orig"), "203.0.113.1\n")
	writeFile(t, filepath.Join(dir, "Test_custom_v4.orig.xxhash128"), "0123456789abcdef0123456789abcdef")
	got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
		Format: "auto", Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "none"})
	if got.Disposition != "changed" {
		t.Fatalf("run = %+v", got)
	}
	if regularExists(filepath.Join(dir, "Test_custom_v4.orig.xxhash128")) {
		t.Fatal("the custom list kept the digest of the last transfer")
	}
}

// A transfer answered 304 published nothing new: the source did not change, and the feed is parsed again from its download.
func TestNotModifiedTransferIsNoSourceChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()
	stage := testStage(t)
	writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), "203.0.113.1\n")
	got := stage.Run(context.Background(), testFeed("ipv4", "enabled", "auto", server.URL+"/feed"), Change{Verdict: VerdictChanged, Force: "none"})
	if got.Disposition != "reparsed" || got.SourceChanged {
		t.Fatalf("a run whose transfer is answered 304 = %+v, want reparsed without a source change", got)
	}
}

// A failure reason reaches the result only when it is short printable text that names no path or credential.
func TestFailureReasonsNameNoPathOrCredential(t *testing.T) {
	stage := testStage(t)
	stage.Fetcher.Proxy = &url.URL{Scheme: "http", Host: "proxy.example:3128", User: url.UserPassword("proxyuser", "proxypass")}
	feed := testFeed("ipv4", "enabled", "auto", "http://feed.example/list")
	feed.Username, feed.Password = "feeduser", "feedpass"
	for reason, want := range map[string]string{
		"404 Not Found":                   "404 Not Found",
		"open /var/db/feed: no such file": "feed_probe_failed",
		`open C:\feed`:                    "feed_probe_failed",
		"denied for feeduser":             "feed_probe_failed",
		"denied: feedpass":                "feed_probe_failed",
		"proxy proxyuser refused":         "feed_probe_failed",
		"proxy said proxypass":            "feed_probe_failed",
		"bad\x01byte":                     "feed_probe_failed",
		strings.Repeat("a", 65):           "feed_probe_failed",
		"":                                "feed_probe_failed",
	} {
		got := stage.Run(context.Background(), feed, Change{Verdict: VerdictFailed, Reason: reason, Force: "none"})
		if got.Disposition != "failed" || got.Stage != "probe" || got.Reason != want {
			t.Errorf("a failed verdict with reason %q = %+v, want reason %q", reason, got, want)
		}
	}

	// The probe of a missing local file and the transfer of a refused remote one, through stage 6 and the stage.
	dir := t.TempDir()
	local := testStage(t)
	local.Fetcher.Policy.LocalDirs = []string{dir}
	source := "file://" + filepath.Join(dir, "missing-feed")
	got := run(local, testFeed("ipv4", "enabled", "auto", source), "none")
	if raw, _ := json.Marshal(got); got.Reason != "feed_probe_failed" || strings.Contains(string(raw), dir) {
		t.Fatalf("the failure of a missing local feed = %s, want feed_probe_failed naming no path", raw)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()
	remote := testStage(t)
	var log strings.Builder
	remote.Log = &log
	feed = testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	feed.Username, feed.Password = "user", "feed-secret-never-return"
	got = run(remote, feed, "download")
	raw, _ := json.Marshal(got)
	if got.Stage != "fetch" || got.Reason != "404 Not Found" {
		t.Fatalf("a refused transfer = %s, want feedfetch's status reason at the fetch", raw)
	}
	// feed.Source is the URL Run receives: testFeed names the host feed.example, so server.URL is not it.
	for _, private := range []string{feed.Password, feed.Source} {
		if strings.Contains(string(raw), private) || strings.Contains(log.String(), private) {
			t.Fatalf("a refused transfer exposed %q: result %s, log %q", private, raw, log.String())
		}
	}
}

// A feed name is a file stem in the feed folder: anything but [A-Za-z0-9_]+ is refused before the folder is touched.
func TestHostileFeedNamesAreRefused(t *testing.T) {
	stage := testStage(t)
	for _, name := range []string{"a/b", "..", "a\x00b", ".hidden", "-x", "", "a.b"} {
		got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: name, State: "enabled", Format: "auto",
			Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "none"})
		if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != "feed_name_invalid" {
			t.Errorf("feed name %q: run = %+v, want feed_name_invalid", name, got)
		}
	}
	if entries, _ := os.ReadDir(stage.Paths.FeedDir); len(entries) != 0 {
		t.Fatalf("refused names left %d files in the feed folder", len(entries))
	}
}

// The empty check reads what the parse read after a pre-script, its output, not the download (#1925): a pre-script that
// leaves only a comment of a download with content leaves no content line, so the list is replaced by the empty placeholder.
func TestEmptyCheckReadsThePreScriptOutput(t *testing.T) {
	stage, feed, source := localStage(t)
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "comments.sh"), []byte("#!/bin/sh\nprintf '# nothing listed\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "203.0.113.1\n")
	feed.PreScript = "comments.sh"
	got := run(stage, feed, "none")
	if got.Disposition != "changed" || got.Placeholder != "empty" {
		t.Fatalf("a pre-script that leaves only a comment = %+v, want the empty placeholder", got)
	}
	if list := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); list != "" {
		t.Fatalf("the list = %q, want it empty", list)
	}
}

// The Suppression CIDR Limit: the global limit never cuts a GeoIP list, a group's own IPv4 limit does, and that limit is over
// the global one.
func TestSuppressionCIDRLimits(t *testing.T) {
	for _, tc := range []struct {
		name            string
		floor, groupCut int
		geoip           bool
		want            string
	}{
		{name: "the global limit cuts a wider prefix", floor: 24, want: "198.51.0.0/32\n"},
		{name: "the global limit never cuts a GeoIP list", floor: 24, geoip: true, want: "198.51.0.0/16\n"},
		{name: "a group's limit cuts a GeoIP list", groupCut: 24, geoip: true, want: "198.51.0.0/32\n"},
		{name: "the group's limit applies without a global one", groupCut: 24, want: "198.51.0.0/32\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, feed, source := localStage(t)
			stage.Config = Config{Suppression: true, FloorV4: tc.floor}
			feed.SuppressionCIDR = tc.groupCut
			if tc.geoip {
				stage.Paths.GeoIPDir = filepath.Dir(source)
				feed.Format, feed.Source = "geoip", "XX Nowhere"
				source = filepath.Join(stage.Paths.GeoIPDir, "XX_v4.txt")
			}
			writeFile(t, source, "198.51.0.0/16\n")
			if got := run(stage, feed, "none"); got.Disposition != "changed" {
				t.Fatalf("run = %+v", got)
			}
			if list := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.parsed.ip")); list != tc.want {
				t.Fatalf("the list = %q, want %q", list, tc.want)
			}
		})
	}
}

// A caller's cancellation while the DNSBL post-script runs fails the feed as cancelled and publishes nothing.
func TestCancelDuringTheDNSBLPostScriptIsReportedCancelled(t *testing.T) {
	ctx, script := cancelWhenScriptStarts(t)
	stage, _, source := localStage(t)
	if err := os.WriteFile(filepath.Join(stage.Paths.ScriptDirs[0], "blocks.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, source, "example.test\n")
	feed := testFeed("dnsbl", "enabled", "auto", "file://"+source)
	feed.PostScript = "blocks.sh"
	got := stage.Run(ctx, feed, Change{Force: "download"})
	if cause := context.Cause(ctx); !errors.Is(cause, errScriptStarted) {
		t.Fatalf("the run = %+v ended with cause %v, want it cancelled once the script started", got, cause)
	}
	if got.Disposition != "failed" || got.Stage != "post-script" || got.Reason != "cancelled" {
		t.Fatalf("a run cancelled in its DNSBL post-script = %+v, want failed/post-script/cancelled", got)
	}
	if regularExists(filepath.Join(stage.Paths.FeedDir, "feed.parsed.ndjson")) {
		t.Fatal("a cancelled run published its rows")
	}
}
