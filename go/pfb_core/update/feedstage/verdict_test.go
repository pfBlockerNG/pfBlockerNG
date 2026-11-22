package feedstage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// Scenario: stage 6 owns the probe.
// Given a feed stage 6 has probed, when Run is given its verdict, then Run sends no request of its own: a changed verdict
// ingests the body the probe kept, an unchanged one follows the reuse rule, and a failed one fails the feed at the probe.
func TestRunTakesTheVerdictAndNeverProbes(t *testing.T) {
	var requests atomic.Int32
	var body atomic.Value
	body.Store("203.0.113.1\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer server.Close()
	stage := testStage(t)
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	dir := stage.Paths.FeedDir
	parsed, probe := filepath.Join(dir, "feed_v4.parsed.ip"), filepath.Join(dir, "feed_v4.probe")
	if got := run(stage, feed, "none"); got.Disposition != "changed" || requests.Load() != 1 {
		t.Fatalf("the first run = %+v after %d requests, want changed after one transfer", got, requests.Load())
	}

	body.Store("203.0.113.2\n")
	change := detect(stage, feed, "none")
	if change.Verdict != VerdictChanged || requests.Load() != 2 || !regularExists(probe) {
		t.Fatalf("stage 6's probe = %+v after %d requests (probe body kept: %v), want changed", change, requests.Load(), regularExists(probe))
	}
	if got := stage.Run(context.Background(), feed, change); got.Disposition != "changed" || requests.Load() != 2 {
		t.Fatalf("Run on a changed verdict = %+v after %d requests, want changed with no request of its own", got, requests.Load())
	}
	if regularExists(probe) {
		t.Error("Run left the probe body; want it consumed by the ingest")
	}
	if got := readFile(t, parsed); got != "203.0.113.2\n" {
		t.Fatalf("the list after a changed verdict = %q, want the probed body", got)
	}

	body.Store("203.0.113.3\n")
	if got := stage.Run(context.Background(), feed, Change{Verdict: VerdictUnchanged, Force: "none"}); got.Disposition != "unchanged" || requests.Load() != 2 {
		t.Fatalf("Run on an unchanged verdict = %+v after %d requests, want the list reused and no request", got, requests.Load())
	}
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictFailed, Reason: "502 Bad Gateway", Force: "none"})
	if got.Disposition != "failed" || got.Stage != "probe" || got.Reason != "502 Bad Gateway" || requests.Load() != 2 {
		t.Fatalf("Run on a failed verdict = %+v after %d requests, want failed at the probe with stage 6's reason", got, requests.Load())
	}
	if got := readFile(t, parsed); got != "203.0.113.2\n" {
		t.Fatalf("the list after a failed verdict = %q, want the last one kept", got)
	}
}

// A force or a verdict Run does not know is a settings failure that touches nothing: an unknown force is never a download.
func TestUnknownForceOrVerdictIsRefused(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	defer server.Close()
	for _, tc := range []struct {
		change Change
		reason string
	}{
		{Change{Verdict: VerdictChanged}, "force_invalid"},
		{Change{Verdict: VerdictChanged, Force: "reload"}, "force_invalid"},
		{Change{Force: "none"}, "verdict_invalid"},
		{Change{Verdict: "maybe", Force: "none"}, "verdict_invalid"},
		{Change{Verdict: "maybe", Force: "download"}, "verdict_invalid"},
	} {
		stage := testStage(t)
		got := stage.Run(context.Background(), testFeed("ipv4", "enabled", "auto", server.URL+"/feed"), tc.change)
		if got.Disposition != "failed" || got.Stage != "settings" || got.Reason != tc.reason {
			t.Errorf("Run(%+v) = %+v, want a settings failure %s", tc.change, got, tc.reason)
		}
		if entries, _ := os.ReadDir(stage.Paths.FeedDir); len(entries) != 0 {
			t.Errorf("Run(%+v) left %d files in the feed folder", tc.change, len(entries))
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("refused runs sent %d requests, want none", requests.Load())
	}
	// A forced download needs no verdict: stage 6 has nothing to decide.
	stage := testStage(t)
	if got := stage.Run(context.Background(), testFeed("ipv4", "enabled", "auto", server.URL+"/feed"), Change{Force: "download"}); got.Disposition != "changed" {
		t.Fatalf("a forced download without a verdict = %+v, want changed", got)
	}
}

// The feed's source address (the settings' bindAddress, today's sourceInterface) is the transfer's.
func TestBindAddressReachesTheRequest(t *testing.T) {
	stage := testStage(t)
	feed := testFeed("ipv4", "enabled", "auto", "http://feed.example/list")
	feed.BindAddress = netip.MustParseAddr("192.0.2.10")
	if request, reason := stage.request(feed); reason != "" || request.BindAddr != feed.BindAddress {
		t.Fatalf("request = %+v (%q), want BindAddr %v", request, reason, feed.BindAddress)
	}
}

// Each parse failure is one record, as pfb_parse_fail_log() writes it, to the writer the caller passes.
func TestParseFailureRecordsGoToTheCallersWriter(t *testing.T) {
	stage := testStage(t)
	var records strings.Builder
	stage.ParseErrors = &records
	feed := Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled", Format: "auto", Custom: true,
		CustomText: "203.0.113.21\n1.2.3.4.5\n300.1.1.1\n"}
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	if got.Disposition != "changed" || got.Entries != 1 || got.ParseFailures != 2 {
		t.Fatalf("run = %+v, want one entry and two parse failures", got)
	}
	lines := strings.Split(strings.TrimSuffix(records.String(), "\n"), "\n")
	want := []string{`Test_custom_v4,1\.2\.3\.4\.5,1\.2\.3\.4\.5,2`, `Test_custom_v4,300\.1\.1\.1,300\.1\.1\.1,3`}
	if len(lines) != len(want) {
		t.Fatalf("records = %q, want %d rows", records.String(), len(want))
	}
	for i, line := range lines {
		if !regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,` + want[i] + `$`).MatchString(line) {
			t.Errorf("record %d = %q, want <timestamp>,%s", i, line, want[i])
		}
	}
}
