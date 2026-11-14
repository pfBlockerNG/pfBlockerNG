package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

type feedPhaseTestBackend struct {
	stored settings.Stored
}

func (b *feedPhaseTestBackend) Read(context.Context) (settings.Stored, error) {
	return b.stored, nil
}

func (b *feedPhaseTestBackend) Write(context.Context, uint64, map[string]map[string]any) (uint64, error) {
	return 0, errors.New("unexpected settings write")
}

func feedPhaseTestRunner(t *testing.T, kind, state, format, source, credentials string, preScript ...string) *feedPhaseRunner {
	t.Helper()
	groupAction := "Deny_Inbound"
	if kind == "dnsbl" {
		groupAction = "unbound"
	}
	source = strings.Replace(source, "127.0.0.1", "feed.example", 1)
	row := map[string]any{"header": "feed", "state": state, "format": format, "url": source, "credentials": credentials}
	if kind == "dnsbl" {
		row["action"] = "deny"
	}
	group := map[string]any{"name": "Test", "action": groupAction, "feeds": []any{row}}
	if len(preScript) > 0 {
		group["preScript"] = preScript[0]
	}
	encoded, err := json.Marshal([]any{group})
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Load(&feedPhaseTestBackend{stored: settings.Stored{
		Initialized: true, Revision: 1,
		Projections: map[string]map[string]json.RawMessage{
			"feeds/" + kind: {"groups": encoded},
			"ingest": {
				"feedHostFilter":    json.RawMessage("true"),
				"feedHostAllowlist": json.RawMessage(`[{"cidr":"127.0.0.1/32"}]`),
				"dnsblIp":           json.RawMessage("true"),
				"suppression":       json.RawMessage("false"),
			},
		},
	}}, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	ipOrig, dnsblOrig, dbDir := t.TempDir(), t.TempDir(), t.TempDir()
	runner := newFeedPhaseRunner(store, feedFlags{OrigDir: ipOrig, DNSBLOrigDir: dnsblOrig, DBDir: dbDir})
	runner.fetcher.Policy.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	return runner
}

func TestFeedPhaseProbeReuseAndForceModes(t *testing.T) {
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
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", server.URL+"/feed", "user:"+secret)
	if err := os.WriteFile(filepath.Join(runner.flags.OrigDir, "feed_v4.orig"), []byte("203.0.113.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.fetcher.RetryDelay = time.Nanosecond

	var updateLog strings.Builder
	call := func(force string) FeedPhaseResult {
		t.Helper()
		got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, force, &updateLog)
		if err != nil || len(got) != 1 {
			t.Fatalf("FeedPhase(%q) = %+v, %v", force, got, err)
		}
		return got[0]
	}
	first := call("none")
	if first.Disposition != "changed" || first.Entries != 1 || requests.Load() != 1 {
		t.Fatalf("first probe+ingest = %+v after %d HTTP requests, want changed/one entry/one request", first, requests.Load())
	}
	etag, err := os.ReadFile(filepath.Join(runner.flags.OrigDir, "feed_v4.orig.etag"))
	if err != nil || string(etag) != `"same"` {
		t.Fatalf("the changed probe's ETag = %q (%v), want it beside the published baseline", etag, err)
	}
	parsed := filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip")
	if got, err := os.ReadFile(parsed); err != nil || string(got) != "203.0.113.1\n" {
		t.Fatalf("parsed IP artifact = %q (%v)", got, err)
	}
	if raw, _ := json.Marshal(first); strings.Contains(string(raw), secret) || strings.Contains(string(raw), server.URL) {
		t.Fatalf("FeedPhase result exposed a secret or URL: %s", raw)
	}

	if got := call("none"); got.Disposition != "unchanged" || requests.Load() != 2 || conditional.Load() != 1 {
		t.Fatalf("unchanged probe = %+v after %d requests (%d conditional), want one conditional request", got, requests.Load(), conditional.Load())
	}
	if got := call("parse"); got.Disposition != "reparsed" || requests.Load() != 2 {
		t.Fatalf("parse force = %+v after %d HTTP requests, want reparsed without a request", got, requests.Load())
	}
	if got := call("download"); got.Disposition != "changed" || requests.Load() != 3 || conditional.Load() != 1 {
		t.Fatalf("download force = %+v after %d requests (%d conditional), want one unconditional fetch", got, requests.Load(), conditional.Load())
	}
	if got := call("both"); got.Disposition != "changed" || requests.Load() != 4 || conditional.Load() != 1 {
		t.Fatalf("both force = %+v after %d requests (%d conditional), want one unconditional fetch", got, requests.Load(), conditional.Load())
	}
	if strings.Contains(updateLog.String(), secret) || strings.Contains(updateLog.String(), server.URL) {
		t.Fatalf("Update log exposed a secret or URL: %s", updateLog.String())
	}
}

func TestFeedPhaseFailureKeepsLastGoodOriginalAndParsedArtifacts(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "rejected", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("203.0.113.9\n"))
	}))
	defer server.Close()
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", server.URL+"/feed", "")
	runner.fetcher.RetryDelay = time.Nanosecond
	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" {
		t.Fatalf("initial FeedPhase = %+v, %v", got, err)
	}
	orig := filepath.Join(runner.flags.OrigDir, "feed_v4.orig")
	parsed := filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip")
	beforeOrig, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	beforeParsed, err := os.ReadFile(parsed)
	if err != nil {
		t.Fatal(err)
	}

	fail.Store(true)
	got, err = runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "failed" {
		t.Fatalf("failed FeedPhase = %+v, %v", got, err)
	}
	afterOrig, _ := os.ReadFile(orig)
	afterParsed, _ := os.ReadFile(parsed)
	if string(afterOrig) != string(beforeOrig) || string(afterParsed) != string(beforeParsed) {
		t.Fatalf("failed feed changed last-known-good artifacts: orig %q -> %q; parsed %q -> %q", beforeOrig, afterOrig, beforeParsed, afterParsed)
	}
}

func TestFeedPhaseFailureReasonDoesNotExposeLocalPaths(t *testing.T) {
	dir := t.TempDir()
	source := "file://" + filepath.Join(dir, "missing-feed")
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", source, "")
	runner.flags.LocalDirs = []string{dir}

	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "failed" {
		t.Fatalf("FeedPhase for missing local feed = %+v, %v", got, err)
	}
	result, _ := json.Marshal(got[0])
	if got[0].Reason != "feed_probe_failed" || strings.Contains(string(result), dir) || strings.Contains(string(result), source) {
		t.Fatalf("FeedPhase failure exposed its local source: %s", result)
	}
}

func TestFeedPhasePropagatesSafeFetcherFailureReasons(t *testing.T) {
	secret := "feed-secret-never-return"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer server.Close()
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", server.URL+"/feed", "user:"+secret)
	runner.fetcher.RetryDelay = time.Nanosecond
	if err := os.WriteFile(filepath.Join(runner.flags.OrigDir, "feed_v4.orig"), []byte("203.0.113.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		force, stage string
	}{
		{"none", "probe"},
		{"download", "fetch"},
	} {
		var updateLog strings.Builder
		got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, tc.force, &updateLog)
		if err != nil || len(got) != 1 || got[0].Disposition != "failed" || got[0].Stage != tc.stage ||
			got[0].Reason != "404 Not Found" {
			t.Fatalf("FeedPhase(%q) failure = %+v, %v; want feedfetch's safe status reason", tc.force, got, err)
		}
		result, _ := json.Marshal(got[0])
		for _, private := range []string{secret, server.URL} {
			if strings.Contains(string(result), private) || strings.Contains(updateLog.String(), private) {
				t.Fatalf("FeedPhase(%q) exposed a secret or URL: result %s, log %q", tc.force, result, updateLog.String())
			}
		}
	}
}

func TestFeedPhaseHoldsDisabledBaselineAndWithoutBaseline(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     string
		hasOrig   bool
		preScript string
		want      string
	}{
		{"held without baseline", "hold", false, "", "held"},
		{"held baseline with script", "hold", true, "pre.sh", "reparsed"},
		{"disabled row", "disabled", false, "", "held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("held/disabled feed made a network request")
			}))
			defer server.Close()
			runner := feedPhaseTestRunner(t, "ipv4", tc.state, "auto", server.URL+"/feed", "", tc.preScript)
			if tc.hasOrig {
				if err := os.WriteFile(filepath.Join(runner.flags.OrigDir, "feed_v4.orig"), []byte("203.0.113.7\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				runner.flags.ScriptDirs = []string{dir}
				if err := os.WriteFile(filepath.Join(dir, tc.preScript), []byte("#!/bin/sh\ntrue\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
			if err != nil || len(got) != 1 || got[0].Disposition != tc.want {
				t.Fatalf("FeedPhase for %s = %+v, %v; want %s", tc.name, got, err, tc.want)
			}
		})
	}
}

func TestResolveListScriptMatchesOutpostContainmentCases(t *testing.T) {
	root := t.TempDir()
	primary, legacy, outside := filepath.Join(root, "list_scripts"), filepath.Join(root, "legacy"), filepath.Join(root, "outside")
	for _, dir := range []string{primary, legacy, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	makeFile := func(dir, name string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	nonexec := makeFile(primary, "ip_pre_noexec.sh", 0o644)
	legacyFile := makeFile(legacy, "ip_pre_legacy.sh", 0o755)
	outsideFile := makeFile(outside, "escape.sh", 0o755)
	makeFile(legacy, "victim.sh", 0o755)
	if err := os.Symlink(outsideFile, filepath.Join(primary, "ip_pre_escape.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, filepath.Join(primary, "ip_pre_todir.sh")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		input string
		dirs  []string
		want  string
	}{
		{name: "non-executable regular file", input: "ip_pre_noexec.sh", dirs: []string{primary, legacy}, want: nonexec},
		{name: "legacy fallback", input: "ip_pre_legacy.sh", dirs: []string{primary, legacy}, want: legacyFile},
		{name: "escaping symlink", input: "ip_pre_escape.sh", dirs: []string{primary, legacy}, want: ""},
		{name: "symlink to a directory", input: "ip_pre_todir.sh", dirs: []string{primary, legacy}, want: ""},
		{name: "traversal basename", input: "../legacy/victim.sh", dirs: []string{primary}, want: ""},
		{name: "subpath basename", input: "subdir/ip_pre_subpath.sh", dirs: []string{primary, legacy}, want: ""},
		{name: "empty name", input: "", dirs: []string{primary, legacy}, want: ""},
		{name: "root name", input: string(filepath.Separator), dirs: []string{primary, legacy}, want: ""},
	} {
		got := resolveListScript(tc.input, tc.dirs)
		if got != tc.want {
			t.Errorf("resolveListScript(%q, dirs) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestFeedPhaseDNSBLPublishesBothEmptyFamilySignalsAndRetainsThemOnFailure(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "rejected", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("example.test\n"))
	}))
	defer server.Close()
	runner := feedPhaseTestRunner(t, "dnsbl", "enabled", "auto", server.URL+"/feed", "")
	runner.fetcher.RetryDelay = time.Nanosecond

	got, err := runner.run(context.Background(), "dnsbl", []string{"dnsbl:feed"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 {
		t.Fatalf("DNSBL FeedPhase = %+v, %v", got, err)
	}
	result := got[0]
	if result.Disposition != "changed" || result.DNSBLRows != 1 || result.IPv4Count != 0 || result.IPv6Count != 0 {
		t.Fatalf("DNSBL result = %+v, want one row and explicit empty IP families", result)
	}
	names := []string{"feed.parsed.ndjson", "feed.parsed.v4.ip", "feed.parsed.v6.ip"}
	before := make(map[string]string, len(names))
	for _, name := range names {
		path := filepath.Join(runner.flags.DNSBLOrigDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		before[name] = string(data)
		if strings.HasSuffix(name, ".ip") && len(data) != 0 {
			t.Errorf("empty family sidecar %s = %q, want empty", name, data)
		}
	}

	fail.Store(true)
	got, err = runner.run(context.Background(), "dnsbl", []string{"dnsbl:feed"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "failed" {
		t.Fatalf("failed DNSBL FeedPhase = %+v, %v", got, err)
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(runner.flags.DNSBLOrigDir, name))
		if err != nil || string(data) != before[name] {
			t.Errorf("failed DNSBL phase changed %s: %q (%v)", name, data, err)
		}
	}
}

func TestFeedPhaseWhoisKeepsPartialResolutionAndReportsFailure(t *testing.T) {
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "whois", "one.example,bad.example", "")
	runner.fetcher.Lookup = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host == "one.example" {
			return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
		}
		return nil, errors.New("lookup failed")
	}

	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 {
		t.Fatalf("WHOIS FeedPhase = %+v, %v", got, err)
	}
	if got[0].Disposition != "failed" || got[0].Stage != "whois" || got[0].Entries != 1 {
		t.Fatalf("partial WHOIS result = %+v, want one retained entry and a whois-stage failure", got[0])
	}
	data, err := os.ReadFile(filepath.Join(runner.flags.OrigDir, "feed_v4.orig"))
	if err != nil || !strings.Contains(string(data), "203.0.113.19") {
		t.Fatalf("partial WHOIS baseline = %q (%v), want the resolved address", data, err)
	}
}

func TestFeedPhaseMissingASNDatabaseReportsReasonAndKeepsLastGoodArtifacts(t *testing.T) {
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "asn", "AS64500", "")
	orig := filepath.Join(runner.flags.OrigDir, "feed_v4.orig")
	parsed := filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip")
	for path, content := range map[string]string{orig: "203.0.113.30\n", parsed: "203.0.113.30\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 {
		t.Fatalf("FeedPhase for a missing ASN database = %+v, %v", got, err)
	}
	if got[0].Disposition != "failed" || got[0].Stage != "whois" || got[0].Reason != "asn_database_missing" {
		t.Fatalf("missing ASN database result = %+v, want a named whois failure", got[0])
	}
	for path, want := range map[string]string{orig: "203.0.113.30\n", parsed: "203.0.113.30\n"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Errorf("missing ASN database changed %s: %q (%v)", filepath.Base(path), data, err)
		}
	}
	if _, err := os.Stat(filepath.Join(runner.flags.OrigDir, "feed_v4.fail")); err != nil {
		t.Errorf("missing ASN database did not leave a failure marker: %v", err)
	}
	partial := feedPhaseTestRunner(t, "ipv4", "enabled", "whois", "one.example,AS64500", "")
	partial.fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.31")}, nil
	}
	if err := os.WriteFile(filepath.Join(partial.flags.OrigDir, "feed_v4.orig"), []byte("203.0.113.32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = partial.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Reason != "asn_database_missing" || got[0].Entries != 1 {
		t.Fatalf("partial WHOIS result with a missing ASN database = %+v, %v", got, err)
	}
	data, err := os.ReadFile(filepath.Join(partial.flags.OrigDir, "feed_v4.orig"))
	if err != nil || !strings.Contains(string(data), "203.0.113.31") {
		t.Fatalf("partial WHOIS baseline = %q (%v), want the resolved domain address", data, err)
	}
}

func TestFeedPhaseCountsMappedDropsWithoutEmptyPlaceholder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("::ffff:192.0.2.1\n"))
	}))
	defer server.Close()
	runner := feedPhaseTestRunner(t, "ipv6", "enabled", "auto", server.URL+"/feed", "")

	got, err := runner.run(context.Background(), "ip", []string{"ipv6:feed_v6"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 {
		t.Fatalf("IPv6 FeedPhase = %+v, %v", got, err)
	}
	result := got[0]
	if result.MappedDrops != 1 || result.ParseFailures != 1 || result.Entries != 0 || result.Placeholder != "" {
		t.Fatalf("IPv6 result = %+v, want one mapped drop, one parse failure and an empty-feed signal", result)
	}
}

func customFeedPhaseTestRunner(t *testing.T, kind, content string) *feedPhaseRunner {
	t.Helper()
	action := "Deny_Inbound"
	if kind == "dnsbl" {
		action = "unbound"
	}
	group, err := json.Marshal([]any{map[string]any{
		"name": "Test", "action": action, "customList": content, "feeds": []any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Load(&feedPhaseTestBackend{stored: settings.Stored{
		Initialized: true, Revision: 1,
		Projections: map[string]map[string]json.RawMessage{
			"feeds/" + kind: {"groups": group},
			"ingest":        {"feedHostFilter": json.RawMessage("false"), "dnsblIp": json.RawMessage("true"), "suppression": json.RawMessage("false")},
		},
	}}, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	ipOrig, dnsblOrig, dbDir := t.TempDir(), t.TempDir(), t.TempDir()
	return newFeedPhaseRunner(store, feedFlags{OrigDir: ipOrig, DNSBLOrigDir: dnsblOrig, DBDir: dbDir})
}

func TestFeedPhaseUsesStableCustomAndSyntheticIDs(t *testing.T) {
	ip := customFeedPhaseTestRunner(t, "ipv4", "203.0.113.21\n")
	got, err := ip.run(context.Background(), "ip", []string{"custom:ipv4:Test"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].Entries != 1 {
		t.Fatalf("custom IP FeedPhase = %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(ip.flags.OrigDir, "Test_custom_v4.parsed.ip")); err != nil {
		t.Fatalf("custom IP parsed artifact: %v", err)
	}

	dnsbl := customFeedPhaseTestRunner(t, "dnsbl", "example.test\n")
	got, err = dnsbl.run(context.Background(), "dnsbl", []string{"custom:dnsbl:Test"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].DNSBLRows != 1 {
		t.Fatalf("custom DNSBL FeedPhase = %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dnsbl.flags.DNSBLOrigDir, "Test_custom.parsed.ndjson")); err != nil {
		t.Fatalf("custom DNSBL parsed artifact: %v", err)
	}

	if err := os.WriteFile(filepath.Join(ip.flags.DBDir, "DNSBLIP_v4.txt"), []byte("203.0.113.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ip.run(context.Background(), "ip", []string{"synthetic:ipv4:DNSBLIP_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].Entries != 1 {
		t.Fatalf("synthetic DNSBLIP FeedPhase = %+v, %v", got, err)
	}
}

func TestFeedPhaseRunsPreScriptAndKeepsOldArtifactsWhenItFails(t *testing.T) {
	scriptDir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '203.0.113.88' > \"$1\"\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "rewrite.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "http://example.test/feed", "", "rewrite.sh")
	runner.flags.ScriptDirs = []string{scriptDir}
	orig := filepath.Join(runner.flags.OrigDir, "feed_v4.orig")
	if err := os.WriteFile(orig, []byte("203.0.113.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "parse", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "reparsed" || got[0].PreScriptFailed {
		t.Fatalf("successful pre-script FeedPhase = %+v, %v", got, err)
	}
	parsed := filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip")
	if data, err := os.ReadFile(parsed); err != nil || string(data) != "203.0.113.88\n" {
		t.Fatalf("pre-script parsed bytes = %q (%v)", data, err)
	}
	if data, err := os.ReadFile(orig); err != nil || string(data) != "203.0.113.1\n" {
		t.Fatalf("pre-script changed the raw baseline: %q (%v)", data, err)
	}

	bad := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "http://example.test/feed", "", "missing.sh")
	bad.flags.ScriptDirs = []string{scriptDir}
	badOrig := filepath.Join(bad.flags.OrigDir, "feed_v4.orig")
	badParsed := filepath.Join(bad.flags.OrigDir, "feed_v4.parsed.ip")
	if err := os.WriteFile(badOrig, []byte("203.0.113.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badParsed, []byte("203.0.113.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = bad.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "parse", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "failed" || !got[0].PreScriptFailed || got[0].Stage != "script" {
		t.Fatalf("missing pre-script FeedPhase = %+v, %v", got, err)
	}
	for _, path := range []string{badOrig, badParsed} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "203.0.113.") {
			t.Fatalf("pre-script failure changed %s: %q (%v)", filepath.Base(path), data, err)
		}
	}
}

func TestFeedPhasePublishesParsedArtifactsAtomically(t *testing.T) {
	dir := t.TempDir()
	names := []string{"first.parsed.ip", "second.parsed.ip"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staged := filepath.Join(dir, ".staged-first")
	if err := os.WriteFile(staged, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := publishStaged(dir, []stagedFeedFile{
		{name: names[0], temp: staged},
		{name: names[1], temp: filepath.Join(dir, ".missing-stage")},
	})
	if err == nil {
		t.Fatal("publication with a missing staged artifact succeeded")
	}
	for _, name := range names {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(got) != "old\n" {
			t.Errorf("failed publication changed %s: %q (%v)", name, got, err)
		}
	}
}

func feedPhaseFTP(t *testing.T, body string) (string, *atomic.Int32) {
	t.Helper()
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	retrieved := &atomic.Int32{}
	go func() {
		conn, err := control.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_, _ = io.WriteString(conn, "220 feed phase fixture\r\n")
		var data net.Listener
		defer func() {
			if data != nil {
				data.Close()
			}
		}()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command, _, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch strings.ToUpper(command) {
			case "USER":
				_, _ = io.WriteString(conn, "331 password\r\n")
			case "PASS":
				_, _ = io.WriteString(conn, "230 logged in\r\n")
			case "MDTM":
				_, _ = io.WriteString(conn, "550 unavailable\r\n")
			case "EPSV":
				data, err = net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return
				}
				port := data.Addr().(*net.TCPAddr).Port
				_, _ = fmt.Fprintf(conn, "229 Entering Extended Passive Mode (|||%d|)\r\n", port)
			case "TYPE":
				_, _ = io.WriteString(conn, "200 type set\r\n")
			case "SIZE":
				_, _ = fmt.Fprintf(conn, "213 %d\r\n", len(body))
			case "RETR":
				retrieved.Add(1)
				_, _ = io.WriteString(conn, "150 opening data connection\r\n")
				dataConn, err := data.Accept()
				if err != nil {
					return
				}
				_, _ = io.WriteString(dataConn, body)
				_ = dataConn.Close()
				_ = data.Close()
				data = nil
				_, _ = io.WriteString(conn, "226 transfer complete\r\n")
			case "QUIT":
				_, _ = io.WriteString(conn, "221 goodbye\r\n")
				return
			default:
				_, _ = io.WriteString(conn, "200 ok\r\n")
			}
		}
	}()
	return fmt.Sprintf("ftp://feed.example:%d/list.txt", control.Addr().(*net.TCPAddr).Port), retrieved
}

func TestFeedPhaseIngestsFTPWithoutUnsupportedProbe(t *testing.T) {
	source, retrieved := feedPhaseFTP(t, "203.0.113.42\n")
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", source, "")
	runner.fetcher.RetryDelay = time.Nanosecond
	orig := filepath.Join(runner.flags.OrigDir, "feed_v4.orig")
	if err := os.WriteFile(orig, []byte("203.0.113.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].Entries != 1 || retrieved.Load() != 1 {
		t.Fatalf("FTP FeedPhase = %+v, %v after %d RETR commands; want changed/one entry/one fetch", got, err, retrieved.Load())
	}
	parsed, err := os.ReadFile(filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip"))
	if err != nil || string(parsed) != "203.0.113.42\n" {
		t.Fatalf("FTP parsed artifact = %q (%v)", parsed, err)
	}
}
