package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

func TestBlacklistFeedPhaseIDsRejectPathComponents(t *testing.T) {
	valid := "blacklist:work-provider:adult-category"
	if !validFeedPhaseID("dnsbl", valid) {
		t.Fatalf("valid blacklist ID %q was refused", valid)
	}
	if !validFeedPhaseID("dnsbl", "blacklist:work:a.b_c") {
		t.Fatal("a dotted blacklist category was refused")
	}
	for _, id := range []string{
		"blacklist:../work:adult",
		"blacklist:/tmp:adult",
		"blacklist:work:../adult",
		"blacklist:work:..",
		"blacklist:work:ad/ult",
	} {
		if validFeedPhaseID("dnsbl", id) {
			t.Errorf("unsafe blacklist ID %q was accepted", id)
		}
	}
	if validFeedPhaseID("ip", valid) {
		t.Fatalf("blacklist ID %q was accepted in the IP phase", valid)
	}
}

func blacklistPhaseTestRunner(t *testing.T, sourceDir, origDir string) *feedPhaseRunner {
	t.Helper()
	provider, err := json.Marshal([]any{
		map[string]any{"id": "work", "title": "Work", "selected": true, "categories": "adult"},
		map[string]any{"id": "ut2", "title": "UT2", "selected": true, "categories": "a.b_c"},
	})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := json.Marshal([]any{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Load(&feedPhaseTestBackend{stored: settings.Stored{
		Initialized: true,
		Revision:    1,
		Projections: map[string]map[string]json.RawMessage{
			"feeds/dnsbl": {"groups": groups},
			"schedule":    {"categoryProviders": provider},
			"ingest": {
				"feedHostFilter":    json.RawMessage("true"),
				"feedHostAllowlist": json.RawMessage(`[]`),
				"dnsblIp":           json.RawMessage("true"),
				"suppression":       json.RawMessage("false"),
			},
		},
	}}, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	flags := feedFlags{DNSBLOrigDir: origDir, LocalDirs: []string{sourceDir}, DBDir: t.TempDir()}
	blacklistDir := reflect.ValueOf(&flags).Elem().FieldByName("BlacklistDir")
	if !blacklistDir.IsValid() || !blacklistDir.CanSet() || blacklistDir.Kind() != reflect.String {
		t.Fatal("feedFlags must expose the trusted BlacklistDir flag")
	}
	blacklistDir.SetString(sourceDir)
	runner := newFeedPhaseRunner(store, flags)
	runner.fetcher.RetryDelay = time.Nanosecond
	runner.fetcher.Policy.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return runner
}

func TestFeedPhaseParsesBlacklistCategoryWithConfiguredTitleAndLocalSource(t *testing.T) {
	sourceDir, origDir := t.TempDir(), t.TempDir()
	providerDir := filepath.Join(sourceDir, "work")
	if err := os.Mkdir(providerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(providerDir, "work_adult")
	if err := os.WriteFile(source, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := blacklistPhaseTestRunner(t, sourceDir, origDir)
	var updateLog strings.Builder

	got, err := runner.run(context.Background(), "dnsbl", []string{"blacklist:work:adult"}, "none", &updateLog)
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].DNSBLRows != 1 {
		t.Fatalf("blacklist FeedPhase = %+v, %v; want changed with one DNSBL row", got, err)
	}
	baseline := filepath.Join(origDir, "Work_adult.orig")
	parsed := filepath.Join(origDir, "Work_adult.parsed.ndjson")
	if body, err := os.ReadFile(baseline); err != nil || string(body) != "example.com\n" {
		t.Fatalf("blacklist baseline = %q, %v; want source bytes", body, err)
	}
	if body, err := os.ReadFile(parsed); err != nil || !strings.Contains(string(body), "example.com") {
		t.Fatalf("blacklist artifact = %q, %v; want Work_adult NDJSON", body, err)
	}
	for _, suffix := range []string{".parsed.v4.ip", ".parsed.v6.ip"} {
		if _, err := os.Stat(filepath.Join(origDir, "Work_adult"+suffix)); err != nil {
			t.Fatalf("blacklist family artifact %s: %v", suffix, err)
		}
	}

	got, err = runner.run(context.Background(), "dnsbl", []string{"blacklist:work:adult"}, "none", &updateLog)
	if err != nil || len(got) != 1 || got[0].Disposition != "unchanged" {
		t.Fatalf("unchanged blacklist FeedPhase = %+v, %v; want unchanged", got, err)
	}
}

func TestFeedPhaseBlacklistCategoryPreservesDotsInSourceAndHeader(t *testing.T) {
	sourceDir, origDir := t.TempDir(), t.TempDir()
	providerDir := filepath.Join(sourceDir, "ut2")
	if err := os.Mkdir(providerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(providerDir, "ut2_a.b_c")
	if err := os.WriteFile(source, []byte("dot.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := blacklistPhaseTestRunner(t, sourceDir, origDir)

	got, err := runner.run(context.Background(), "dnsbl", []string{"blacklist:ut2:a.b_c"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" || got[0].DNSBLRows != 1 {
		t.Fatalf("dotted blacklist FeedPhase = %+v, %v; want changed with one row", got, err)
	}
	baseline := filepath.Join(origDir, "UT2_a.b_c.orig")
	parsed := filepath.Join(origDir, "UT2_a.b_c.parsed.ndjson")
	if body, err := os.ReadFile(baseline); err != nil || string(body) != "dot.example\n" {
		t.Fatalf("dotted blacklist source baseline = %q, %v", body, err)
	}
	if body, err := os.ReadFile(parsed); err != nil || !strings.Contains(string(body), "dot.example") {
		t.Fatalf("dotted blacklist parsed artifact = %q, %v", body, err)
	}
}

func TestFeedPhaseMissingBlacklistSourceKeepsLastKnownGoodArtifacts(t *testing.T) {
	sourceDir, origDir := t.TempDir(), t.TempDir()
	providerDir := filepath.Join(sourceDir, "work")
	if err := os.Mkdir(providerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(providerDir, "work_adult")
	if err := os.WriteFile(source, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := blacklistPhaseTestRunner(t, sourceDir, origDir)
	got, err := runner.run(context.Background(), "dnsbl", []string{"blacklist:work:adult"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" {
		t.Fatalf("initial blacklist FeedPhase = %+v, %v", got, err)
	}
	baseline := filepath.Join(origDir, "Work_adult.orig")
	parsed := filepath.Join(origDir, "Work_adult.parsed.ndjson")
	beforeBaseline, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	beforeParsed, err := os.ReadFile(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}

	got, err = runner.run(context.Background(), "dnsbl", []string{"blacklist:work:adult"}, "none", &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition != "failed" || got[0].Stage != "probe" || got[0].Reason == "" {
		t.Fatalf("missing blacklist source = %+v, %v; want a named probe failure", got, err)
	}
	afterBaseline, _ := os.ReadFile(baseline)
	afterParsed, _ := os.ReadFile(parsed)
	if string(afterBaseline) != string(beforeBaseline) || string(afterParsed) != string(beforeParsed) {
		t.Fatalf("missing blacklist source changed last-known-good artifacts: baseline %q -> %q; parsed %q -> %q",
			beforeBaseline, afterBaseline, beforeParsed, afterParsed)
	}
}
