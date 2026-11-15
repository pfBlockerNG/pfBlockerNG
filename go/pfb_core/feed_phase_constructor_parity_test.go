package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

func constructorGzip(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func constructorFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s = %q, %v; want %q", path, got, err, want)
	}
}

func TestConstructorETFirstDownload(t *testing.T) {
	for _, tc := range []struct{ name, block, match, wantBlock, wantMatch string }{
		{"empty", `[]`, `[]`, "", ""},
		{"block", `[{"category":"ET_Cnc"}]`, `[]`, "198.51.100.1\n", ""},
		{"match", `[]`, `[{"category":"ET_Bot"}]`, "", "198.51.100.2\n"},
		{"both", `[{"category":"ET_Cnc"}]`, `[{"category":"ET_Bot"}]`, "198.51.100.1\n", "198.51.100.2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			raw := constructorGzip(t, "198.51.100.1,1,90\n198.51.100.2,2,80\n")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("ETag", `"et-v1"`)
				w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			runner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{
				"etBlockCategories": json.RawMessage(tc.block), "etMatchCategories": json.RawMessage(tc.match),
			}, "ipv4", "enabled", "auto", server.URL+"/iprepdata.txt", "user:constructor-secret")
			for _, dir := range []string{filepath.Join(runner.flags.DBDir, "ET"), filepath.Join(runner.flags.DBDir, "match", "generated")} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var log strings.Builder
			results, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "download", &log)
			if err != nil || len(results) != 1 || results[0].Disposition != "changed" {
				t.Fatalf("actual constructor ET = %+v, %v", results, err)
			}
			if requests.Load() != 1 {
				t.Fatalf("requests = %d", requests.Load())
			}
			base := filepath.Join(runner.flags.OrigDir, "feed_v4")
			constructorFile(t, base+".orig", tc.wantBlock)
			constructorFile(t, filepath.Join(runner.flags.DBDir, "ET", "ET_Cnc.txt"), "198.51.100.1\n")
			constructorFile(t, filepath.Join(runner.flags.DBDir, "ET", "ET_Bot.txt"), "198.51.100.2\n")
			if tc.wantMatch != "" {
				constructorFile(t, filepath.Join(runner.flags.DBDir, "match", "generated", "pfB_Match_ET_v4.txt"), tc.wantMatch)
			}
			constructorFile(t, base+".orig.etag", `"et-v1"`)
			if b, err := os.ReadFile(base + ".orig.xxhash128"); err != nil || len(b) == 0 {
				t.Fatalf("wire digest = %q, %v", b, err)
			}
			if b, err := os.ReadFile(base + ".raw"); err != nil || !bytes.Equal(b, raw) {
				t.Fatalf("retained gzip raw differs: %v", err)
			}
			if b, _ := json.Marshal(results); strings.Contains(string(b)+log.String(), "constructor-secret") || strings.Contains(string(b)+log.String(), server.URL) {
				t.Fatal("result/log leaked credentials or URL")
			}
		})
	}
}

func TestConstructorETTrustedPathsAndExplicitConfiguration(t *testing.T) {
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "https://example.com/iprepdata.txt", "")
	for _, root := range []string{"", "relative"} {
		runner.flags.DBDir = root
		f, err := runner.fetcherFor(nil)
		if err != nil || f.ETDir != "" || f.ETMatchFile != "" {
			t.Fatalf("root %q generated paths: %+v, %v", root, f, err)
		}
	}
	runner.fetcher.ETDir, runner.fetcher.ETMatchFile = t.TempDir(), filepath.Join(t.TempDir(), "match.txt")
	f, err := runner.fetcherFor(nil)
	if err != nil || f.ETDir != runner.fetcher.ETDir || f.ETMatchFile != runner.fetcher.ETMatchFile {
		t.Fatalf("explicit ET paths lost: %+v, %v", f, err)
	}
}

func TestConstructorSanityWireAndExtractedHTML(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			t.Run(strings.Join([]string{map[bool]string{false: "wire", true: "gzip"}[compressed], map[bool]string{false: "off", true: "on"}[enabled]}, "/"), func(t *testing.T) {
				body := []byte("<!doctype html><html><title>Access Denied</title><body>Access Denied</body></html>\n")
				if compressed {
					body = constructorGzip(t, string(body))
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
				defer server.Close()
				runner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{"feedSanity": json.RawMessage(map[bool]string{false: "false", true: "true"}[enabled])}, "ipv4", "enabled", "auto", server.URL+"/error.txt", "")
				results, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "download", nil)
				if err != nil || len(results) != 1 {
					t.Fatalf("run = %+v, %v", results, err)
				}
				if enabled && (results[0].Disposition != "failed" || results[0].Stage != "fetch") {
					t.Fatalf("enabled sanity accepted HTML: %+v", results[0])
				}
				if !enabled && results[0].Disposition != "changed" {
					t.Fatalf("disabled sanity refused HTML: %+v", results[0])
				}
			})
		}
	}
}

func TestConstructorETDefaultSelectionsReachConsumer(t *testing.T) {
	// This uses only pre-existing schema fields, so the RED proves the real constructor fails ET independently of new schema validation.
	raw := constructorGzip(t, "198.51.100.1,1,90\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
	defer server.Close()
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", server.URL+"/iprepdata.txt", "")
	for _, dir := range []string{filepath.Join(runner.flags.DBDir, "ET"), filepath.Join(runner.flags.DBDir, "match", "generated")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "download", nil)
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" {
		t.Fatalf("default ET constructor = %+v, %v", got, err)
	}
	constructorFile(t, filepath.Join(runner.flags.OrigDir, "feed_v4.orig"), "")
}

// The API assertion is runtime, not a missing-method build failure on the frozen source.
func TestConstructorETReprocessAPI(t *testing.T) {
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "https://example.com/iprepdata.txt", "")
	if _, ok := any(runner.fetcher).(interface {
		ReprocessET(context.Context, feedfetch.Feed, feedfetch.Request) feedfetch.Result
	}); !ok {
		t.Fatal("Fetcher lacks retained-raw ET reprocessing")
	}
}

func TestConstructorETCategoryChangeReusesRetainedGzip(t *testing.T) {
	var requests atomic.Int32
	raw := constructorGzip(t, "198.51.100.1,1,90\n198.51.100.2,2,80\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	runner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{
		"etBlockCategories": json.RawMessage(`[{"category":"ET_Cnc"}]`),
		"etMatchCategories": json.RawMessage(`[{"category":"ET_Bot"}]`),
	}, "ipv4", "enabled", "auto", server.URL+"/iprepdata.txt", "")
	for _, dir := range []string{filepath.Join(runner.flags.DBDir, "ET"), filepath.Join(runner.flags.DBDir, "match", "generated")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "download", nil)
	if err != nil || len(got) != 1 || got[0].Disposition != "changed" {
		t.Fatalf("initial ET: %+v, %v", got, err)
	}
	ingest, err := runner.store.GetClear("ingest")
	if err != nil {
		t.Fatal(err)
	}
	ingest["etBlockCategories"] = []any{map[string]any{"category": "ET_Bot"}}
	ingest["etMatchCategories"] = []any{map[string]any{"category": "ET_Cnc"}}
	fetcher, err := runner.fetcherFor(ingest)
	if err != nil {
		t.Fatal(err)
	}
	api, ok := any(fetcher).(interface {
		ReprocessET(context.Context, feedfetch.Feed, feedfetch.Request) feedfetch.Result
	})
	if !ok {
		t.Fatal("constructor fetcher lacks ReprocessET")
	}
	feed := feedfetch.Feed{Dir: runner.flags.OrigDir, Name: "feed_v4"}
	result := api.ReprocessET(context.Background(), feed, feedfetch.Request{URL: server.URL + "/iprepdata.txt"})
	if !result.OK || result.Decision != feedfetch.Changed || requests.Load() != 1 {
		t.Fatalf("retained-raw reselection: %+v; requests %d", result, requests.Load())
	}
	constructorFile(t, filepath.Join(feed.Dir, "feed_v4.orig"), "198.51.100.2\n")
	constructorFile(t, filepath.Join(runner.flags.DBDir, "match", "generated", "pfB_Match_ET_v4.txt"), "198.51.100.1\n")
}

func TestConstructorETRefusesRelativeExplicitPaths(t *testing.T) {
	for _, match := range []bool{false, true} {
		runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "https://example.com/iprepdata.txt", "")
		runner.flags.DBDir = ""
		if match {
			runner.fetcher.ETMatchFile = "relative/match.txt"
		} else {
			runner.fetcher.ETDir = "relative/ET"
		}
		if _, err := runner.fetcherFor(nil); err == nil {
			t.Fatalf("relative explicit ET path accepted (match=%v)", match)
		}
	}
}
