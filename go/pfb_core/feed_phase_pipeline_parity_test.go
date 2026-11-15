package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

func pipelineParityRun(t *testing.T, runner *feedPhaseRunner, kind, force string) FeedPhaseResult {
	t.Helper()
	phase, name := "ip", "feed"+familySuffix(kind)
	if kind == "dnsbl" {
		phase, name = "dnsbl", "feed"
	}
	got, err := runner.run(context.Background(), phase, []string{kind + ":" + name}, force, &strings.Builder{})
	if err != nil || len(got) != 1 || got[0].Disposition == "failed" {
		t.Fatalf("runner = %+v, %v", got, err)
	}
	return got[0]
}

func pipelineParityBaseline(t *testing.T, runner *feedPhaseRunner, kind, body string) string {
	t.Helper()
	dir, name := runner.flags.OrigDir, "feed"+familySuffix(kind)
	if kind == "dnsbl" {
		dir, name = runner.flags.DNSBLOrigDir, "feed"
	}
	if err := os.WriteFile(filepath.Join(dir, name+".orig"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name+".parsed.ip")
}

func pipelineParityBytes(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("artifact = %q (%v), want %q", got, err, want)
	}
}

func TestPipelineParityPreScriptFamily(t *testing.T) {
	for _, tc := range []struct{ kind, arg, body string }{
		{"ipv4", "_v4", "198.51.100.31\n"}, {"ipv6", "_v6", "2606:4700::1\n"}, {"dnsbl", "dnsbl", "blocked.example\n"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, tc.kind, "enabled", "auto", "http://example.test/list.txt", "", "family.sh")
			dir := t.TempDir()
			script := "#!/bin/sh\n[ \"$2\" = '" + tc.arg + "' ] || exit 23\n[ \"$#\" = 2 ] || exit 24\n"
			if err := os.WriteFile(filepath.Join(dir, "family.sh"), []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			runner.flags.ScriptDirs = []string{dir}
			path := pipelineParityBaseline(t, runner, tc.kind, tc.body)
			got := pipelineParityRun(t, runner, tc.kind, "parse")
			if got.PreScriptFailed {
				t.Fatal(got)
			}
			if tc.kind != "dnsbl" {
				pipelineParityBytes(t, path, tc.body)
			} else if got.DNSBLRows != 1 {
				t.Fatal(got)
			}
		})
	}
}

func TestPipelineParityShippedAWSFamily(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Fatal(err)
	}
	iprange, err := exec.LookPath("iprange")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("pathjq", jq)
	t.Setenv("pathaggregate", iprange)
	dir, err := filepath.Abs("../../src/usr/local/pkg/pfblockerng/list_scripts")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ kind, want string }{{"ipv4", "198.51.100.0/24\n"}, {"ipv6", "2606:4700::/32\n"}} {
		t.Run(tc.kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, tc.kind, "enabled", "auto", "http://example.test/list.txt", "", "aws_region_prefixes.sh")
			runner.flags.ScriptDirs = []string{dir}
			path := pipelineParityBaseline(t, runner, tc.kind, `{"prefixes":[{"ip_prefix":"198.51.100.0/24"}],"ipv6_prefixes":[{"ipv6_prefix":"2606:4700::/32"},{"ipv6_prefix":"2606:4700::/32"}]}`+"\n")
			got := pipelineParityRun(t, runner, tc.kind, "parse")
			if got.Entries != 1 {
				t.Fatal(got)
			}
			pipelineParityBytes(t, path, tc.want)
		})
	}
}

func TestPipelineParitySuppressionFloors(t *testing.T) {
	for _, tc := range []struct {
		name, kind, format, body, want string
		own                            int
		suppressed                     bool
	}{
		{"geo-v4", "ipv4", "geoip", "81.169.0.0/16\n", "81.169.0.0/16\n", 0, false},
		{"geo-v6", "ipv6", "geoip", "2606:4700::/32\n", "2606:4700::/32\n", 0, false},
		{"geo-own-v4", "ipv4", "geoip", "81.169.0.0/16\n", "81.169.0.0/32\n", 17, false},
		{"ordinary-v4", "ipv4", "auto", "81.169.0.0/16\n", "81.169.0.0/32\n", 0, false},
		{"ordinary-v6", "ipv6", "auto", "2606:4700::/32\n", "2606:4700::\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ingest := map[string]json.RawMessage{"suppression": json.RawMessage("true"), "suppressionCidrV4": json.RawMessage("17"), "suppressionCidrV6": json.RawMessage("64")}
			runner := feedPhaseTestRunnerWithIngest(t, ingest, tc.kind, "enabled", tc.format, "US", "")
			// Use the same settings projection as production for the explicit group override.
			if tc.own != 0 {
				groups, _ := json.Marshal([]any{map[string]any{"name": "Test", "action": "Deny_Inbound", "suppressionCidr": tc.own, "feeds": []any{map[string]any{"header": "feed", "state": "enabled", "format": tc.format, "url": "US"}}}})
				runner.store, _ = settings.Load(&feedPhaseTestBackend{stored: settings.Stored{Initialized: true, Revision: 1, Projections: map[string]map[string]json.RawMessage{"feeds/" + tc.kind: {"groups": groups}, "ingest": ingest}}}, settings.Production())
				if runner.store == nil {
					t.Fatal("settings load failed")
				}
			}
			runner.flags.GeoIPDir = t.TempDir()
			if err := os.WriteFile(filepath.Join(runner.flags.GeoIPDir, "US"+familySuffix(tc.kind)+".txt"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			path := pipelineParityBaseline(t, runner, tc.kind, tc.body)
			force := "parse"
			if tc.format == "geoip" {
				force = "download"
			}
			got := pipelineParityRun(t, runner, tc.kind, force)
			if got.Suppressed != tc.suppressed {
				t.Fatal(got)
			}
			pipelineParityBytes(t, path, tc.want)
		})
	}
}

func TestPipelineParityParseSelector(t *testing.T) {
	for _, tc := range []struct {
		name, format, path string
		entries            int
	}{
		{"explicit", "regex", "/list.txt", 2}, {"html", "auto", "/list.html", 2}, {"htm", "auto", "/list.htm", 2},
		{"php-query", "auto", "/list.php?q=1", 2}, {"aspx", "auto", "/list.aspx", 2}, {"cgi", "auto", "/list.cgi", 2},
		{"csv", "auto", "/list.csv", 2}, {"rules", "auto", "/list.rules", 2}, {"empty-extension", "auto", "/list.", 2},
		{"extensionless", "auto", "/list", 2}, {"text-auto", "auto", "/list.txt", 1}, {"iblocklist-override", "auto", "/iblocklist/list.csv", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("198.51.100.31 198.51.100.32\n")) }))
			defer server.Close()
			runner := feedPhaseTestRunner(t, "ipv4", "enabled", tc.format, server.URL+tc.path, "")
			got := pipelineParityRun(t, runner, "ipv4", "download")
			if got.Entries != tc.entries {
				t.Fatalf("entries = %d, want %d", got.Entries, tc.entries)
			}
			want := "198.51.100.31\n"
			if tc.entries == 2 {
				want += "198.51.100.32\n"
			}
			pipelineParityBytes(t, filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip"), want)
		})
	}
}

func TestPipelineParityPlaceholderArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name, kind, body, want, placeholder string
		entries                             int
		suppressed                          bool
	}{
		{"empty-v4", "ipv4", "# comment\n", "", "empty", 0, false}, {"empty-v6", "ipv6", "# comment\n", "", "empty", 0, false},
		{"suppressed-v6", "ipv6", "2001:db8::/32\n", "", "suppressed", 0, true},
		{"real-v4", "ipv4", "81.169.0.1\n", "81.169.0.1\n", "", 1, false},
		{"real-v6", "ipv6", "2606:4700::1\n", "2606:4700::1\n", "", 1, false},
		{"all-invalid-v4", "ipv4", "invalid\n", "", "", 0, false}, {"all-invalid-v6", "ipv6", "invalid\n", "", "", 0, false},
		{"zero-byte-v4", "ipv4", "", "", "", 0, false}, {"zero-byte-v6", "ipv6", "", "", "", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{"suppression": json.RawMessage("true"), "suppressionCidrV6": json.RawMessage("64")}, tc.kind, "enabled", "auto", "http://example.test/list.txt", "")
			path := pipelineParityBaseline(t, runner, tc.kind, tc.body)
			got := pipelineParityRun(t, runner, tc.kind, "parse")
			if got.Entries != tc.entries || got.Placeholder != tc.placeholder || got.Suppressed != tc.suppressed {
				t.Fatal(got)
			}
			pipelineParityBytes(t, path, tc.want)
		})
	}
}

func TestPipelineParityGenericPlaceholderContract(t *testing.T) {
	for _, family := range []string{"_v4", "_v6"} {
		t.Run(family, func(t *testing.T) {
			var out strings.Builder
			got, err := feedparse.ParseIPFeed(strings.NewReader("# comment\n"), feedparse.IPConfig{VType: family, PFType: "auto"}, "1", 0, &out, feedparse.Sink{})
			want := "1\n"
			if family == "_v6" {
				want = "::1\n"
			}
			if err != nil || got.Placeholder != "empty" || out.String() != want {
				t.Fatalf("generic = %+v, %q, %v", got, out.String(), err)
			}
		})
	}
}

func pipelineParityETRunner(t *testing.T, source, block, match string) *feedPhaseRunner {
	t.Helper()
	runner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{
		"etBlockCategories": json.RawMessage(`[{"category":"` + block + `"}]`),
		"etMatchCategories": json.RawMessage(`[{"category":"` + match + `"}]`),
	}, "ipv4", "enabled", "auto", source, "")
	for _, dir := range []string{filepath.Join(runner.flags.DBDir, "ET"), filepath.Join(runner.flags.DBDir, "match", "generated")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return runner
}

func TestPipelineParityETCachedReprocess(t *testing.T) {
	for _, scenario := range []string{"categories", "missing-raw", "bad-raw", "script-failure"} {
		t.Run(scenario, func(t *testing.T) {
			var raw bytes.Buffer
			z := gzip.NewWriter(&raw)
			if _, err := z.Write([]byte("81.169.0.1,1,90\n81.169.0.2,2,80\n")); err != nil {
				t.Fatal(err)
			}
			if err := z.Close(); err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("ETag", `"et-cached"`)
				if r.Header.Get("If-None-Match") == `"et-cached"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				_, _ = w.Write(raw.Bytes())
			}))
			defer server.Close()
			source := server.URL + "/iprepdata.txt"
			runner := pipelineParityETRunner(t, source, "ET_Cnc", "ET_Bot")
			base := filepath.Join(runner.flags.OrigDir, "feed_v4")
			match := filepath.Join(runner.flags.DBDir, "match", "generated", "pfB_Match_ET_v4.txt")
			first := pipelineParityRun(t, runner, "ipv4", "download")
			if !first.SourceChanged || first.Entries != 1 || requests.Load() != 1 {
				t.Fatal(first, requests.Load())
			}
			pipelineParityBytes(t, base+".orig", "81.169.0.1\n")
			pipelineParityBytes(t, base+".parsed.ip", "81.169.0.1\n")
			pipelineParityBytes(t, match, "81.169.0.2\n")
			// PHP owns the action file; cached Core work must not replace its last-good bytes.
			if err := os.WriteFile(base+".txt", []byte("81.169.0.1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			next := pipelineParityETRunner(t, source, "ET_Bot", "ET_Cnc")
			runner.store = next.store
			switch scenario {
			case "missing-raw":
				if err := os.Remove(base + ".raw"); err != nil {
					t.Fatal(err)
				}
			case "bad-raw":
				if err := os.WriteFile(base+".raw", []byte("not gzip"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "script-failure":
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "fail.sh"), []byte("#!/bin/sh\nexit 23\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				runner.flags.ScriptDirs = []string{dir}
				scriptRunner := feedPhaseTestRunnerWithIngest(t, map[string]json.RawMessage{
					"etBlockCategories": json.RawMessage(`[{"category":"ET_Bot"}]`),
					"etMatchCategories": json.RawMessage(`[{"category":"ET_Cnc"}]`),
				}, "ipv4", "enabled", "auto", source, "", "fail.sh")
				runner.store = scriptRunner.store
			}
			got, err := runner.run(context.Background(), "ip", []string{"ipv4:feed_v4"}, "parse", nil)
			if err != nil || len(got) != 1 {
				t.Fatalf("reprocess = %+v, %v", got, err)
			}
			if requests.Load() != 1 {
				t.Fatalf("cache-only reprocess made %d requests", requests.Load())
			}
			if scenario == "bad-raw" || scenario == "script-failure" {
				stage := "fetch"
				if scenario == "script-failure" {
					stage = "script"
				}
				if got[0].Disposition != "failed" || got[0].Stage != stage || got[0].Reason == "" || got[0].SourceChanged {
					t.Fatal(got)
				}
				pipelineParityBytes(t, base+".orig", "81.169.0.1\n")
				pipelineParityBytes(t, base+".parsed.ip", "81.169.0.1\n")
				pipelineParityBytes(t, base+".txt", "81.169.0.1\n")
				pipelineParityBytes(t, base+".orig.etag", `"et-cached"`)
				return
			}
			if got[0].Disposition != "reparsed" || got[0].Entries != 1 || got[0].SourceChanged {
				t.Fatal(got)
			}
			want := "81.169.0.2\n"
			if scenario == "missing-raw" {
				want = "81.169.0.1\n"
			}
			pipelineParityBytes(t, base+".orig", want)
			pipelineParityBytes(t, base+".parsed.ip", want)
			pipelineParityBytes(t, base+".txt", "81.169.0.1\n")
			if scenario == "categories" {
				pipelineParityBytes(t, match, "81.169.0.1\n")
			}
			pipelineParityBytes(t, base+".orig.etag", `"et-cached"`)
			if scenario != "categories" {
				return
			}
			// A later conditional 304 must NOT reselect categories or disturb parsed/action metadata.
			runner.store = pipelineParityETRunner(t, source, "ET_Cnc", "ET_Bot").store
			saved := make(map[string][]byte)
			for _, path := range []string{base + ".orig", base + ".parsed.ip", base + ".txt", base + ".orig.etag", base + ".norm.src.xxhash128", match} {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				saved[path] = body
			}
			third := pipelineParityRun(t, runner, "ipv4", "none")
			if third.Disposition != "unchanged" || third.SourceChanged || third.NormalizedChanged || requests.Load() != 2 {
				t.Fatal(third, requests.Load())
			}
			for path, body := range saved {
				current, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(current, body) {
					t.Fatalf("304 altered %s: %q -> %q", filepath.Base(path), body, current)
				}
			}
		})
	}
}
