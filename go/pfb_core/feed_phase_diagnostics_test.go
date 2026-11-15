package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// Optional reflection keeps the frozen regression runnable before the diagnostic flags exist.
func diagnosticPaths(runner *feedPhaseRunner, ip, dnsbl string) {
	for field, path := range map[string]string{"IPParseLog": ip, "DNSBLParseLog": dnsbl} {
		v := reflect.ValueOf(&runner.flags).Elem().FieldByName(field)
		if v.IsValid() && v.CanSet() && v.Kind() == reflect.String {
			v.SetString(path)
		}
	}
}

func diagnosticRun(t *testing.T, runner *feedPhaseRunner, kind string, ctx context.Context, log io.Writer) FeedPhaseResult {
	t.Helper()
	phase, id := "ip", kind+":feed"+familySuffix(kind)
	if kind == "dnsbl" {
		phase, id = "dnsbl", "dnsbl:feed"
	}
	got, err := runner.run(ctx, phase, []string{id}, "parse", log)
	if err != nil || len(got) != 1 {
		t.Fatalf("actual phase = %+v, %v; want one result", got, err)
	}
	return got[0]
}

// Compare the persisted rows with the unchanged generic parser, not with a second normalization of its FailRecord.
func diagnosticRecords(t *testing.T, kind, text string, custom bool) ([]feedparse.FailRecord, string) {
	t.Helper()
	var records []feedparse.FailRecord
	var parsed strings.Builder
	sink := feedparse.Sink{Fail: func(r feedparse.FailRecord) { records = append(records, r) }}
	var err error
	if kind == "dnsbl" {
		_, err = feedparse.ParseDNSBLFeed(strings.NewReader(text), feedparse.DNSBLConfig{DNSBLIP: true, Custom: custom}, &parsed, sink)
	} else {
		_, err = feedparse.ParseIPFeed(strings.NewReader(text), feedparse.IPConfig{VType: familySuffix(kind), PFType: "auto", Custom: custom, FloorV4: "Disabled", FloorV6: "Disabled"}, "", 1, &parsed, sink)
	}
	if err != nil {
		t.Fatal(err)
	}
	return records, parsed.String()
}

func diagnosticFile(t *testing.T, path, prefix, header string, records []feedparse.FailRecord, loc *time.Location, before, after time.Time) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("detailed diagnostic file %s missing after real FeedPhase: %v", path, err)
	}
	if !strings.HasPrefix(string(data), prefix) {
		t.Fatalf("append lost previous content: %q; want prefix %q", data, prefix)
	}
	rows := strings.Split(strings.TrimSuffix(strings.TrimPrefix(string(data), prefix), "\n"), "\n")
	if len(records) == 0 {
		if string(data) != prefix {
			t.Fatalf("unexpected diagnostic rows: %q", data)
		}
		return
	}
	if len(rows) != len(records) {
		t.Fatalf("diagnostic rows = %q; want %d records %+v", rows, len(records), records)
	}
	for i, record := range records {
		want := fmt.Sprintf(",%s,%s,%s,%d", header, record.Line, record.Raw, record.LineNo)
		if len(rows[i]) < 19 || rows[i][19:] != want {
			t.Errorf("row %d = %q; want local timestamp followed by %q", i, rows[i], want)
			continue
		}
		stamp, err := time.ParseInLocation("2006-01-02 15:04:05", rows[i][:19], loc)
		if err != nil || stamp.Before(before.Truncate(time.Second)) || stamp.After(after) {
			t.Errorf("row %d timestamp = %q (%v); want actual %s wall clock between %s and %s", i, rows[i][:19], err, loc, before, after)
		}
	}
}

func TestFeedPhaseDiagnosticsActualFiles(t *testing.T) {
	for _, tc := range []struct{ name, kind, body string }{
		{"ipv4-zero-commas-crlf", "ipv4", "# comment\r\n198.51.100.8\r\n2606:4700::1\r\n0\r\n999.999.999.999 ,raw\r\n256.256.256.256"},
		{"ipv6-raw-and-opposite-family", "ipv6", "# comment\n2606:4700::1\n198.51.100.8\n::ffff:192.168.1.100 ,raw\r\n12345"},
		{"dnsbl-strict-scheme-path", "dnsbl", "example.org\nhttp://example.com/\nhttp://example.com/path\nhttps://example.net/a/b.html\nhttp://example.com:8080\nhttp://example.com/#frag\ninvalid_domain\n"},
		{"dnsbl-null-and-crlf", "dnsbl", "example.org\r\ninvalid_domain\r\n.\r\na b\r\nuser@example.com\r\n:80\r\nok.example.net\r\n-\r\n"},
		{"dnsbl-csv-raw-commas-null", "dnsbl", "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n4,,http://phishtank.example/4,2024-01-01,yes,2024-01-02,yes,Other\n"},
		{"ip-normalized-controls", "ipv4", "\x01# stripped control comment\n\x00\n999.999.999.999\x01 ,raw\r\n0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, tc.kind, "enabled", "auto", "https://example.test/list.txt", "")
			ip, dnsbl := filepath.Join(t.TempDir(), "ip.log"), filepath.Join(t.TempDir(), "dnsbl.log")
			diagnosticPaths(runner, ip, dnsbl)
			path, other, header := ip, dnsbl, "feed"+familySuffix(tc.kind)
			if tc.kind == "dnsbl" {
				path, other, header = dnsbl, ip, "feed"
			}
			const prefix = "existing diagnostic content\n"
			if err := os.WriteFile(path, []byte(prefix), 0600); err != nil {
				t.Fatal(err)
			}
			pipelineParityBaseline(t, runner, tc.kind, tc.body)
			records, parsed := diagnosticRecords(t, tc.kind, string(feedparse.Normalize([]byte(tc.body))), false)
			if len(records) == 0 {
				t.Fatal("fixture must yield detailed records")
			}
			before := time.Now()
			got := diagnosticRun(t, runner, tc.kind, context.Background(), io.Discard)
			after := time.Now()
			if got.Disposition != "reparsed" || tc.kind != "dnsbl" && got.ParseFailures != len(records) {
				t.Fatalf("actual phase = %+v; want reparsed with %d detailed IP failures", got, len(records))
			}
			diagnosticFile(t, path, prefix, header, records, time.Local, before, after)
			if _, err := os.Stat(other); !os.IsNotExist(err) {
				t.Errorf("other family log exists or cannot be inspected: %v", err)
			}
			artifact := filepath.Join(runner.flags.OrigDir, "feed"+familySuffix(tc.kind)+".parsed.ip")
			if tc.kind == "dnsbl" {
				artifact = filepath.Join(runner.flags.DNSBLOrigDir, "feed.parsed.ndjson")
			}
			pipelineParityBytes(t, artifact, parsed)
			// The existing IP parser skips PHP-falsy literal 0 rather than emitting a FailRecord.
			if tc.kind != "dnsbl" {
				for _, r := range records {
					if r.Line == "0" {
						t.Fatalf("literal IP zero unexpectedly became a failure: %+v", records)
					}
				}
			}
		})
	}
}

func TestFeedPhaseDiagnosticsNoRowsForValidOppositeOrSkippedControls(t *testing.T) {
	for _, tc := range []struct{ kind, body string }{
		{"ipv4", "# note\n\x01\n0\n198.51.100.8\n2606:4700::1\n"},
		{"ipv6", "# note\n0\n2606:4700::1\n198.51.100.8\n"},
		{"dnsbl", "# note\n! note\n// note\n[Adblock Plus 2.0]\n\x00\nvalid.example\n"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, tc.kind, "enabled", "auto", "https://example.test/list.txt", "")
			path := filepath.Join(t.TempDir(), "parse.log")
			diagnosticPaths(runner, path, path)
			pipelineParityBaseline(t, runner, tc.kind, tc.body)
			got := diagnosticRun(t, runner, tc.kind, context.Background(), io.Discard)
			if got.Disposition != "reparsed" || got.ParseFailures != 0 {
				t.Fatalf("valid/skipped phase = %+v", got)
			}
			if b, err := os.ReadFile(path); err != nil && !os.IsNotExist(err) || len(b) != 0 {
				t.Fatalf("valid/skipped lines wrote details: %q, %v", b, err)
			}
		})
	}
}

func TestFeedPhaseDiagnosticsOmittedPathsDisableDetailedLogging(t *testing.T) {
	runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "https://example.test/list.txt", "")
	pipelineParityBaseline(t, runner, "ipv4", "999.999.999.999\n256.256.256.256\n")
	var log strings.Builder
	got := diagnosticRun(t, runner, "ipv4", context.Background(), &log)
	if got.Disposition != "reparsed" || got.ParseFailures != 2 || strings.Contains(strings.ToLower(log.String()), "warning") {
		t.Fatalf("unconfigured detailed logging changed parse outcome: %+v, log %q", got, log.String())
	}
}

func TestFeedPhaseDiagnosticsAppendFailureIsBestEffortOncePerFeed(t *testing.T) {
	for _, kind := range []string{"ipv4", "ipv6", "dnsbl"} {
		t.Run(kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, kind, "enabled", "auto", "https://example.test/list.txt", "")
			path := t.TempDir() // A directory fails append even as root.
			diagnosticPaths(runner, path, path)
			pipelineParityBaseline(t, runner, kind, "999.999.999.999\n256.256.256.256\n99999.99999.99999.99999\n")
			var log strings.Builder
			got := diagnosticRun(t, runner, kind, context.Background(), &log)
			if got.Disposition != "reparsed" || kind != "dnsbl" && got.ParseFailures != 3 {
				t.Fatalf("append failure changed parse result: %+v", got)
			}
			warnings := 0
			for _, line := range strings.Split(log.String(), "\n") {
				if strings.Contains(strings.ToLower(line), "warning") {
					warnings++
				}
			}
			if warnings != 1 {
				t.Fatalf("append failure warnings = %d, want exactly one for three failures; log %q", warnings, log.String())
			}
		})
	}
}

func TestFeedPhaseDiagnosticFlags(t *testing.T) {
	for _, tc := range []struct{ flag, field string }{{"feed-ip-parse-log", "IPParseLog"}, {"feed-dnsbl-parse-log", "DNSBLParseLog"}} {
		t.Run(tc.flag, func(t *testing.T) {
			want := filepath.Join(t.TempDir(), "parse.log")
			ff, out, err := parseFeedFlags("--"+tc.flag, filepath.Dir(want)+"/./parse.log")
			if err != nil {
				t.Fatalf("approved absolute diagnostic flag rejected: %v, %s", err, out)
			}
			v := reflect.ValueOf(ff).Elem().FieldByName(tc.field)
			if !v.IsValid() || v.Kind() != reflect.String || v.String() != want {
				t.Fatalf("flag %s did not set cleaned %s=%q", tc.flag, tc.field, want)
			}
			for _, bad := range []string{"", "relative/parse.log", "https://example.test/log", "file:///tmp/log"} {
				_, out, err := parseFeedFlags("--"+tc.flag, bad)
				if err == nil || !strings.Contains(out, tc.flag) {
					t.Errorf("unsafe flag %s=%q: error %v, output %q", tc.flag, bad, err, out)
				}
			}
		})
	}
}

func TestFeedPhaseDiagnosticsConfiguredTimezoneThroughCore(t *testing.T) {
	holdQuarters(t)
	f := newFakeUpdate(t)
	dir, orig := scratchDir(t), t.TempDir()
	zonePath, logPath := filepath.Join(dir, "zoneinfo"), filepath.Join(dir, "ip.log")
	if err := os.WriteFile(zonePath, tzif(t, 9*3600+30*60, "DIAG"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orig, "Feed1_v4.orig"), []byte("999.999.999.999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := startCore(t, dir, "--update-cmd", f.path, "--zoneinfo", zonePath,
		"--feed-orig-dir", orig, "--feed-ip-parse-log", logPath, "--feed-dnsbl-parse-log", filepath.Join(dir, "dnsbl.log"))
	t.Cleanup(f.release)
	c.initialize()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"diagnostic-zone","trigger":"manual"}`), 200, `{}`)
	var request struct {
		Token string `json:"token"`
	}
	waitFor(t, func() bool {
		data, err := os.ReadFile(filepath.Join(f.dir, "req"))
		return err == nil && json.Unmarshal(data, &request) == nil && len(request.Token) == 64
	})
	for i, offset := range []int32{9*3600 + 30*60, -7 * 3600} {
		if err := os.WriteFile(zonePath, tzif(t, offset, "DIAG"), 0600); err != nil {
			t.Fatal(err)
		}
		before := time.Now()
		got := c.post("FeedPhase", `{"requestId":"diagnostic-zone-`+strconv.Itoa(i)+`","token":"`+request.Token+`","phase":"ip","feeds":["ipv4:Feed1_v4"],"force":"parse"}`)
		after := time.Now()
		var response FeedPhaseResponse
		if got.status != 200 || json.Unmarshal(got.body, &response) != nil || len(response.Results) != 1 || response.Results[0].Disposition != "reparsed" || response.Results[0].ParseFailures != 1 {
			t.Fatalf("zoned actual FeedPhase = %d %s", got.status, got.body)
		}
		prefix := ""
		if i != 0 {
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			first := strings.IndexByte(string(data), '\n')
			if first < 0 {
				t.Fatalf("missing first diagnostic row: %q", data)
			}
			prefix = string(data[:first+1])
		}
		diagnosticFile(t, logPath, prefix, "Feed1_v4", []feedparse.FailRecord{{LineNo: 1, Line: "999.999.999.999", Raw: "999.999.999.999"}}, time.FixedZone("DIAG", int(offset)), before, after)
	}
	f.release()
	c.waitFinished("manual")
}

func TestFeedPhaseDiagnosticsPreScriptRawBytesAreNotNormalizedAgain(t *testing.T) {
	for _, kind := range []string{"ipv4", "ipv6", "dnsbl"} {
		t.Run(kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, kind, "enabled", "auto", "https://example.test/list.txt", "", "raw.sh")
			scripts := t.TempDir()
			payload := "invalid\x01,raw\tfield\r\ninvalid\x00_name\r\n0\r\n"
			if kind == "ipv4" {
				payload = "999.999.999.999\x01 ,raw\tfield\r\n1\x00.2.3.4\r\n0\r\n"
			} else if kind == "ipv6" {
				payload = "::ffff:192.168.1.100 \x01,raw\tfield\r\n12345\r\n0\r\n"
			}
			if err := os.WriteFile(filepath.Join(scripts, "payload"), []byte(payload), 0600); err != nil {
				t.Fatal(err)
			}
			script := "#!/bin/sh\ncat '" + filepath.Join(scripts, "payload") + "' > \"$1\"\n"
			if err := os.WriteFile(filepath.Join(scripts, "raw.sh"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			runner.flags.ScriptDirs = []string{scripts}
			path := filepath.Join(t.TempDir(), "parse.log")
			diagnosticPaths(runner, path, path)
			pipelineParityBaseline(t, runner, kind, "198.51.100.1\n")
			records, _ := diagnosticRecords(t, kind, payload, false)
			if len(records) == 0 || !strings.Contains(records[0].Raw, ",raw\tfield") || !strings.Contains(records[0].Raw, "\x01") {
				t.Fatalf("fixture must retain raw controls and commas: %+v", records)
			}
			before := time.Now()
			got := diagnosticRun(t, runner, kind, context.Background(), io.Discard)
			after := time.Now()
			if got.Disposition != "reparsed" || got.PreScriptFailed || kind != "dnsbl" && got.ParseFailures != len(records) {
				t.Fatalf("pre-script diagnostic phase = %+v; want %d detailed IP failures", got, len(records))
			}
			diagnosticFile(t, path, "", "feed"+familySuffix(kind), records, time.Local, before, after)
		})
	}
}

func TestFeedPhaseDiagnosticsCustomAndCategoryHeaders(t *testing.T) {
	for _, kind := range []string{"ipv4", "ipv6", "dnsbl"} {
		t.Run("custom-"+kind, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, kind, "enabled", "auto", "https://example.test/list.txt", "")
			projection, err := runner.store.GetClear("feeds/" + kind)
			if err != nil {
				t.Fatal(err)
			}
			// Change the real settings projection, not a hand-built phaseFeed.
			groups := projection["groups"].([]any)
			groups[0].(map[string]any)["customList"] = "999.999.999.999\n"
			raw, err := json.Marshal(projection)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			backend := &feedPhaseTestBackend{stored: settings.Stored{
				Initialized: true, Revision: 1,
				Projections: map[string]map[string]json.RawMessage{"feeds/" + kind: fields},
			}}
			runner.store, err = settings.Load(backend, settings.Production())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "parse.log")
			diagnosticPaths(runner, path, path)
			phase := "ip"
			if kind == "dnsbl" {
				phase = "dnsbl"
			}
			before := time.Now()
			got, err := runner.run(context.Background(), phase, []string{"custom:" + kind + ":Test"}, "download", io.Discard)
			after := time.Now()
			if err != nil || len(got) != 1 || got[0].Disposition != "changed" || kind != "dnsbl" && got[0].ParseFailures != 1 {
				t.Fatalf("custom phase = %+v, %v; want one genuine IP parse failure", got, err)
			}
			diagnosticFile(t, path, "", "Test_custom"+familySuffix(kind),
				[]feedparse.FailRecord{{LineNo: 1, Line: "999.999.999.999", Raw: "999.999.999.999"}}, time.Local, before, after)
		})
	}
	t.Run("category-configured-title", func(t *testing.T) {
		source, orig := t.TempDir(), t.TempDir()
		if err := os.Mkdir(filepath.Join(source, "work"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "work", "work_adult_category"), []byte("invalid_domain\n"), 0600); err != nil {
			t.Fatal(err)
		}
		runner := blacklistPhaseTestRunner(t, source, orig)
		path := filepath.Join(t.TempDir(), "parse.log")
		diagnosticPaths(runner, "", path)
		before := time.Now()
		got, err := runner.run(context.Background(), "dnsbl", []string{"blacklist:work:adult-category"}, "download", io.Discard)
		after := time.Now()
		if err != nil || len(got) != 1 || got[0].Disposition != "changed" {
			t.Fatalf("category phase = %+v, %v", got, err)
		}
		diagnosticFile(t, path, "", "Work_adult_category",
			[]feedparse.FailRecord{{LineNo: 1, Line: "invalid_domain", Raw: "invalid_domain"}}, time.Local, before, after)
	})
}
