package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type diagnosticProgress struct {
	onFailure func()
}

func (p diagnosticProgress) Write(b []byte) (int, error) {
	if strings.Contains(string(b), "parse failure at line") {
		p.onFailure()
	}
	return len(b), nil
}

func diagnosticOpenHandles(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("descriptor lifecycle probe needs /proc/self/fd: %v", err)
	}
	var handles []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == path {
			handles = append(handles, entry.Name())
		}
	}
	return handles
}

func TestFeedPhaseDiagnosticsPerFeedHandleClosedAfterReturn(t *testing.T) {
	for _, outcome := range []string{"success", "cancel", "read-error", "publish-error"} {
		t.Run(outcome, func(t *testing.T) {
			runner := feedPhaseTestRunner(t, "ipv4", "enabled", "auto", "https://example.test/list.txt", "")
			path := filepath.Join(t.TempDir(), "parse.log")
			diagnosticPaths(runner, path, "")
			pipelineParityBaseline(t, runner, "ipv4", "999.999.999.999\n256.256.256.256\n99999.99999.99999.99999\n")
			if outcome == "read-error" {
				// Force another input-buffer fill after the append handle opens.
				pipelineParityBaseline(t, runner, "ipv4", "999.999.999.999\n256.256.256.256\n"+strings.Repeat("99999.99999.99999.99999\n", 20000))
			}
			if outcome == "publish-error" {
				target := filepath.Join(runner.flags.OrigDir, "feed_v4.parsed.ip")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "block"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failures := 0
			var active []string
			log := diagnosticProgress{onFailure: func() {
				failures++
				if failures >= 2 && failures <= 3 {
					handles := diagnosticOpenHandles(t, path)
					if len(handles) != 1 {
						t.Errorf("failure %d has append handles %v; want one retained per-feed handle", failures, handles)
					} else if len(active) != 0 && !reflect.DeepEqual(handles, active) {
						t.Errorf("append handle changed within feed: %v -> %v", active, handles)
					}
					active = handles
					if outcome == "cancel" {
						cancel()
					}
					if outcome == "read-error" && failures == 2 {
						handles := diagnosticOpenHandles(t, filepath.Join(runner.flags.OrigDir, "feed_v4.norm"))
						if len(handles) != 1 {
							t.Fatalf("read-error injection needs one real parser input, got %v", handles)
						}
						n, err := strconv.ParseUint(handles[0], 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.NewFile(uintptr(n), "diagnostic-read-error").Close(); err != nil {
							t.Fatal(err)
						}
					}
				}
			}}
			got := diagnosticRun(t, runner, "ipv4", ctx, log)
			if outcome == "success" && got.Disposition != "reparsed" ||
				outcome == "cancel" && got.Reason != "cancelled" ||
				outcome == "read-error" && (got.Stage != "parse" || got.Reason != "ip_parse_failed") ||
				outcome == "publish-error" && got.Stage != "publish" {
				t.Fatalf("%s phase = %+v", outcome, got)
			}
			if handles := diagnosticOpenHandles(t, path); len(handles) != 0 {
				t.Fatalf("%s leaked append handles %v", outcome, handles)
			}
			data, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(data), ",feed_v4,999.999.999.999,999.999.999.999,1\n") {
				t.Fatalf("%s lost already-streamed diagnostic: %q, %v", outcome, data, err)
			}
		})
	}
}
