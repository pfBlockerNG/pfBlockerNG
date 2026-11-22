package feedstage

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Scenario: the fail marker follows today's PHP (pfb_download_failure(), apply.inc:2859 and :4276).
// A failed transfer creates the marker and publishes it; past the skipfeed threshold it removes it instead. A successful
// download removes it whatever a later step of the run does. A non-custom whois feed's download "succeeds" even when
// entries fail, so its marker is removed too; a custom whois list never removes it.
func TestAFailedTransferCreatesTheFailMarker(t *testing.T) {
	stage, feed, _ := localStage(t) // the source file is absent: the transfer fails
	got := run(stage, feed, "download")
	if got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the run = %+v, want failed at the transfer", got)
	}
	if !regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")) {
		t.Error("no failure marker after a failed transfer, want it published")
	}
}

func TestAFailedTransferPastSkipFeedRemovesTheFailMarker(t *testing.T) {
	stage, feed, _ := localStage(t)
	marker := filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")
	writeFile(t, marker, "")
	feed.SkipFeedPassed = true
	if got := run(stage, feed, "download"); got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the run = %+v, want failed at the transfer", got)
	}
	if regularExists(marker) {
		t.Error("the marker stands after a failed transfer past the skipfeed threshold, want it removed")
	}
}

func TestASuccessfulDownloadRemovesTheMarkerWhenALaterStepFails(t *testing.T) {
	stage, feed, source := localStage(t)
	writeFile(t, source, "198.51.100.1\n")
	writeFile(t, filepath.Join(stage.Paths.ScriptDirs[0], "pre.sh"), "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(filepath.Join(stage.Paths.ScriptDirs[0], "pre.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")
	writeFile(t, marker, "")
	feed.PreScript = "pre.sh"
	if got := run(stage, feed, "none"); got.Disposition != "failed" || got.Stage != "script" {
		t.Fatalf("the run = %+v, want failed at the pre-script", got)
	}
	if regularExists(marker) {
		t.Error("the marker stands after a successful download whose pre-script failed, want it removed")
	}
}

func TestAWhoisFeedRemovesTheMarkerWhateverItsEntriesDo(t *testing.T) {
	for name, lookup := range map[string]func(context.Context, string, string) ([]netip.Addr, error){
		"a partial": func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if host == "bad.example" {
				return nil, errors.New("no such host")
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.19")}, nil
		},
		"a total failure": func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no such host") },
	} {
		t.Run(name, func(t *testing.T) {
			stage, feed, _ := localStage(t)
			stage.Fetcher.Lookup = lookup
			feed.Format, feed.Source = "whois", "one.example\nbad.example"
			marker := filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")
			writeFile(t, marker, "")
			if got := run(stage, feed, "none"); got.Disposition != "failed" {
				t.Fatalf("the run = %+v, want failed", got)
			}
			if regularExists(marker) {
				t.Error("the marker stands, want it removed as the whois format's download succeeds")
			}
		})
	}
}

// Scenario: a run the caller cancelled did not fail the feed. A transfer that ended because the context did neither
// creates the marker nor, past the skipfeed threshold, removes it.
func TestACancelledTransferTouchesNoFailMarker(t *testing.T) {
	for name, passed := range map[string]bool{"below the threshold": false, "past the threshold": true} {
		t.Run(name, func(t *testing.T) {
			stage, feed, _ := localStage(t)
			feed.Source = "http://feed.example/list.txt"
			feed.SkipFeedPassed = passed
			marker := filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")
			if passed {
				writeFile(t, marker, "")
			}
			// The context ends during the transfer, at the resolution of the source's host.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resolve := stage.Fetcher.Policy.Resolve
			stage.Fetcher.Policy.Resolve = func(c context.Context, host string) ([]netip.Addr, error) {
				cancel()
				return resolve(c, host)
			}
			got := stage.Run(ctx, feed, Change{Verdict: VerdictChanged, Force: "download"})
			if got.Disposition != "failed" {
				t.Fatalf("the run = %+v, want failed", got)
			}
			if got.Stage != "fetch" || got.Reason != "cancelled" {
				t.Errorf("the run = %+v, want failed at fetch with the reason cancelled", got)
			}
			if regularExists(marker) != passed {
				t.Errorf("the marker exists = %v after a cancelled transfer, want it untouched (%v)", !passed, passed)
			}
		})
	}
}

// Scenario: the marker cannot be created. The failure is logged, and the marker is not among what the commit publishes.
func TestAFailMarkerThatCannotBeCreatedIsLogged(t *testing.T) {
	stage, feed, _ := localStage(t)
	var log strings.Builder
	stage.Log = &log
	withFault(t, func(op, path string) error {
		if op == "create" && strings.HasSuffix(path, ".fail") {
			return syscall.EIO
		}
		return nil
	})
	got := run(stage, feed, "download")
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the run = %+v, want failed at the transfer", got)
	}
	if !strings.Contains(log.String(), "fail marker could not be created") {
		t.Errorf("log = %q, want the marker's creation error", log.String())
	}
	if regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")) {
		t.Error("a marker stands that was never created")
	}
}

// Scenario: a commit whose only operation is the marker reports the marker; one that also retires validators keeps
// validators_retire_failed.
func TestAMarkerOnlyCommitFailureHasItsOwnReason(t *testing.T) {
	stage, feed, _ := localStage(t)
	stage.Fetcher.Lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	feed.Format, feed.Source, feed.Custom, feed.WhoisConvert = "whois", "bad.example", true, true
	feed.CustomText = "bad.example"
	withFault(t, func(op, path string) error {
		if op == "sync" && filepath.Base(path) == "COMMIT.tmp" {
			return syscall.EIO
		}
		return nil
	})
	got := run(stage, feed, "none")
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "whois" || got.Reason != "fail_marker_publish_failed" {
		t.Errorf("the run = %+v, want failed at whois with fail_marker_publish_failed", got)
	}
}

// Scenario: a transfer that ended because its deadline passed is a failed download, as today's pfb_download_failure(): the
// marker is created. Only a cancelled run leaves it alone.
func TestATransferThatTimedOutCreatesTheFailMarker(t *testing.T) {
	stage, feed, _ := localStage(t)
	feed.Source = "http://feed.example/list.txt"
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	// The transfer blocks at the resolution of the source's host until the deadline ends it.
	stage.Fetcher.Policy.Resolve = func(c context.Context, _ string) ([]netip.Addr, error) {
		<-c.Done()
		return nil, c.Err()
	}
	got := stage.Run(ctx, feed, Change{Verdict: VerdictChanged, Force: "download"})
	if got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the run = %+v, want failed at the transfer", got)
	}
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("the context ended with %v, want its deadline", ctx.Err())
	}
	if !regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.fail")) {
		t.Error("no failure marker after a transfer that timed out, want it published")
	}
}

// Scenario: the first download of a feed fails and the commit of its marker cannot be made. With no validators to retire,
// the marker is the commit's only operation, so that is the reason.
func TestAFirstDownloadFailureWhoseMarkerCommitFailsNamesTheMarker(t *testing.T) {
	stage, feed, _ := localStage(t) // the source file is absent: the transfer fails
	withFault(t, func(op, path string) error {
		if op == "sync" && filepath.Base(path) == "COMMIT.tmp" {
			return syscall.EIO
		}
		return nil
	})
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "fail_marker_publish_failed" {
		t.Errorf("the run = %+v, want failed at fetch with fail_marker_publish_failed", got)
	}
}

// Scenario: the whois branch's marker reason names only a failure the whois branch returned. An asn feed whose whois
// succeeds and whose parse fails keeps the parse stage and reason when the commit of the marker's removal fails too.
func TestAParseFailureAfterWhoisKeepsItsOwnReasonWhenTheCommitFails(t *testing.T) {
	stage, feed, _ := localStage(t)
	stage.Fetcher.ASNCSV = filepath.Join(t.TempDir(), "asn.csv")
	writeFile(t, stage.Fetcher.ASNCSV, "198.51.100.0,198.51.100.255,AS64500,Example\n")
	feed.Format, feed.Source = "asn", "AS64500"
	writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.fail"), "")
	withFault(t, func(op, path string) error {
		if op == "create" && filepath.Base(path) == "feed_v4.parsed.ip" || op == "sync" && filepath.Base(path) == "COMMIT.tmp" {
			return syscall.EIO
		}
		return nil
	})
	got := stage.Run(context.Background(), feed, Change{Force: "none"})
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "parse" || got.Reason != "ip_parse_failed" {
		t.Errorf("the run = %+v, want failed at parse with ip_parse_failed", got)
	}
}
