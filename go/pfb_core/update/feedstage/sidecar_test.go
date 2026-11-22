package feedstage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

// Scenario: the digest of the last transfer cannot be removed.
// Given a custom list with its download and the digest of a transfer, when its text changes and removing that digest fails
// for a reason other than its absence, then the run fails and the journal puts the last text and its digest back: a
// digest never stands beside bytes it does not describe.
func TestCustomListFailsWhenTheTransferDigestStays(t *testing.T) {
	stage := testStage(t)
	dir := stage.Paths.FeedDir
	orig := filepath.Join(dir, "Test_custom_v4.orig")
	sidecar := orig + ".xxhash128"
	writeFile(t, orig, "203.0.113.1\n")
	writeFile(t, sidecar, "0123456789abcdef0123456789abcdef")
	withFault(t, func(op, path string) error {
		if op == "remove" && path == sidecar {
			return syscall.EIO
		}
		return nil
	})
	got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
		Format: "auto", Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "none"})
	fault = noFault
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "custom_source_unavailable" {
		t.Fatalf("a custom run whose transfer digest stays = %+v, want failed/fetch/custom_source_unavailable", got)
	}
	for path, want := range map[string]string{orig: "203.0.113.1\n", sidecar: "0123456789abcdef0123456789abcdef"} {
		if body := readFile(t, path); body != want {
			t.Errorf("after the failed run %s = %q, want the last %q", filepath.Base(path), body, want)
		}
	}
	journalLeftovers(t, dir, "after the failed run")
}

// failingTransfer publishes a feed with an ETag, then fails its next transfer with fault set: the failed run's result.
func failingTransfer(t *testing.T, f func(op, path string) error) (Result, *Stage) {
	t.Helper()
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "rejected", http.StatusBadGateway)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("203.0.113.1\n"))
	}))
	t.Cleanup(server.Close)
	stage := testStage(t)
	feed := testFeed("ipv4", "enabled", "auto", server.URL+"/feed")
	writeFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig"), "203.0.113.2\n") // so that stage 6's probe keeps the body
	if got := run(stage, feed, "none"); got.Disposition != "changed" || !regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.etag")) {
		t.Fatalf("the first run = %+v, want changed with its ETag", got)
	}
	fail.Store(true)
	withFault(t, f)
	got := stage.Run(context.Background(), feed, Change{Verdict: VerdictChanged, Force: "none"})
	fault = noFault
	return got, stage
}

// Scenario: the absent record of a validator cannot be written.
// Given a published feed with an ETag, when its transfer fails and the absent record that retires the ETag cannot be
// created, then the ETag is retired all the same: put back, it would let the next probe answer 304 for the refused body.
func TestFailedIngestRetiresTheValidatorsWithoutTheirRecord(t *testing.T) {
	got, stage := failingTransfer(t, func(op, path string) error {
		if op == "create" && strings.HasPrefix(filepath.Base(path), ".feed_v4.orig.etag"+absentMark) {
			return syscall.ENOSPC
		}
		return nil
	})
	if got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the failing transfer = %+v, want failed at the fetch", got)
	}
	if regularExists(filepath.Join(stage.Paths.FeedDir, "feed_v4.orig.etag")) {
		t.Fatal("a failed transfer whose absent record could not be written put the ETag back, want it retired")
	}
	if body := readFile(t, filepath.Join(stage.Paths.FeedDir, "feed_v4.orig")); body != "203.0.113.1\n" {
		t.Fatalf("the download after a failed transfer = %q, want the last one", body)
	}
	journalLeftovers(t, stage.Paths.FeedDir, "after the failed run")
}

// Scenario: a validator can be retired in no way.
// Given a published feed with an ETag, when its transfer fails and neither the absent record of the ETag nor the removal of
// its backup can be made, then the run reports that the validators are not retired, never only the transfer's failure.
func TestValidatorsThatCannotBeRetiredAreReported(t *testing.T) {
	got, _ := failingTransfer(t, func(op, path string) error {
		name := filepath.Base(path)
		if op == "create" && strings.HasPrefix(name, ".feed_v4.orig.etag"+absentMark) ||
			op == "remove" && strings.HasPrefix(name, ".feed_v4.orig.etag"+backupMark) {
			return syscall.EIO
		}
		return nil
	})
	if got.Disposition != "failed" || got.Stage != "fetch" || got.Reason != "validators_retire_failed" {
		t.Fatalf("the failing transfer = %+v, want failed/fetch/validators_retire_failed", got)
	}
}
