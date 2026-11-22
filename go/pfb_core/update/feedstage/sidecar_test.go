package feedstage

import (
	"context"
	"path/filepath"
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
