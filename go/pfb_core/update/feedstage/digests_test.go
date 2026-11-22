package feedstage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Scenario: the text of a custom list changes over the digests of an earlier download.
// Given a custom list whose download stands with an xxh128 digest and a legacy MD5 digest beside it, when its text
// changes, then both digests are gone with the new text: neither describes the bytes the download now holds.
func TestAChangedCustomTextDropsEveryDigest(t *testing.T) {
	stage := testStage(t)
	dir := stage.Paths.FeedDir
	orig := filepath.Join(dir, "Test_custom_v4.orig")
	writeFile(t, orig, "203.0.113.1\n")
	writeFile(t, orig+".xxhash128", "0123456789abcdef0123456789abcdef")
	writeFile(t, orig+".md5", "0123456789abcdef0123456789abcdef")
	got := stage.Run(context.Background(), Feed{ID: "custom:ipv4:Test", Kind: "ipv4", Name: "Test_custom_v4", State: "enabled",
		Format: "auto", Custom: true, CustomText: "203.0.113.21\n"}, Change{Force: "none"})
	if got.Disposition != "changed" {
		t.Fatalf("the run = %+v, want the new text published", got)
	}
	if body := readFile(t, orig); body != "203.0.113.21\n" {
		t.Errorf("the download is %q, want the new text", body)
	}
	for _, suffix := range []string{".xxhash128", ".md5"} {
		if _, err := os.Lstat(orig + suffix); !os.IsNotExist(err) {
			t.Errorf("the digest %s stands beside the new text (%v)", filepath.Base(orig+suffix), err)
		}
	}
}

// Scenario: a forced download of both kinds fails.
// Given a published feed whose download has an xxh128 and a legacy MD5 digest, when a run forced to download and drop the
// digests (force both) cannot transfer the source, then the feed fails at the transfer, its download and list stay, and
// both digests are gone: today's Force both sweeps them before any transfer, whatever its outcome
// (pfb_force_clear_validators()).
func TestAFailedTransferUnderForceBothStillDropsTheDigests(t *testing.T) {
	stage, feed, source := localStage(t)
	writeFile(t, source, "198.51.100.1\n")
	if r := run(stage, feed, "none"); r.Disposition != "changed" {
		t.Fatalf("the baseline run = %+v", r)
	}
	dir := stage.Paths.FeedDir
	orig := filepath.Join(dir, "feed_v4.orig")
	writeFile(t, orig+".md5", "0123456789abcdef0123456789abcdef")
	if !regularExists(orig + ".xxhash128") {
		t.Fatal("the baseline run left no xxh128 digest")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if got := run(stage, feed, "both"); got.Disposition != "failed" || got.Stage != "fetch" {
		t.Fatalf("the run = %+v, want failed at the transfer", got)
	}
	for _, path := range []string{orig, filepath.Join(dir, "feed_v4.parsed.ip")} {
		if body := readFile(t, path); body != "198.51.100.1\n" {
			t.Errorf("after the failed run %s = %q, want it as it was", filepath.Base(path), body)
		}
	}
	for _, suffix := range []string{".xxhash128", ".md5"} {
		if _, err := os.Lstat(orig + suffix); !os.IsNotExist(err) {
			t.Errorf("the digest %s survived the forced run (%v)", filepath.Base(orig+suffix), err)
		}
	}
}
