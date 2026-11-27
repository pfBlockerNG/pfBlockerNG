package update

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cutover's one-time move of PHP's DNSBL downloads (issue #4258's contract, wired by #3977): before an Update decides
// its work, the loop recovers the Core Updater's DNSBL feed folder and moves <db>/dnsblorig into it, so the first Update
// re-downloads nothing it would not have before.

func TestAnUpdateMovesPHPsDNSBLDownloadsBeforeItDecidesItsWork(t *testing.T) {
	fx := newLoopFixture(t)
	mkdirs(t, filepath.Join(fx.db, "dnsblorig"))
	touch(t, filepath.Join(fx.db, "dnsblorig", "Z.orig"), "z.example\n")
	touch(t, filepath.Join(fx.db, "dnsblorig", "Z.orig.etag"), `"etag-z"`)

	if _, err := fx.run(t, manual()); err != nil {
		t.Fatalf("run = %v, want success", err)
	}
	for name, want := range map[string]string{"Z.orig": "z.example\n", "Z.orig.etag": `"etag-z"`} {
		if b, err := os.ReadFile(filepath.Join(fx.db, "dnsbl", name)); err != nil || string(b) != want {
			t.Errorf("dnsbl/%s = %q, %v; want PHP's %q", name, b, err, want)
		}
		if _, err := os.Lstat(filepath.Join(fx.db, "dnsblorig", name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("dnsblorig/%s is still there (%v): the move removes PHP's copy once it is linked", name, err)
		}
	}
}

func TestAMoveThatFailsFailsTheUpdateBeforeAnyFeedWorkAndSaysWhy(t *testing.T) {
	fx := newLoopFixture(t)
	mkdirs(t, filepath.Join(fx.db, "dnsblorig"), filepath.Join(fx.db, "dnsbl", "Z.orig.etag"))
	touch(t, filepath.Join(fx.db, "dnsblorig", "Z.orig"), "z.example\n")
	// a directory at a sidecar name is never cleared by a retry (issue #4258)
	touch(t, filepath.Join(fx.db, "dnsbl", "Z.orig.etag", "x"), "")

	_, err := fx.run(t, manual())
	if err == nil || !strings.Contains(err.Error(), "dnsblorig") {
		t.Fatalf("run = %v, want a failure naming dnsblorig", err)
	}
	if n := fx.applyRuns(t); n != 0 {
		t.Errorf("the apply ran %d times, want none: nothing is published over a half-moved feed", n)
	}
	if _, err := os.Stat(filepath.Join(fx.db, "dnsbl", "D.orig")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dnsbl/D.orig exists (%v): no feed work runs after a failed move", err)
	}
	if text := logText(t, fx.log); !strings.Contains(text, "dnsblorig") {
		t.Errorf("the transcript does not name the failed move:\n%s", text)
	}
}
