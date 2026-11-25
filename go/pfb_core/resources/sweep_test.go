package resources

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stopAt makes the next writer call stop where the named step is reached, as a Core stopped there would leave the store:
// the step's work is durable, nothing after it ran.
func stopAt(t *testing.T, name string, call func()) {
	t.Helper()
	prev := step
	t.Cleanup(func() { step = prev })
	type stopped struct{}
	step = func(n string) {
		if n == name {
			panic(stopped{})
		}
	}
	defer func() {
		step = prev
		if r := recover(); r != nil {
			if _, ok := r.(stopped); !ok {
				panic(r)
			}
			return
		}
		t.Fatalf("the call never reached %s", name)
	}()
	call()
}

func storeFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// Scenario: issue #4181. RemovalApplied saves the index without the id and then prunes its files; a Core stopped between
// the two left files that no later call named, as the index no longer holds the id.
//
// GIVEN a removed id whose RemovalApplied stopped right after the index save, beside a held id with a baseline and a delta
// WHEN the writer sweeps the store
// THEN every file of the dropped id is gone, and every file the index names is kept and still served.
func TestSweepRemovesTheFilesOfAnIDTheIndexNoLongerHolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := Open(dir)
	for _, id := range []string{"ip-set/Gone/ipv4", "dnsbl/kept"} {
		if _, err := s.Publish(id, []string{"1.1.1.1"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Applied("dnsbl/kept", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish("dnsbl/kept", []string{"2.2.2.2"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("ip-set/Gone/ipv4"); err != nil {
		t.Fatal(err)
	}
	stopAt(t, "index-renamed", func() { _ = s.RemovalApplied("ip-set/Gone/ipv4") })
	if !slices.ContainsFunc(storeFiles(t, dir), func(n string) bool { return strings.HasPrefix(n, "ip-set~Gone~ipv4.") }) {
		t.Fatalf("before: %q, want the stopped removal to leave the dropped id's body", storeFiles(t, dir))
	}
	kept := []string{"dnsbl~kept.1.body", "dnsbl~kept.2.1.add", "dnsbl~kept.2.1.remove", "dnsbl~kept.2.body", "index.json"}

	if err := s.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := storeFiles(t, dir); !slices.Equal(got, kept) {
		t.Errorf("after the sweep:\n have %q\n want %q", got, kept)
	}
	if got := bodyLines(t, s, "dnsbl/kept", 1); !slices.Equal(got, []string{"1.1.1.1"}) {
		t.Errorf("the baseline serves %q, want [1.1.1.1]", got)
	}
}

// Scenario: issue #4181. Applied saves the index with the new baseline and then prunes the old one; a Core stopped between
// the two left the old baseline's body and the delta from it, and FoldApplied never calls Applied again for a generation
// that already is the baseline.
//
// GIVEN an id whose Applied of its current generation stopped right after the index save
// WHEN the writer sweeps the store
// THEN the old baseline's body and the delta from it are gone, and the current body is kept and still served.
func TestSweepRemovesTheOldBaselineAStoppedAppliedLeft(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := Open(dir)
	if _, err := s.Publish("dnsbl/kept", []string{"1.1.1.1"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Applied("dnsbl/kept", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish("dnsbl/kept", []string{"2.2.2.2"}, nil); err != nil {
		t.Fatal(err)
	}
	stopAt(t, "index-renamed", func() { _ = s.Applied("dnsbl/kept", 2) })
	if !slices.Contains(storeFiles(t, dir), "dnsbl~kept.1.body") {
		t.Fatalf("before: %q, want the stopped Applied to leave the old baseline's body", storeFiles(t, dir))
	}
	kept := []string{"dnsbl~kept.2.body", "index.json"}

	if err := s.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got := storeFiles(t, dir); !slices.Equal(got, kept) {
		t.Errorf("after the sweep:\n have %q\n want %q", got, kept)
	}
	if got := bodyLines(t, s, "dnsbl/kept", 2); !slices.Equal(got, []string{"2.2.2.2"}) {
		t.Errorf("the current body serves %q, want [2.2.2.2]", got)
	}
}

// GIVEN an id whose Applied of a generation the store does not hold, which clears the baseline, stopped right after the index
// save
// WHEN the writer sweeps the store
// THEN the cleared baseline's body and the delta from it are gone, and the current body is kept.
func TestSweepRemovesTheBaselineAStoppedClearingAppliedLeft(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	s := Open(dir)
	if _, err := s.Publish("dnsbl/kept", []string{"1.1.1.1"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Applied("dnsbl/kept", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish("dnsbl/kept", []string{"2.2.2.2"}, nil); err != nil {
		t.Fatal(err)
	}
	stopAt(t, "index-renamed", func() { _ = s.Applied("dnsbl/kept", 99) })
	if !slices.Contains(storeFiles(t, dir), "dnsbl~kept.1.body") {
		t.Fatalf("before: %q, want the stopped Applied to leave the cleared baseline's body", storeFiles(t, dir))
	}

	if err := s.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if got, want := storeFiles(t, dir), []string{"dnsbl~kept.2.body", "index.json"}; !slices.Equal(got, want) {
		t.Errorf("after the sweep:\n have %q\n want %q", got, want)
	}
}
