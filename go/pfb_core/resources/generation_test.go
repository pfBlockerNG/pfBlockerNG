package resources

import (
	"errors"
	"os"
	"testing"
)

// Generation reads the index alone (issue #4038, the Core Updater's apply of unrequested generations): a damaged body does
// not hide the generation the index holds, and an id the store does not hold, or holds as removed, is not found.
func TestGenerationReadsTheIndexAlone(t *testing.T) {
	s := Open(t.TempDir())
	for range 2 {
		if _, err := s.Publish("ip-set/A/ipv4", []string{"1.1.1.1"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Publish("ip-set/A/ipv4", []string{"2.2.2.2"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.bodyPath("ip-set/A/ipv4", 2), []byte("damaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("ip-set/A/ipv4", nil); err == nil {
		t.Fatal("before: Get reads the damaged body without an error")
	}
	if g, err := s.Generation("ip-set/A/ipv4"); err != nil || g != 2 {
		t.Errorf("Generation = %d, %v; want 2 from the index", g, err)
	}
	if _, err := s.Generation("ip-set/B/ipv4"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Generation of an id never published = %v, want ErrNotFound", err)
	}
	if err := s.Remove("ip-set/A/ipv4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Generation("ip-set/A/ipv4"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Generation of a removed id = %v, want ErrNotFound", err)
	}
}
