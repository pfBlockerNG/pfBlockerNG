package decider

import (
	"os"
	"path/filepath"
	"testing"
)

// issue #4053 slice 3: the HSTS list is gone. A stale ini that still says python_hsts and a leftover pfb_py_hsts.txt
// change nothing: a block of a preloaded name, or of a name under a former built-in HSTS TLD, logs the Python type.
func TestAStaleHstsFlagAndPreloadFileNoLongerMarkABlock(t *testing.T) {
	rlQuietLog(t)
	dir := opManifestModule(t, []string{"python_hsts = true", "python_blocking = true"},
		map[string][]string{"feed.txt": {"blocked.dev", "blocked.example"}})
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_hsts.txt"), []byte("blocked.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := modMust(t, dir)
	m.stopReloadWatcher()
	next := m.snapshot.Load()
	for _, tc := range []struct{ name, tld string }{{"blocked.dev", "dev"}, {"blocked.example", "example"}} {
		got := evaluateDomain(tc.name, tc.name, tc.tld, false, m.evaluateCfg(next), next.containers())
		if !got.isFound || got.pType != "Python" {
			t.Errorf("%s: (isFound, pType) = (%v, %q), want (true, \"Python\")", tc.name, got.isFound, got.pType)
		}
	}
}
