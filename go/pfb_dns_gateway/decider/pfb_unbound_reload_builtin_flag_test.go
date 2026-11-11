package decider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A live reload carries the manifest's builtin_log_flag into the snapshot it swaps in: a regex block decided before the
// swap answers with the old mechanism, and the same block after the swap answers with the new one. A swap that dropped
// the flag would reset every reloaded box to the default "0" (Null Blocking) until the next restart.
func TestReloadSwapCarriesTheManifestBuiltinLogFlag(t *testing.T) {
	m, dir := rlManifestModule(t, nil, map[string][]string{"feed.txt": {`/^bad[0-9]+\.example$/`}})
	const q = "bad1.example"
	decide := func() dnsblDecision {
		snap := m.snapshot.Load()
		return *evaluateDomain(q, q, "example", false, m.evaluateCfg(snap), snap.containers())
	}

	before := decide()
	if !before.isFound || before.logType != "0" || before.nxdomain {
		t.Fatalf("before the swap: decision = %s, want a block with the default flag \"0\"", evDump(before))
	}

	manifest, err := json.Marshal(map[string]any{
		"version": 1,
		"config":  map[string]any{"builtin_log_flag": "4"},
		"feeds":   []map[string]string{{"raw": "feed.txt", "feed": "feed.txt", "group": "feed.txt", "log_flag": "1", "provenance": "feed"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pfb_py_sources.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if !m.reloadRunSwap(m.reloadBuildSnapshot) {
		t.Fatal("reloadRunSwap = false, want the swap reported")
	}

	after := decide()
	if !after.isFound || after.logType != "4" || !after.nxdomain {
		t.Errorf("after the swap: decision = %s, want the same block under flag \"4\" (NXDOMAIN)", evDump(after))
	}
}
