package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// decisionFiles reads the decisions folder: file name -> content.
func decisionFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("decisions folder: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(data)
	}
	return out
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// #4164: after a pull, each origin's banned values are in <decisions_dir>/<origin>.txt, one per line and sorted, mode 0644, so
// pfBlockerNG's filterlog daemon can name the origin of the decision that dropped an address without asking the LAPI.
func TestAPullWritesEachOriginsValuesToItsFile(t *testing.T) {
	h := newHarness(t, ok(startupBody))
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"crowdsec.txt": "198.51.100.10\n203.0.113.0/24\n2001:db8:beef::/48\n",
		"cscli.txt":    "198.51.100.11\n",
		"CAPI.txt":     "2001:db8:dead::1\n",
	}
	if got := decisionFiles(t, h.cfg.DecisionsDir); !sameFiles(got, want) {
		t.Fatalf("decision files = %q; want %q", got, want)
	}
	info, err := os.Stat(filepath.Join(h.cfg.DecisionsDir, "CAPI.txt"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("decision file mode = %v, %v; want 0644", info, err)
	}
}

// A delta rewrites only the origins whose values changed and removes an origin left with none; a failed pull touches nothing.
func TestADeltaRewritesOnlyChangedOriginsAndAFailedPullNone(t *testing.T) {
	h := newHarness(t, ok(startupBody),
		ok(`{"new":[{"id":6,"origin":"lists:firehol_level1","type":"ban","scope":"Range","value":"192.0.2.0/24"}],
			"deleted":[{"id":2,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.11"}]}`),
		lapiReply{502, "down"})
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(1_000_000_000, 0)
	unchanged := filepath.Join(h.cfg.DecisionsDir, "crowdsec.txt")
	if err := os.Chtimes(unchanged, old, old); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"crowdsec.txt":             "198.51.100.10\n203.0.113.0/24\n2001:db8:beef::/48\n",
		"CAPI.txt":                 "2001:db8:dead::1\n",
		"lists:firehol_level1.txt": "192.0.2.0/24\n",
	}
	if got := decisionFiles(t, h.cfg.DecisionsDir); !sameFiles(got, want) {
		t.Fatalf("decision files after the delta = %q; want %q", got, want)
	}
	if info, _ := os.Stat(unchanged); !info.ModTime().Equal(old) {
		t.Fatalf("crowdsec.txt rewritten (mtime %v) although its values did not change", info.ModTime())
	}

	if err := h.d.pull(ctx); err == nil {
		t.Fatal("pull against a 502 = nil")
	}
	if got := decisionFiles(t, h.cfg.DecisionsDir); !sameFiles(got, want) {
		t.Fatalf("decision files after a failed pull = %q; want them unchanged", got)
	}
}

// Files an earlier run left are replaced by the first pull's set; shutdown removes the files: a stopped bouncer bans nothing.
func TestTheFirstPullReplacesStaleFilesAndShutdownRemovesThem(t *testing.T) {
	h := newHarness(t, ok(`{"new":[{"id":1,"origin":"CAPI","type":"ban","scope":"Ip","value":"192.0.2.7"}],"deleted":[]}`))
	if err := os.MkdirAll(h.cfg.DecisionsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cscli.txt", "CAPI.txt"} {
		if err := os.WriteFile(filepath.Join(h.cfg.DecisionsDir, name), []byte("198.51.100.99\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	if err := h.d.setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.d.pull(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := decisionFiles(t, h.cfg.DecisionsDir), map[string]string{"CAPI.txt": "192.0.2.7\n"}; !sameFiles(got, want) {
		t.Fatalf("decision files = %q; want %q", got, want)
	}
	h.d.shutdown(ctx)
	if got := decisionFiles(t, h.cfg.DecisionsDir); len(got) != 0 {
		t.Fatalf("decision files after shutdown = %q; want none", got)
	}
}

// An origin becomes a file name of A-Z a-z 0-9 _ : @ + - only (no dot, so no name holds ".txt:", which ends the name in
// grep's output, and no comma, which would split the log's CSV row); an empty one is "unknown", and one that holds the key
// is "hidden", as the status file's origins.
func TestOriginFileNamesAreSafe(t *testing.T) {
	cases := map[string]string{
		"CAPI":                 "CAPI",
		"lists:firehol_level1": "lists:firehol_level1",
		"a/b.c,d e\n":          "a_b_c_d_e_",
		"x.txt:y":              "x_txt:y",
		"":                     "unknown",
		"key " + testKey:       "hidden",
	}
	for origin, want := range cases {
		if got := originFileName(origin, testKey); got != want {
			t.Errorf("originFileName(%q) = %q; want %q", origin, got, want)
		}
	}
	long := originFileName(string(slices.Repeat([]byte("a"), 300)), testKey)
	if len(long) != 200 {
		t.Errorf("a 300-byte origin's name has %d bytes; want 200", len(long))
	}
}
