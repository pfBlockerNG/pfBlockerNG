package update

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Issue #4038, hostile row: the resource store directory missing or read-only fails the Update before any stage
// publishes. The loop checks the store right after the snapshot, so no stage after it runs.

// WHEN the loop's resource store is missing, is a file, or is a directory Core cannot write THEN the Update fails at the
// snapshot boundary, names the store, and no later stage runs; a store Core can write lets every stage run and is left as
// it was.
func TestAStoreThatCannotBeWrittenFailsTheUpdateBeforeAnyStagePublishes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) string
		fails bool
	}{
		{"missing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "resources") }, true},
		{"a file", func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "resources")
			touch(t, p, "")
			return p
		}, true},
		{"read-only", func(t *testing.T) string {
			if os.Geteuid() == 0 {
				t.Skip("root writes into a read-only directory, so the refusal cannot be observed")
			}
			p := t.TempDir()
			if err := os.Chmod(p, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(p, 0o755) })
			return p
		}, true},
		{"writable", func(t *testing.T) string { return t.TempDir() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.store(t)
			adapter, _ := settingsAdapter(t, plainReply)
			u := &updater{loop: Loop{SettingsCmd: adapter, ResourceDir: store}, req: Request{Trigger: "manual"}, stateDir: t.TempDir()}
			seen := recordBoundaries(t)
			err := u.run()
			if !tc.fails {
				if err != nil || !slices.Equal(*seen, wantBoundaries) {
					t.Fatalf("run = %v, boundaries %q; want every stage", err, *seen)
				}
				if entries, err := os.ReadDir(store); err != nil || len(entries) != 0 {
					t.Errorf("the store holds %d entries (%v) after the check, want none", len(entries), err)
				}
				return
			}
			if err == nil || errors.Is(err, ErrDeferred) {
				t.Fatalf("run = %v, want a failure", err)
			}
			if !strings.Contains(err.Error(), store) {
				t.Errorf("run = %v, want the store %s named", err, store)
			}
			if !slices.Equal(*seen, []string{"snapshot"}) {
				t.Errorf("boundaries:\n have %q\n want only the snapshot's", *seen)
			}
		})
	}
}
