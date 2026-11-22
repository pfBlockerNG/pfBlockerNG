package feedstage

import (
	"os"
	"path/filepath"
	"testing"
)

// Recover removes what a KILL inside stage 6's change probe leaves in the feed folder, the one writer there besides a
// commit: the probe body's temporary and the validators' temporaries, for a valid feed stem only. The transfer, the
// scripts and the normalization write in the run folder, which Recover deletes whole.
func TestRecoverRemovesTheTransferTemporaries(t *testing.T) {
	dir := t.TempDir()
	removed := []string{"a_v4.orig.etag.part", "a_v4.orig.lastmod.part", "a_v4.orig.size.part", "a_v4.probe.part",
		"a_v4.probe.etag.part", "a_v4.probe.lastmod.part", "a_v4.probe.size.part"}
	kept := []string{"a_v4.orig", "a.b.orig.tmp", "a.b.orig.size.part", "a.b.probe.part", "a_v4.probe", "notes.part", ".pfbstagebak2_a", "pfbstage_1"}
	for _, name := range append(append([]string{}, removed...), kept...) {
		writeFile(t, filepath.Join(dir, name), "x\n")
	}
	if err := Recover(dir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for _, name := range removed {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("Recover left %s (%v)", name, err)
		}
	}
	for _, name := range kept {
		if !regularExists(filepath.Join(dir, name)) {
			t.Errorf("Recover removed %s, which is no temporary of a feed's transfer", name)
		}
	}
}
