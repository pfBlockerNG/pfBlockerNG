package settings

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAFileBackendWritesOnlyAtItsOwnRevision(t *testing.T) {
	dir := t.TempDir()
	fb := NewFileBackend(dir)
	stored, err := fb.Read()
	if err != nil || stored.Initialized || stored.Revision != 0 {
		t.Fatalf("Read of an empty directory = %+v, %v, want uninitialized at revision 0", stored, err)
	}
	dns := Production().Projections[0]
	values := map[string]map[string]any{"dns": defaults(dns)}

	_, err = fb.Write(1, values)
	var c *ConflictError
	if !errors.As(err, &c) {
		t.Fatalf("Write(1) before the first configuration = %v, want a *ConflictError", err)
	}
	if _, err := os.Stat(filepath.Join(dir, storeFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the refused write made %s: %v", storeFile, err)
	}

	if rev, err := fb.Write(0, values); err != nil || rev != 1 {
		t.Fatalf("Write(0) = %d, %v, want the first configuration at revision 1", rev, err)
	}
	first := storeBytes(t, dir)
	other := map[string]map[string]any{"dns": defaults(dns)}
	other["dns"]["control"] = true
	if _, err := fb.Write(0, other); !errors.As(err, &c) {
		t.Errorf("Write(0) over a configuration = %v, want a *ConflictError", err)
	}
	if _, err := fb.Write(5, other); !errors.As(err, &c) || c.Field != "expectedRevision" {
		t.Errorf("Write(5) at revision 1 = %v, want a *ConflictError on expectedRevision", err)
	}
	if !bytes.Equal(storeBytes(t, dir), first) {
		t.Error("a refused write changed settings.json")
	}
	if rev, err := fb.Write(1, other); err != nil || rev != 2 {
		t.Fatalf("Write(1) at revision 1 = %d, %v, want revision 2", rev, err)
	}
	stored, err = fb.Read()
	if err != nil || !stored.Initialized || stored.Revision != 2 || string(stored.Projections["dns"]["control"]) != "true" {
		t.Errorf("Read after the writes = %+v, %v, want revision 2 with control true", stored, err)
	}
}

// Once the document is renamed into place it is the configuration: the write reports its revision beside the error, so
// the Store serves what is on disk.
func TestAFileBackendReportsACommittedWriteWhoseDirectorySyncFailed(t *testing.T) {
	dir := t.TempDir()
	fb := NewFileBackend(dir)
	syncDir = func(*os.File) error { return errors.New("injected directory sync failure") }
	t.Cleanup(func() { syncDir = (*os.File).Sync })
	rev, err := fb.Write(0, map[string]map[string]any{"dns": defaults(Production().Projections[0])})
	if err == nil || rev != 1 {
		t.Errorf("Write with a failing directory sync = %d, %v, want revision 1 with the error", rev, err)
	}
	if stored, err := fb.Read(); err != nil || stored.Revision != 1 {
		t.Errorf("Read after it = %+v, %v, want revision 1: the file was renamed into place", stored, err)
	}
}

func TestReloadOfAnUnreadableStoreFileFailsAndKeepsTheValues(t *testing.T) {
	st, dir := initialized(t)
	good := storeBytes(t, dir)
	before := jsonOf(t, get(t, st))
	if err := os.WriteFile(filepath.Join(dir, storeFile), []byte(`{"format": 1, "revision": `), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Reload(); isBackendError(err) == nil {
		t.Errorf("Reload over a truncated settings.json = %v, want a *BackendError", err)
	}
	if after := jsonOf(t, get(t, st)); after != before {
		t.Errorf("a failed Reload changed the values:\n before %s\n after  %s", before, after)
	}
	if err := os.WriteFile(filepath.Join(dir, storeFile), good, 0o600); err != nil {
		t.Fatal(err)
	}
	if snap, err := st.Reload(); err != nil || jsonOf(t, snap) != before {
		t.Errorf("Reload over the repaired file = %s, %v, want %s", jsonOf(t, snap), err, before)
	}
}
