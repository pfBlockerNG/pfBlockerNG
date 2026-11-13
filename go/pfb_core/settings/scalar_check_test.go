package settings

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A scalar field's Check refuses a value that is valid for its type but not for the setting (issue #3941: the schedule
// minute is a multiple of 15). The refusal names the field, and nothing is written.
func TestAScalarFieldCheckRefusesTheSaveNamingTheFieldAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	st := open(t, dir)
	if _, err := st.Initialize(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "settings.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Save(t.Context(), 1, changes(t, `{"schedule": {"minute": 20}}`))
	var v *ValidationError
	if !errors.As(err, &v) || len(v.Fields) != 1 || v.Fields[0].Field != "schedule.minute" {
		t.Fatalf("Save of minute 20 = %v, want a ValidationError naming schedule.minute", err)
	}
	if after, _ := os.ReadFile(file); !bytes.Equal(before, after) {
		t.Errorf("a refused save changed settings.json:\n%s\n%s", before, after)
	}
	if snap := get(t, st); snap.Revision != 1 || projection(t, snap, "schedule").Value["minute"] != int64(0) {
		t.Errorf("a refused save moved the settings: %s", jsonOf(t, snap))
	}
	if _, err := st.Save(t.Context(), 1, changes(t, `{"schedule": {"minute": 45}}`)); err != nil {
		t.Errorf("Save of minute 45: %v", err)
	}
	if _, err := st.Save(t.Context(), 2, changes(t, `{"schedule": {"minute": null}}`)); err != nil {
		t.Errorf("Save of minute null (the default 0): %v", err)
	}
}
