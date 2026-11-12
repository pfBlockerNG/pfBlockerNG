package settings

import (
	"strings"
	"testing"
)

// One Core per state directory: a second store on the same directory is refused while the first is open (each would
// accept a save at the same revision and one change would be lost), and taken once the first is closed.
func TestASecondStoreOnTheSameStateDirectoryIsRefused(t *testing.T) {
	st, dir := initialized(t)
	if second, err := Open(dir, testSchema()); err == nil {
		second.Close()
		t.Fatal("a second store opened the state directory a first one holds")
	} else if !strings.Contains(err.Error(), "in use") {
		t.Errorf("refusal = %v, want it to say the directory is in use", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	again, err := Open(dir, testSchema())
	if err != nil {
		t.Fatalf("Open after the first store closed: %v", err)
	}
	again.Close()
}
