package scheduler

import (
	"errors"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// A caller tells "the schedule cannot be planned" from the gate's refusal by ErrModel, whatever the cause behind it.
func TestAModelThatCannotBeBuiltIsErrModelFromEveryEntryPoint(t *testing.T) {
	f := newFixture(t, allEntries(), "")
	broken := errors.New("settings unavailable")
	f.setModelErr(broken)

	if err := f.s.Tick(); !errors.Is(err, ErrModel) || !errors.Is(err, broken) {
		t.Errorf("Tick returned %v, want ErrModel wrapping %v", err, broken)
	}
	if err := f.s.Start("retry", "", ""); !errors.Is(err, ErrModel) || !errors.Is(err, broken) {
		t.Errorf("a retry returned %v, want ErrModel wrapping %v", err, broken)
	}
	if _, err := f.s.View(); !errors.Is(err, ErrModel) || !errors.Is(err, broken) {
		t.Errorf("View returned %v, want ErrModel wrapping %v", err, broken)
	}
}

func TestOtherRefusalsAreNotErrModel(t *testing.T) {
	f := newFixture(t, allEntries(), "")
	f.setStartErr(update.ErrRunning)
	if err := f.s.Start("retry", "", ""); !errors.Is(err, update.ErrRunning) || errors.Is(err, ErrModel) {
		t.Errorf("a retry refused by the gate returned %v, want ErrRunning and not ErrModel", err)
	}
	if err := f.s.Start("nosuch", "", ""); err == nil || errors.Is(err, ErrModel) {
		t.Errorf("an unknown trigger returned %v, want an error that is not ErrModel", err)
	}
}
