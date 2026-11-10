//go:build !linux && !freebsd

package decider

import "testing"

// Any other OS has no probe, so the gate declines (fail closed).
func TestTotalPhysicalRAMIsUnknownOnOtherSystems(t *testing.T) {
	if got, ok := totalPhysicalRAM(); ok {
		t.Errorf("totalPhysicalRAM = (%d, true), want unknown", got)
	}
}
