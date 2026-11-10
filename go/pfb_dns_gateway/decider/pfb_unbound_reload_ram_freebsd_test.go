//go:build freebsd

package decider

import "testing"

// hw.physmem is the FreeBSD counterpart of Linux's MemTotal: SC_PHYS_PAGES * SC_PAGE_SIZE.
func TestTotalPhysicalRAMOnFreeBSDIsHwPhysmem(t *testing.T) {
	if got, ok := totalPhysicalRAM(); !ok || got == 0 {
		t.Errorf("totalPhysicalRAM = (%d, %v), want hw.physmem and true", got, ok)
	}
}
