//go:build linux

package decider

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Python's os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") is the kernel's MemTotal in bytes; on the host this was
// written on, both are 50519658496.
func TestTotalPhysicalRAMOnLinuxIsTheKernelsMemTotal(t *testing.T) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		t.Skipf("no /proc/meminfo: %v", err)
	}
	defer file.Close()
	var want uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			want = kib * 1024
		}
	}
	if want == 0 {
		t.Fatalf("/proc/meminfo has no MemTotal line")
	}
	got, ok := totalPhysicalRAM()
	if !ok || got != want {
		t.Errorf("totalPhysicalRAM = (%d, %v), want (%d, true)", got, ok, want)
	}
}

// With no seam set the gate asks the real probe, which reports this host's RAM, far above a small reload's projection.
func TestReloadRunSwapAsksTheRealRAMProbeByDefault(t *testing.T) {
	m := rlModule(t)
	m.totalRAM = nil
	b := newRlBuilds(m)
	if !m.reloadRunSwap(b.build) {
		t.Errorf("reloadRunSwap with the real RAM probe = false, want a swap on a host with RAM to spare")
	}
}
