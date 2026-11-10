//go:build linux

package decider

import "golang.org/x/sys/unix"

// totalPhysicalRAM is _reload_total_ram_bytes: total physical RAM in bytes, what os.sysconf("SC_PHYS_PAGES") times
// SC_PAGE_SIZE gives (glibc reads sysinfo(2) for it). Not free memory: the gate asks whether the transient could ever fit.
func totalPhysicalRAM() (uint64, bool) {
	var info unix.Sysinfo_t
	if unix.Sysinfo(&info) != nil || info.Unit == 0 {
		return 0, false
	}
	return uint64(info.Totalram) * uint64(info.Unit), true
}
