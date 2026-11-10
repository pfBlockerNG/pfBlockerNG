//go:build freebsd

package decider

import "golang.org/x/sys/unix"

// totalPhysicalRAM is _reload_total_ram_bytes: total physical RAM in bytes, hw.physmem, which is what os.sysconf
// ("SC_PHYS_PAGES") times SC_PAGE_SIZE gives (both 6306570240 on the pfSense box this was probed on). Not free memory: the gate asks
// whether the transient could ever fit.
// shortcut: hw.physmem is an unsigned long; a 32-bit FreeBSD reports 4 bytes, which SysctlUint64 refuses, so the gate
// declines there. The gateway is built for amd64 and arm64.
func totalPhysicalRAM() (uint64, bool) {
	physmem, err := unix.SysctlUint64("hw.physmem")
	return physmem, err == nil
}
