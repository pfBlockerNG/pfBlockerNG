//go:build !linux && !freebsd

package decider

// totalPhysicalRAM is _reload_total_ram_bytes on a system with no probe: unknown, so the RAM gate declines (fail closed).
func totalPhysicalRAM() (uint64, bool) { return 0, false }
