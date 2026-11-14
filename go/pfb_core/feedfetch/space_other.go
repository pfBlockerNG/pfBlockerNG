//go:build !linux && !freebsd && !darwin

package feedfetch

// freeBytes: no file system call is made on this host, so the space is not known, which is no shortfall.
func freeBytes(string) (uint64, bool) { return 0, false }
