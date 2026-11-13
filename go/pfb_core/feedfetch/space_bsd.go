//go:build freebsd || darwin

package feedfetch

import "syscall"

// freeBytes is what disk_free_space() reports: the blocks a process may still use.
func freeBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
