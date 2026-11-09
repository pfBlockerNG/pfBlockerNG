//go:build linux

package decider

import (
	"os"
	"syscall"
)

// sidecarOpenFlags is what dnsblFixedTop1mLines opens the TOP1M sidecar with: never through a final symlink, never
// blocking on a FIFO. Zero means the OS has no O_NOFOLLOW and the sidecar is refused.
const sidecarOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// statCtimeNlink is st_ctime_ns and st_nlink of a file's stat.
func statCtimeNlink(info os.FileInfo) (ctimeNs int64, nlink uint64) {
	st := info.Sys().(*syscall.Stat_t)
	return int64(st.Ctim.Sec)*1e9 + int64(st.Ctim.Nsec), uint64(st.Nlink)
}
