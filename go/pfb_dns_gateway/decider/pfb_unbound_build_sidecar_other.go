//go:build !linux && !freebsd && !darwin

package decider

import "os"

// sidecarOpenFlags is zero where the OS has no O_NOFOLLOW: dnsblFixedTop1mLines refuses the sidecar there, as Python
// does when os.O_NOFOLLOW is missing.
const sidecarOpenFlags = 0

func statCtimeNlink(os.FileInfo) (ctimeNs int64, nlink uint64) { return 0, 0 }
