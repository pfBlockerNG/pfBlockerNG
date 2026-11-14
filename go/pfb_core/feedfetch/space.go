package feedfetch

// availableBytes is the space statfs leaves a process: avail blocks of size bytes. A count at or below zero (UFS's
// reserve, held by root) is no space at all, never a wrapped-around unsigned one.
func availableBytes(avail int64, size uint64) (uint64, bool) {
	if avail <= 0 {
		return 0, true
	}
	return uint64(avail) * size, true
}
