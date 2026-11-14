package feedfetch

// availableBytes is the space statfs leaves a process: avail blocks of size bytes.
func availableBytes(avail int64, size uint64) (uint64, bool) {
	return uint64(avail) * size, true
}
