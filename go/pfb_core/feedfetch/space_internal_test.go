package feedfetch

import "testing"

// The space a process may still use, from statfs: a negative count (UFS's reserve, root-only blocks in use) is none,
// never a wrapped-around huge number that would skip the staging-space check.
func TestAvailableBytesTreatsANegativeCountAsNone(t *testing.T) {
	for _, c := range []struct {
		avail int64
		size  uint64
		want  uint64
	}{{-5, 4096, 0}, {0, 4096, 0}, {3, 4096, 12288}} {
		if got, ok := availableBytes(c.avail, c.size); !ok || got != c.want {
			t.Errorf("availableBytes(%d, %d) = %d, %v; want %d, true", c.avail, c.size, got, ok, c.want)
		}
	}
}
