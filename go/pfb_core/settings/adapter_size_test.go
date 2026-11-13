package settings

import (
	"strings"
	"testing"
)

// Issue #3937 (review): the feed projections carry the groups' custom lists, so a read reply of a few MiB is a real
// configuration, not a runaway adapter; it loads. Past 32 MiB it still fails the call.
func TestAReadReplyOfSomeMiBLoads(t *testing.T) {
	list := strings.Repeat("192.0.2.0/24\n", (3<<20)/13) // 3 MiB of custom list
	reply := `{"version":1,"revision":4,"settings":{"feeds/ipv4":{"groups":[{"name":"Big","customList":"` +
		strings.ReplaceAll(list, "\n", `\n`) + `"}]}}}`
	st := loadFake(t, newFakeAdapter(t, reply), 0)
	if got := projection(t, get(t, st, "feeds/ipv4"), "feeds/ipv4").Value["groups"].([]any)[0].(map[string]any)["customList"]; got != list {
		t.Fatalf("the custom list read back as %d bytes, want %d", len(got.(string)), len(list))
	}
}
