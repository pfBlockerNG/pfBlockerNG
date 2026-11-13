package update

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// A descendant that keeps the program's stdin open must not hold Run, whatever the size of the request: it is a regular
// file, so nothing waits on it, and the program never reads it.
func TestAGrandchildHoldingStdinDoesNotHoldRunWithALargeRequest(t *testing.T) {
	var feeds []string
	for i := range 20000 { // about 450 KB: far over a pipe buffer
		feeds = append(feeds, fmt.Sprintf("ipv4:feed_%05d_v4", i))
	}
	p, dir := program(t, `exec 4<&0; sleep 60 <&4 & echo $! > "$D/child"`)
	res, err := runCmd(t, p, Request{Trigger: "apply", Feeds: feeds}, newLog(t))
	if err != nil {
		hint := ""
		if strings.Contains(err.Error(), "killed") {
			hint = " (STUCK: the wait on the program's stdin never ended, and the watchdog killed the program)"
		}
		t.Fatalf("Run = %v, want it back with no error once the program exited 0%s", err, hint)
	}
	if !reflect.DeepEqual(res, Result{}) {
		t.Errorf("Run returned %s, want an empty Result: the program reported none", jsonOf(t, res))
	}
	if pid := recordedPid(t, dir); exited(pid) {
		t.Errorf("the grandchild %d is gone, so Run did not return while it held stdin", pid)
	}
}
