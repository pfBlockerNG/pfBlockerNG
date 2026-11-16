//go:build linux

package process

import "testing"

func TestAnUnanswerableExitCheckIsNotExited(t *testing.T) {
	if exitedUnreaped(-1) { // waitid(P_PID, -1) is EINVAL
		t.Fatal("an unanswerable check reported exited; cleanup would leave a running command's group alone")
	}
}
