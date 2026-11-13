package update

import (
	"context"
	"os/exec"
	"reflect"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// awaitZombie returns once pid has exited, leaving it unreaped.
func awaitZombie(t *testing.T, pid int) {
	t.Helper()
	var info [16]uint64 // a 128-byte siginfo_t
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			t.Fatalf("ENVIRONMENT: waitid(%d): %v", pid, errno)
		}
		return
	}
}

func TestAContextEndingAfterTheProgramExitedButBeforeItsReapLeavesTheGroupAndTheSuccess(t *testing.T) {
	setKillGrace(t, 100*time.Millisecond)
	c, dir := program(t, `printf '{"version":1,"attempted":["ipv4:a_v4"]}' >&3
sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
exit 0`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	decided := make(chan struct{})
	oldExited, oldReap := leaderExited, reap
	t.Cleanup(func() { leaderExited, reap = oldExited, oldReap })
	leaderExited = func(pid int) bool {
		defer close(decided)
		return oldExited(pid)
	}
	// Run calls reap on this goroutine, so recv may fail the test from here.
	reap = func(cmd *exec.Cmd) error {
		awaitZombie(t, cmd.Process.Pid)
		cancel()
		recv(t, decided, "the watcher never decided after the cancel")
		return cmd.Wait()
	}

	res, err := c.Run(ctx, Request{}, newLog(t))

	if err != nil || !reflect.DeepEqual(res, Result{Attempted: []string{"ipv4:a_v4"}}) {
		t.Fatalf("Run() = %+v, %v; want the program's result and no error: it had already exited", res, err)
	}
	if pid := recordedPid(t, dir); exited(pid) {
		t.Fatalf("the program's member %d was killed after the program had exited", pid)
	}
}
