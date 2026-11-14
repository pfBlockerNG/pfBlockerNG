//go:build linux || freebsd

package process_test

import (
	"context"
	"os/exec"
	"reflect"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// Between the program's exit and its supervisor's, the supervisor still runs: a context ending then must still find the program
// exited and leave its group alone (issue #4003), or a daemon a successful Update restarted is killed. leaderExited answers
// "still running" here, as it does in that window, so only what the supervisor tells Core can decide.
func TestAContextEndingWhileTheSupervisorOutlivesTheProgramLeavesTheGroupAndTheSuccess(t *testing.T) {
	c, dir := program(t, `printf '{"version":1,"attempted":["ipv4:a_v4"]}\n' >&3
sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
exit 0`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	decided := make(chan struct{})
	oldExited, oldReap := *process.LeaderExited, *process.Reap
	t.Cleanup(func() { *process.LeaderExited, *process.Reap = oldExited, oldReap })
	*process.LeaderExited = func(int) bool {
		defer close(decided)
		return false
	}
	// Run calls reap on this goroutine, so recv may fail the test from here.
	*process.Reap = func(cmd *exec.Cmd) error {
		awaitZombie(t, cmd.Process.Pid) // the supervisor has ended, so the program had ended before it
		cancel()
		recv(t, decided, "the watcher never decided after the cancel")
		return cmd.Wait()
	}

	res, err := c.Run(ctx, update.Request{}, newLog(t))

	if err != nil || !reflect.DeepEqual(res, update.Result{Attempted: []string{"ipv4:a_v4"}}) {
		t.Errorf("Run() = %+v, %v; want the program's result and no error: it had exited before the context ended", res, err)
	}
	if pid := recordedPid(t, dir); exited(pid) {
		t.Errorf("the program's member %d was killed after the program had exited", pid)
	}
}
