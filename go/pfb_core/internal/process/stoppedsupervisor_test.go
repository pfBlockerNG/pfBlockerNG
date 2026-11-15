//go:build linux || freebsd

package process_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// A stopped watcher cannot publish an exit notification: cancellation must inspect the program itself.
func TestAContextEndingWithTheWatcherStoppedAfterTheProgramExitedPreservesItsDaemon(t *testing.T) {
	c, dir := program(t, `printf '{"version":1,"attempted":["ipv4:a_v4"]}\n' >&3
sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
group=$(ps -o pgid= -p $$ | tr -d ' ') || exit 1
printf '%s %s\n' "$$" "$group" > "$D/leader.tmp"; mv "$D/leader.tmp" "$D/leader"
kill -STOP "$group"
exit 0`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	actualChecked := make(chan struct{})
	oldExited, oldReap := *process.LeaderExited, *process.Reap
	t.Cleanup(func() { *process.LeaderExited, *process.Reap = oldExited, oldReap })
	var leader int
	*process.LeaderExited = func(pid int) bool {
		ended := oldExited(pid)
		if pid == leader && ended {
			close(actualChecked)
		}
		return ended
	}
	*process.Reap = func(cmd *exec.Cmd) error {
		awaitFile(t, filepath.Join(dir, "leader"))
		raw, err := os.ReadFile(filepath.Join(dir, "leader"))
		if err != nil {
			t.Fatal(err)
		}
		identity := strings.Fields(string(raw))
		if len(identity) != 2 {
			t.Fatalf("the program recorded an invalid pid/pgid %q", raw)
		}
		leader, err = strconv.Atoi(identity[0])
		if err != nil || leader <= 0 {
			t.Fatalf("the program recorded an invalid pid %q: %v", raw, err)
		}
		group, err := strconv.Atoi(identity[1])
		if err != nil || group <= 0 {
			t.Fatalf("the program recorded an invalid pgid %q: %v", raw, err)
		}
		child := recordedPid(t, dir)
		t.Cleanup(func() { _ = syscall.Kill(group, syscall.SIGCONT) })
		for deadline := time.Now().Add(stuck); ; {
			probe, stop := context.WithTimeout(context.Background(), time.Second)
			state, err := exec.CommandContext(probe, "ps", "-o", "stat=", "-p", strconv.Itoa(leader)).Output()
			stop()
			if err == nil && strings.HasPrefix(strings.TrimSpace(string(state)), "Z") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("STUCK: program %d never became a zombie with its watcher stopped: state %q, %v", leader, state, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		// Resume only after the real program-exit check, or the regression has killed the survivor.
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		watchdog := time.NewTimer(stuck)
		defer watchdog.Stop()
	waitDecision:
		for !exited(t, child) {
			select {
			case <-actualChecked:
				break waitDecision
			case <-tick.C:
			case <-watchdog.C:
				t.Fatal("STUCK: cancellation neither inspected the exited program nor ended its daemon")
			}
		}
		_ = syscall.Kill(group, syscall.SIGCONT)
		return cmd.Wait()
	}
	res, err := c.Run(ctx, update.Request{}, newLog(t))
	if err != nil || !reflect.DeepEqual(res, update.Result{Attempted: []string{"ipv4:a_v4"}}) {
		t.Errorf("Run() = %+v, %v; want the successful result after the program exited with its watcher stopped", res, err)
	}
	if child := recordedPid(t, dir); exited(t, child) {
		t.Errorf("the successful program's daemon %d was killed while its watcher was stopped", child)
	}
}
