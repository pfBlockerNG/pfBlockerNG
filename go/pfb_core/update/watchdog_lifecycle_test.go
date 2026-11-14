//go:build linux || freebsd

package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestTheUpdateProgramIsCoresOwnChildInTheWatchdogsGroup(t *testing.T) {
	c, dir := program(t, `echo "$PPID $(ps -o pgid= -p $$) $$" > "$D/ownership"`)
	if _, err := c.Run(context.Background(), Request{}, newLog(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "ownership"))
	if err != nil {
		t.Fatal(err)
	}
	var parent, group, pid int
	if _, err := fmt.Sscan(string(raw), &parent, &group, &pid); err != nil {
		t.Fatalf("invalid ownership record %q: %v", raw, err)
	}
	if parent != os.Getpid() || group == pid || group <= 0 {
		t.Errorf("program parent/group/pid = %d/%d/%d; want Core %d as parent and a separate watchdog group leader", parent, group, pid, os.Getpid())
	}
}

func TestAnUnexpectedWatchdogDeathEndsTheUnprotectedUpdateAndItsChildren(t *testing.T) {
	c, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
kill -KILL "$(ps -o pgid= -p $$ | tr -d ' ')"
wait`)
	_, err := c.Run(context.Background(), Request{}, newLog(t))
	if err == nil {
		t.Error("Run succeeded after its watchdog was killed; want an interrupted Update")
	}
	child := recordedPid(t, dir)
	if !gone(child) {
		t.Errorf("the unprotected Update's child %d survived its watchdog's unexpected death", child)
	}
}

const completionBoundaryEnv = "PFB_TEST_COMPLETION_BOUNDARY"

func init() {
	mode := os.Getenv(completionBoundaryEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv(coreDirEnv + "_BOUNDARY")
	if mode == "before" {
		reap = func(cmd *exec.Cmd) error {
			err := cmd.Wait()
			_ = os.WriteFile(filepath.Join(dir, "boundary"), []byte("before completion"), 0o600)
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
			return err
		}
	}
	log, err := os.OpenFile(filepath.Join(dir, "update.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_, err = (&Command{Path: filepath.Join(dir, "update.sh")}).Run(context.Background(), Request{}, log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = os.WriteFile(filepath.Join(dir, "boundary"), []byte("after completion"), 0o600)
	_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
	os.Exit(0)
}

func TestCoresDeathBeforeCompletionCleansTheGroupButAfterRunLeavesItsDaemon(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			_, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
exit 0`)
			core := exec.Command(os.Args[0], "-test.run=^$")
			core.Env = append(os.Environ(), completionBoundaryEnv+"="+mode, coreDirEnv+"_BOUNDARY="+dir)
			if err := core.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = core.Process.Kill(); _ = core.Wait() })
			awaitFile(t, filepath.Join(dir, "boundary"))
			child := recordedPid(t, dir)
			if exited(child) {
				t.Fatalf("before-state: daemon %d is not alive at the %s-completion boundary", child, mode)
			}
			if err := core.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = core.Wait()
			if mode == "before" {
				if !gone(child) {
					t.Errorf("daemon %d survived Core's death before completion was committed", child)
				}
			} else if exited(child) {
				t.Errorf("daemon %d was killed by Core's death after Run completed", child)
			}
		})
	}
}

func TestAProgramThatCannotStartReturnsAnErrorWithoutLeavingAWatchdog(t *testing.T) {
	c, _ := program(t, "exit 0")
	c.Path += ".missing"
	if _, err := c.Run(context.Background(), Request{}, newLog(t)); err == nil {
		t.Fatal("Run succeeded for a missing program")
	}
	// Every owned process must have been waited by Run, including its watchdog.
	children, err := exec.Command("pgrep", "-P", strconv.Itoa(os.Getpid())).Output()
	if err == nil && strings.TrimSpace(string(children)) != "" {
		t.Errorf("Run left child processes after its program could not start: %s", children)
	}
}
