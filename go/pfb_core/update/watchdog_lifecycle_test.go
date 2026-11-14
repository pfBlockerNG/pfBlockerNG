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
