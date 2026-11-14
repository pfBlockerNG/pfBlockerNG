//go:build linux || freebsd

package update

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestWatchdogDeathCleanupFinishesBeforeTheIndependentSalvageContextFires(t *testing.T) {
	c, _ := program(t, `kill -KILL "$(ps -o pgid= -p $$ | tr -d ' ')"; exec sleep 60`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	oldReap := reap
	t.Cleanup(func() { reap = oldReap })
	reap = func(cmd *exec.Cmd) error {
		// Salvage independently of the production monitor, even if it returns a cause without signalling the group.
		stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
		defer stop()
		return oldReap(cmd)
	}
	_, err := c.Run(ctx, Request{}, newLog(t))
	if ctx.Err() != nil {
		t.Errorf("the independent salvage context fired: %v; watchdog death must finish cleanup itself", ctx.Err())
	}
	if err == nil || !strings.Contains(err.Error(), "watchdog exited while the program was running") {
		t.Errorf("Run() = %v; want watchdog-death interruption before independent salvage", err)
	}
}
