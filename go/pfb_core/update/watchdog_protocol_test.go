//go:build linux || freebsd

package update

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTheWatchdogAcknowledgesReadinessWithItsOwnProcessGroupEstablished(t *testing.T) {
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.reap() })
	group, err := syscall.Getpgid(w.cmd.Process.Pid)
	if err != nil || group != w.cmd.Process.Pid {
		t.Errorf("ready watchdog group = %d, %v; want its pid %d", group, err, w.cmd.Process.Pid)
	}
	if err := w.retire(false); err != nil {
		t.Errorf("ready watchdog did not acknowledge completion: %v", err)
	}
}

func TestAStoppedWatchdogsAcknowledgementTimeoutLeavesTheSuccessfulProgramsDaemon(t *testing.T) {
	setKillGrace(t, 100*time.Millisecond)
	w, err := startWatchdog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.cmd.Process.Kill(); _ = w.reap() })
	request, requestW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	defer requestW.Close()
	response, responseW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	defer responseW.Close()
	daemon := exec.Command("/bin/sh", "-c", "printf r; read token; printf a; exec sleep 60")
	daemon.Stdin, daemon.Stdout = request, responseW
	daemon.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: w.cmd.Process.Pid}
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Process.Kill(); _ = daemon.Wait() })
	_ = request.Close()
	_ = responseW.Close()
	if err := response.SetReadDeadline(time.Now().Add(stuck)); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(response, reply[:]); err != nil || reply[0] != 'r' {
		t.Fatalf("daemon readiness = %q, %v; want r", reply, err)
	}
	if err := w.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(stuck); ; {
		probe, stop := context.WithTimeout(context.Background(), time.Second)
		state, err := exec.CommandContext(probe, "ps", "-o", "stat=", "-p", strconv.Itoa(w.cmd.Process.Pid)).Output()
		stop()
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(state)), "T") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: watchdog never stopped: state %q, %v", state, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := w.retire(false); err == nil || !strings.Contains(err.Error(), "did not acknowledge completion") {
		t.Errorf("retire(stopped watchdog) = %v; want an acknowledgement failure", err)
	}
	if _, err := requestW.Write([]byte("continue\n")); err != nil {
		t.Fatalf("successful daemon could not receive its post-retirement request: %v", err)
	}
	if _, err := io.ReadFull(response, reply[:]); err != nil || reply[0] != 'a' {
		t.Errorf("daemon post-retirement acknowledgement = %q, %v; want a (still executing)", reply, err)
	}
}

func TestAWatchdogThatCannotReportReadinessExitsInsteadOfWaitingForCompletion(t *testing.T) {
	ready, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = ready.Close()
	defer readyW.Close()
	completion, completionW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Close()
	defer completionW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], superviseArg)
	cmd.ExtraFiles = []*os.File{readyW, completion}
	cmd.SysProcAttr = procAttr()
	if err := cmd.Run(); err == nil || ctx.Err() != nil {
		t.Errorf("watchdog with failed readiness = %v, context %v; want its own immediate error, not a wait for completion", err, ctx.Err())
	}
}

func TestEveryTerminalProgramResultCommitsCompletionWithoutKillingItsDaemon(t *testing.T) {
	for _, end := range []string{"exit 0", "exit 7", "exit 75", "kill -TERM $$"} {
		t.Run(end, func(t *testing.T) {
			c, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null &
echo $! > "$D/child"
`+end)
			_, err := c.Run(context.Background(), Request{}, newLog(t))
			if (end == "exit 0") != (err == nil) {
				t.Errorf("Run(%s) = %v; want success only for exit 0", end, err)
			}
			child := recordedPid(t, dir)
			if exited(child) {
				t.Errorf("daemon %d was killed after terminal program result %s", child, end)
			}
		})
	}
}
