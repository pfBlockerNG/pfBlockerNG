package update

import (
	"os/exec"
	"testing"
)

func start(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("ENVIRONMENT: %v", err)
	}
	return cmd
}

func TestAReapedChildIsExited(t *testing.T) {
	cmd := start(t, "true")
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !exitedUnreaped(cmd.Process.Pid) {
		t.Fatal("a reaped child was reported running")
	}
}

func TestAnExitedChildIsExitedAndStaysUnreaped(t *testing.T) {
	cmd := start(t, "true")
	awaitZombie(t, cmd.Process.Pid)
	if !exitedUnreaped(cmd.Process.Pid) {
		t.Fatal("a zombie was reported running")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the check reaped the child: %v", err)
	}
}

func TestARunningChildIsNotExited(t *testing.T) {
	cmd := start(t, "sleep", "60")
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	checked := make(chan bool, 1)
	go func() { checked <- exitedUnreaped(cmd.Process.Pid) }()
	if recv(t, checked, "the check blocked on a running child") {
		t.Fatal("a running child was reported exited")
	}
}

func TestAProcessThatIsNotAChildIsExited(t *testing.T) {
	if !exitedUnreaped(1) { // init: never this test's child
		t.Fatal("a process of someone else's was reported running")
	}
}

func TestACheckThatCannotBeAnsweredIsNotExited(t *testing.T) {
	if exitedUnreaped(-1) { // waitid(P_PID, -1) is EINVAL
		t.Fatal("an unanswerable check reported exited: Run would leave a running program's group alone")
	}
}
