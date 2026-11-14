package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A program a signal ended reads to Core exactly as it would without the supervisor between them (issue #4003): the same
// "signal: ..." error, for the signals the Go runtime itself would catch, panic on or ignore too, and nothing of the supervisor
// in the log. The supervisor never dumps core itself (the program's own core file is the one to read), so no "(core dumped)".
func TestASignalEndsRunAsItEndedTheProgram(t *testing.T) {
	for _, sig := range []string{"KILL", "TERM", "INT", "HUP", "SEGV", "ABRT", "PIPE", "USR1"} {
		t.Run(sig, func(t *testing.T) {
			want := exec.Command("/bin/sh", "-c", "kill -"+sig+" $$").Run()
			if want == nil || !strings.HasPrefix(want.Error(), "signal: ") {
				t.Fatalf("ENVIRONMENT: sh killed by %s ends with %v, not a signal", sig, want)
			}
			p, _ := program(t, `kill -`+sig+` $$`)
			log := newLog(t)
			_, err := runCmd(t, p, Request{Trigger: "manual"}, log)
			wantErr := "the update program failed: " + strings.TrimSuffix(want.Error(), " (core dumped)")
			if err == nil || err.Error() != wantErr {
				t.Errorf("Run = %v, want %q, as the program ended", err, wantErr)
			}
			if text := logText(t, log); text != "" {
				t.Errorf("the log holds %.200q, want nothing: the program printed nothing", text)
			}
		})
	}
}

// A hangup sent inside the Update's group is the program's business, not Core's death (issue #4003).
func TestAHangupInsideTheGroupIsNotTakenForCoresDeath(t *testing.T) {
	p, _ := program(t, `trap '' HUP; kill -HUP 0; sleep 0.2; echo survived`)
	log := newLog(t)
	if _, err := runCmd(t, p, Request{Trigger: "manual"}, log); err != nil {
		t.Errorf("Run = %v, want success: a program that ignores HUP outlives its own HUP", err)
	}
	if text := logText(t, log); text != "survived\n" {
		t.Errorf("the log = %q, want the program to have run on", text)
	}
}

// coreKilledDuring runs child.sh (body, in the program's directory) as a child of the program under a Core of its own, kills
// that Core once the child is up, and returns the program's directory and the child's pid.
func coreKilledDuring(t *testing.T, body string) (string, int) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("%s has no parent-death signal (procattr_other.go)", runtime.GOOS)
	}
	_, dir := program(t, `sh "$D/child.sh" & wait`)
	if err := os.WriteFile(filepath.Join(dir, "child.sh"), []byte("D='"+dir+"'\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	core := exec.Command(os.Args[0], "-test.run=^$")
	core.Env = append(os.Environ(), coreDirEnv+"="+dir)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Process.Kill(); _ = core.Wait() })
	awaitFile(t, filepath.Join(dir, "up"))
	pid := recordedPid(t, dir)
	if err := core.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = core.Wait()
	return dir, pid
}

// When Core dies, a member of the Update's group that ignores TERM still ends: KILL follows the grace (issue #4003).
func TestAChildIgnoringTermIsKilledWhenCoreIsKilled(t *testing.T) {
	_, pid := coreKilledDuring(t, `trap '' TERM; echo $$ > "$D/child"; echo up > "$D/up"; while :; do sleep 1; done`)
	if !gone(pid) {
		t.Errorf("the child %d, which ignores TERM, still runs after its Core was killed, want it KILLed after the grace", pid)
	}
}

// When Core dies, a member of the Update's group that handles TERM gets its grace to finish (issue #4003).
func TestAChildHandlingTermGetsItsGraceWhenCoreIsKilled(t *testing.T) {
	dir, pid := coreKilledDuring(t, `trap 'sleep 0.3; echo handled > "$D/marker"; exit 0' TERM
echo $$ > "$D/child"; echo up > "$D/up"; sleep 300 & wait`)
	if !gone(pid) {
		t.Fatalf("the child %d still runs after its Core was killed", pid)
	}
	if marker, err := os.ReadFile(filepath.Join(dir, "marker")); err != nil || string(marker) != "handled\n" {
		t.Errorf("the child's marker = %q (%v), want it written: the child got no TERM, or no grace before KILL", marker, err)
	}
}
