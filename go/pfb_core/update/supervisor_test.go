package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// A Core killed outright takes its Update's whole process group with it (issue #4003), not only the program: a command the
// program started (an Extra's own php) must not run on with nothing left to watch it.
func TestTheProgramsChildDiesWithACoreThatIsKilled(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("%s has no parent-death signal (procattr_other.go)", runtime.GOOS)
	}
	_, dir := program(t, `sleep 300 & echo $! > "$D/child"; echo up > "$D/up"; wait`)
	core := exec.Command(os.Args[0], "-test.run=^$")
	core.Env = append(os.Environ(), coreDirEnv+"="+dir)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Process.Kill(); _ = core.Wait() })
	awaitFile(t, filepath.Join(dir, "up"))
	pid := recordedPid(t, dir)
	if exited(pid) {
		t.Fatalf("before-state: the program's child %d is not running under its Core", pid)
	}

	if err := core.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = core.Wait()

	if !gone(pid) {
		t.Errorf("the program's child %d still runs after its Core was killed, want the Update's whole group killed with its Core", pid)
	}
}
