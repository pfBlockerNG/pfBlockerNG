package update

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// coreDirEnv makes the test binary a Core that runs one Update of the program in that directory, until it is killed.
const coreDirEnv = "PFB_TEST_CORE_DIR"

func TestMain(m *testing.M) {
	if dir := os.Getenv(coreDirEnv); dir != "" {
		log, err := os.OpenFile(filepath.Join(dir, "update.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err == nil {
			_, err = (&Command{Path: filepath.Join(dir, "update.sh")}).Run(context.Background(), Request{Trigger: "manual"}, log)
		}
		fmt.Fprintln(os.Stderr, "the Core of the test ended its Update:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// A Core killed outright (SIGKILL, the OOM killer, a crash) takes its Update's program with it (issue #4003): nothing is left
// to record what the program reports, and the Core the supervisor starts next must not find it still running.
func TestTheProgramDiesWithACoreThatIsKilled(t *testing.T) {
	_, dir := program(t, `echo $$ > "$D/child"; echo up > "$D/up"; exec sleep 300`)
	core := exec.Command(os.Args[0], "-test.run=^$")
	core.Env = append(os.Environ(), coreDirEnv+"="+dir)
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.Process.Kill(); _ = core.Wait() })
	awaitFile(t, filepath.Join(dir, "up"))
	pid := recordedPid(t, dir)
	if exited(pid) {
		t.Fatalf("before-state: the program %d is not running under its Core", pid)
	}

	if err := core.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = core.Wait()

	if !gone(pid) {
		t.Errorf("the program %d still runs after its Core was killed, want it killed with its Core", pid)
	}
}
