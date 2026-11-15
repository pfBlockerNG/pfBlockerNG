//go:build linux || freebsd

package process_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const completionBoundaryEnv = "PFB_TEST_COMPLETION_BOUNDARY"

func init() {
	mode := os.Getenv(completionBoundaryEnv)
	if mode == "" {
		return
	}
	dir := os.Getenv(coreDirEnv + "_BOUNDARY")
	if mode == "before" {
		*process.Reap = func(cmd *exec.Cmd) error {
			err := cmd.Wait()
			_ = os.WriteFile(filepath.Join(dir, "boundary"), []byte("before completion"), 0o600)
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
			return err
		}
	}
	log, err := os.OpenFile(filepath.Join(dir, "update.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_, err = (&update.Command{Path: filepath.Join(dir, "update.sh")}).Run(context.Background(), update.Request{}, log)
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
			if exited(t, child) {
				t.Fatalf("before-state: daemon %d is not alive at the %s-completion boundary", child, mode)
			}
			if err := core.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = core.Wait()
			if mode == "before" {
				if !gone(t, child) {
					t.Errorf("daemon %d survived Core's death before completion was committed", child)
				}
			} else if exited(t, child) {
				t.Errorf("daemon %d was killed by Core's death after Run completed", child)
			}
		})
	}
}
