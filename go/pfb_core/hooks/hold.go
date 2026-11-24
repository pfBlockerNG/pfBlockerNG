package hooks

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/process"
)

// holdArg re-executes this binary as a hook's holder (Runner.Hold): it runs the hook named by the arguments after it,
// keeps the lock it inherited as descriptor 3 until the hook's own process exits, passes TERM on to the hook, and exits
// with the hook's status as exec reports it. The hook dies with the holder, so KILL after the grace still ends it.
const holdArg = "--hook-hold"

func init() {
	if len(os.Args) > 2 && os.Args[1] == holdArg {
		os.Exit(hold(os.Args[2:]))
	}
}

func hold(argv []string) int {
	syscall.CloseOnExec(3) // the hook and what it starts never get the lock
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	start := func(argv []string) (*exec.Cmd, error) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		process.DieWithParent(cmd.SysProcAttr)
		return cmd, cmd.Start()
	}
	cmd, err := start(argv)
	if len(argv) == 1 && errors.Is(err, syscall.ENOEXEC) { // no #! line: sh runs it, as execvp() does
		cmd, err = start([]string{bourneShell, argv[0]})
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 127
	case err != nil:
		return 126
	}
	go func() {
		for range term {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}()
	_ = cmd.Wait()
	if ws := cmd.ProcessState.Sys().(syscall.WaitStatus); ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return cmd.ProcessState.ExitCode()
}
