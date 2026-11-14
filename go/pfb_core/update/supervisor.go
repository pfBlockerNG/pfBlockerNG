package update

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// superviseArg, then the program's path, makes the binary that links this package (pfb-core, or this package's test binary)
// the Update's supervisor (issue #4003). Command.Run starts it in a process group of its own, tied to Core by the
// parent-death signal (procAttr); it runs the program in that same group, passing stdin, stdout, stderr and fd 3 through,
// and exits as the program did. It holds nothing else: no settings, store, socket or log.
const superviseArg = "--update-supervise"

// coreDied is the parent-death signal the supervisor gets when Core dies. Core itself only ever sends the group TERM and KILL.
const coreDied = syscall.SIGHUP

// init dispatches the supervisor before anything of pfb-core runs, as the first thing the binary does.
func init() {
	if len(os.Args) == 3 && os.Args[1] == superviseArg {
		os.Exit(supervise(os.Args[2]))
	}
}

// supervise runs the program at path in its own process group and returns its exit status; a program a signal ended ends the
// supervisor with the same signal. When Core dies first, the group gets TERM, KILL after killGrace, and the supervisor with it.
func supervise(path string) int {
	died := make(chan os.Signal, 1)
	signal.Notify(died, coreDied)
	// Core's TERM to the group is for the program: the supervisor stays to report how it ends. A caught signal is reset to its
	// default in the program (exec), unlike an ignored one.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGTERM)
	cmd := exec.Command(path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{os.NewFile(3, "result")}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "the update program cannot be started: %v\n", err)
		return 127
	}
	exited := make(chan struct{})
	var code int
	var sig syscall.Signal
	go func() { code, sig = awaitExit(cmd); close(exited) }()
	select {
	case <-exited:
		if sig != 0 { // the same end as the program's: Core reads the signal from the supervisor's status
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig)
			time.Sleep(time.Second) // the signal ends the process here; one that cannot (SIGSTOP and the like) falls through
			return 128 + int(sig)
		}
		return code
	case <-died:
		group := -syscall.Getpgrp()
		_ = syscall.Kill(group, syscall.SIGTERM)
		time.Sleep(killGrace)                    // every member gets the grace, as Core gives it
		_ = syscall.Kill(group, syscall.SIGKILL) // the supervisor too: what TERM left of the group ends here
		select {}
	}
}
