//go:build linux || freebsd

package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const fstatProgramEnv = "PFB_TEST_PROGRAM_FSTAT"

func init() {
	if os.Getenv(fstatProgramEnv) != "1" || len(os.Args) != 1 {
		return
	}
	for fd := range 4 {
		var stat syscall.Stat_t
		if err := syscall.Fstat(fd, &stat); err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
			fmt.Fprintf(os.Stderr, "fd %d: fstat mode %o, %v; want a regular file\n", fd, stat.Mode, err)
			os.Exit(2)
		}
		path, err := os.Stat(fmt.Sprintf("/dev/fd/%d", fd))
		var mode any
		if err == nil {
			mode = path.Mode()
		}
		fmt.Fprintf(os.Stdout, "fd %d: fstat regular; /dev/fd mode %v, regular=%t (%v)\n", fd, mode, err == nil && path.Mode().IsRegular(), err)
	}
	var request struct {
		Version int    `json:"version"`
		Trigger string `json:"trigger"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil || request.Version != 1 || request.Trigger != "manual" {
		fmt.Fprintf(os.Stderr, "stdin request = %+v, %v; want version 1 manual\n", request, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "stdout fstat proof")
	fmt.Fprintln(os.Stderr, "stderr fstat proof")
	if _, err := os.NewFile(3, "result").Write([]byte("{\"version\":1,\"attempted\":[\"ipv4:a_v4\"]}\n")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

func TestTheProgramReceivesFourRegularFilesByFstatAndReportsItsResult(t *testing.T) {
	t.Setenv(fstatProgramEnv, "1")
	log := newLog(t)
	res, err := (&Command{Path: os.Args[0]}).Run(context.Background(), Request{Trigger: "manual"}, log)
	text := logText(t, log)
	t.Log(text)
	if !strings.Contains(text, "stdout fstat proof") || !strings.Contains(text, "stderr fstat proof") {
		t.Errorf("program log = %q; want both stdout and stderr proof markers", text)
	}
	if err != nil || !reflect.DeepEqual(res, Result{Attempted: []string{"ipv4:a_v4"}}) {
		t.Errorf("Run(fstat program) = %+v, %v; want four regular descriptors and the fd 3 result", res, err)
	}
}
