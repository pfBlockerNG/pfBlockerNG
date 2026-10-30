package main

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A start's first log line is `starting pid <pid>`: pfBlockerNG reads the gateway's log from the last such line to know
// which lines belong to which start, whatever the start went on to log or fail with.

// G12: the line comes before every line a start logs, and it names the process that logs it.
func TestAStartLogsItsPidBeforeAnyOtherLine(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	lines := strings.Split(logs.text(), "\n")
	if want := "starting pid " + strconv.Itoa(os.Getpid()); lines[0] != want {
		t.Fatalf("the first log line is %q, want %q; log:\n%s", lines[0], want, logs.text())
	}
	if n := strings.Count(logs.text(), "starting pid "); n != 1 {
		t.Fatalf("%d `starting pid` lines, want one per start; log:\n%s", n, logs.text())
	}
}

// G12: a start that fails says so after the line, not before it.
func TestAStartThatFailsStillLogsItsPidFirst(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.listen = []string{"192.0.2.1"} // not an address of this host: nothing binds
	if srv, err := start(cfg, logs.logf); err == nil {
		srv.shutdown()
		t.Fatal("start succeeded with no address to bind")
	}
	lines := strings.Split(logs.text(), "\n")
	if want := "starting pid " + strconv.Itoa(os.Getpid()); lines[0] != want {
		t.Fatalf("the first log line is %q, want %q; log:\n%s", lines[0], want, logs.text())
	}
	if i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "cannot listen on 192.0.2.1:") }); i < 1 {
		t.Fatalf("the bind error is at line %d, want one after the pid line; log:\n%s", i, logs.text())
	}
}

// G12: as a process, on stderr, with the pid of that process, ahead of the bind error of an address that cannot be bound.
func TestTheGatewayProcessLogsItsOwnPidFirst(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "192.0.2.1", "--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf"}, decider("serve"))
	gw.waitLine("ready upstream ")
	lines := strings.Split(gw.logText(), "\n")
	if want := "starting pid " + strconv.Itoa(gw.cmd.Process.Pid); lines[0] != want {
		t.Fatalf("the first stderr line is %q, want %q; log:\n%s", lines[0], want, gw.logText())
	}
	if i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "cannot listen on 192.0.2.1:") }); i < 1 {
		t.Fatalf("the bind error is at line %d, want one after the pid line; log:\n%s", i, gw.logText())
	}
}
