package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// issue #3513 (readiness for #3515): with --ready-file the gateway publishes its own pid, mode 0600, once it serves,
// and at stop removes the file only while it still names this process.

// readyFileFlags is a gateway on an ephemeral port with no Unbound config, publishing to ready.
func readyFileFlags(ready string) []string {
	return []string{"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf", "--ready-file", ready}
}

// readReadyPid reads the pid the gateway wrote: decimal, one line.
func readReadyPid(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSuffix(string(b), "\n"))
	if err != nil {
		t.Fatalf("ready file %q: %v", b, err)
	}
	return pid
}

// stopGateway sends SIGTERM and requires a clean exit.
func stopGateway(t *testing.T, gw *gatewayProcess) {
	t.Helper()
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGTERM, want 0; log:\n%s", code, gw.logText())
	}
}

// Once the gateway logs readiness the file exists: it holds the gateway's own pid (not the decider's), is mode 0600,
// is not handed to the decider, and the listener it names answers queries.
func TestReadyFilePublishesTheGatewayPidOnceItServes(t *testing.T) {
	dir := t.TempDir()
	ready, pidfile, argvFile := filepath.Join(dir, "ready"), filepath.Join(dir, "decider.pid"), filepath.Join(dir, "argv")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	t.Setenv("PFB_FAKE_ARGVFILE", argvFile)
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream ")

	info, err := os.Stat(ready)
	if err != nil {
		t.Fatalf("no ready file when the gateway logged readiness: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ready file mode %o, want 0600", perm)
	}
	if pid := readReadyPid(t, ready); pid != gw.cmd.Process.Pid {
		t.Fatalf("ready file names pid %d, want the gateway's %d", pid, gw.cmd.Process.Pid)
	}
	if dec := readPid(t, pidfile); dec == readReadyPid(t, ready) {
		t.Fatalf("ready file names the decider's pid %d", dec)
	}
	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 0 {
		t.Fatalf("the decider was handed %q: the ready flag belongs to the gateway", argv)
	}
	query := buildQuery(t, 0x4321, "example.", true)
	if got, want := udpQuery(t, serving, query), echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("query after the ready file: got %x, want the decider's %x", got, want)
	}
	stopGateway(t, gw)
}

// READY is what publishes: the decider looks at the ready file just before it sends READY and records what it saw, so the
// order is read from the decider's own events, not inferred from a window in which a test saw no file. The file is absent
// at that moment and, once the gateway reports that it serves, names the gateway.
func TestReadyFileIsNotPublishedBeforeTheDeciderIsReady(t *testing.T) {
	dir := t.TempDir()
	ready, events := filepath.Join(dir, "ready"), filepath.Join(dir, "events")
	t.Setenv("PFB_FAKE_EVENTS", events)
	t.Setenv("PFB_FAKE_WATCH", ready)
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	if got, want := readEvents(t, events), []string{"before-ready ready-file=absent"}; !slices.Equal(got, want) {
		t.Fatalf("decider events %q, want %q: the ready file was published before the decider sent READY", got, want)
	}
	if pid := readReadyPid(t, ready); pid != gw.cmd.Process.Pid {
		t.Fatalf("ready file names pid %d once the gateway serves, want the gateway's %d", pid, gw.cmd.Process.Pid)
	}
	stopGateway(t, gw)
}

// A decider that never says READY means the gateway never published: after it stopped, nothing is left behind.
func TestReadyFileIsNotLeftBehindByAGatewayThatNeverBecameReady(t *testing.T) {
	dir := t.TempDir()
	ready, pidfile := filepath.Join(dir, "ready"), filepath.Join(dir, "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("no-ready-hang"))
	waitForPid(t, pidfile) // the decider is running and the gateway waits for its READY
	stopGateway(t, gw)
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("ready file left behind by a gateway that never became ready")
	}
}

func TestReadyFileIsRemovedAtStopWhileItNamesTheGateway(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	stopGateway(t, gw)
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("ready file survives the gateway's stop")
	}
}

// A marker that names another pid is not ours: stop leaves it byte for byte.
func TestReadyFileNamingAnotherPidIsLeftAloneAtStop(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	if err := os.WriteFile(ready, []byte("424242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopGateway(t, gw)
	if got, err := os.ReadFile(ready); err != nil || string(got) != "424242\n" {
		t.Fatalf("ready file naming another pid: got %q (%v), want it untouched", got, err)
	}
}

// Replaced by a symlink to a file that names the gateway, the marker is not ours to follow or remove: the target
// and the link both survive the stop.
func TestReadyFileReplacedBySymlinkIsNotFollowedAtStop(t *testing.T) {
	dir := t.TempDir()
	ready, victim := filepath.Join(dir, "ready"), filepath.Join(dir, "victim")
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	if err := os.WriteFile(victim, []byte(strconv.Itoa(gw.cmd.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ready); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ready); err != nil {
		t.Fatal(err)
	}
	stopGateway(t, gw)
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("the symlink's target was removed: %v", err)
	}
	if _, err := os.Lstat(ready); err != nil {
		t.Fatalf("the symlink was removed: %v", err)
	}
}

// A symlink planted where the marker goes is replaced by the publish, never written through.
func TestReadyFilePublishReplacesAPlantedSymlinkInsteadOfWritingThroughIt(t *testing.T) {
	dir := t.TempDir()
	ready, victim := filepath.Join(dir, "ready"), filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, ready); err != nil {
		t.Fatal(err)
	}
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("serve"))
	gw.waitLine("ready upstream ")
	if got, err := os.ReadFile(victim); err != nil || string(got) != "victim\n" {
		t.Fatalf("the victim of the planted symlink changed: %q (%v)", got, err)
	}
	info, err := os.Lstat(ready)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the planted symlink is still where the ready file goes")
	}
	if pid := readReadyPid(t, ready); pid != gw.cmd.Process.Pid {
		t.Fatalf("ready file names pid %d, want the gateway's %d", pid, gw.cmd.Process.Pid)
	}
	stopGateway(t, gw)
}

// A marker that cannot be written fails the start: exit 1, no readiness line, the decider gone and the port released.
func TestReadyFileThatCannotBeWrittenFailsStartupWithoutServing(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "missing", "ready")
	pidfile := filepath.Join(dir, "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	port := freePort(t)
	flags := []string{"--listen", "127.0.0.1", "--port", strconv.Itoa(port), "--unbound-conf", "/nonexistent/unbound.conf", "--ready-file", ready}
	gw := startGatewayProcess(t, flags, decider("serve"))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	if text := gw.logText(); !strings.Contains(text, "cannot write the ready file") || strings.Contains(text, "ready upstream") || strings.Contains(text, "listening") {
		t.Fatalf("want the ready-file error and no readiness line, got:\n%s", text)
	}
	requireGone(t, readPid(t, pidfile))
	l, err := bindPlain("127.0.0.1", port)
	if err != nil {
		t.Fatalf("the port is still held after a failed start: %v", err)
	}
	l.close()
}

// A marker some other process left is not ours, even when this gateway stops before it is ready.
func TestReadyFileLeftAloneWhenTheGatewayStopsBeforeReady(t *testing.T) {
	dir := t.TempDir()
	ready, pidfile := filepath.Join(dir, "ready"), filepath.Join(dir, "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	if err := os.WriteFile(ready, []byte("424242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gw := startGatewayProcess(t, readyFileFlags(ready), decider("no-ready-hang"))
	waitForPid(t, pidfile)
	stopGateway(t, gw)
	if got, err := os.ReadFile(ready); err != nil || string(got) != "424242\n" {
		t.Fatalf("ready file of another pid: got %q (%v), want it untouched", got, err)
	}
}
