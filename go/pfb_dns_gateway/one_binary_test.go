package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Issue #3791: pfb-dns is one process. These tests start the gateway role of the test binary WITHOUT a fake decider, so
// it boots the real one (package decider) on a module directory, and ask it over the sockets.

const (
	blockedName = "blocked.example."
	moduleVIP   = "10.10.10.1"
)

// writeModuleDir shapes dir like /var/unbound for the decider: an ini, the manifest and one raw feed that lists blocked.example
// as a VIP block (log flag 1: no log row, so the test writes no log).
func writeModuleDir(t *testing.T, dir string) {
	t.Helper()
	ini := "[MAIN]\npython_enable = true\npython_blocking = true\npython_reply = true\npython_cname = true\npython_control = true\n" +
		"python_control_legacy = true\ndnsbl_ipv4 = " + moduleVIP + "\ndnsbl_ipv6 = fd00::1\n"
	manifest, err := json.Marshal(map[string]any{
		"version": 1, "config": map[string]any{},
		"feeds": []map[string]string{{"raw": "pfb_py_raw/feed.txt", "feed": "TestFeed", "group": "TestGroup", "log_flag": "1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pfb_py_raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"pfb_unbound.ini":     ini,
		"pfb_py_sources.json": string(manifest),
		"pfb_py_raw/feed.txt": "blocked.example\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// oneBinaryFlags is a gateway in front of up on an ephemeral port, with no Unbound config, plus extra.
func oneBinaryFlags(up string, extra ...string) []string {
	return append([]string{"--listen", "127.0.0.1", "--port", "0", "--upstream", up, "--unbound-conf", "/nonexistent/unbound.conf"}, extra...)
}

// answerA is the A record the reply carries, "" when it has none.
func answerA(t *testing.T, wire []byte) string {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("reply %x does not parse: %v", wire, err)
	}
	for _, a := range m.Answers {
		if r, ok := a.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(r.A).String()
		}
	}
	return ""
}

// children is the pids of the processes the process pid has started, read from the kernel; ok is false where it cannot say.
func children(pid int) (pids []string, ok bool) {
	tasks, err := filepath.Glob("/proc/" + strconv.Itoa(pid) + "/task/*/children")
	if err != nil || len(tasks) == 0 {
		return nil, false
	}
	for _, f := range tasks {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, false
		}
		pids = append(pids, strings.Fields(string(b))...)
	}
	return pids, true
}

// R1: the module decides in the gateway's own process: a listed name gets the block answer over UDP and TCP and is never
// asked of Unbound; an unlisted one is relayed from Unbound; and the gateway has started no process.
func TestOneBinaryBlocksAListedNameAndRelaysTheRest(t *testing.T) {
	dir := shortTempDir(t)
	writeModuleDir(t, dir)
	up := newFakeUpstream(t)
	gw := startGatewayProcessWith(t, oneBinaryFlags(up.addr, "--module-dir", dir))
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream ")

	blocked := buildQuery(t, 0x0b0b, blockedName, true)
	if got := answerA(t, udpQuery(t, serving, blocked)); got != moduleVIP {
		t.Fatalf("blocked name over UDP: A %q, want the module's VIP %s\n%s", got, moduleVIP, gw.logText())
	}
	c, err := net.Dial("tcp4", serving.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tcpSend(t, c, blocked)
	if got := answerA(t, tcpReply(t, c)); got != moduleVIP {
		t.Fatalf("blocked name over TCP: A %q, want the module's VIP %s", got, moduleVIP)
	}
	select {
	case seen := <-up.queries:
		t.Fatalf("Unbound was asked for a blocked name: %x", seen.wire)
	default:
	}

	allowed := buildQuery(t, 0x0a0a, "allowed.example.", true)
	if got, want := udpQuery(t, serving, allowed), echoWithQR(seenQuery{wire: allowed})[0]; !bytes.Equal(got, want) {
		t.Fatalf("an unlisted name: got %x, want Unbound's reply %x", got, want)
	}
	if seen := up.next(); !bytes.Equal(seen.wire, allowed) {
		t.Fatalf("Unbound saw %x, want the unlisted query %x", seen.wire, allowed)
	}
	if kids, ok := children(gw.cmd.Process.Pid); ok && len(kids) != 0 {
		t.Fatalf("the gateway has child processes %v: the decider is part of it", kids)
	}
}

// R2: with --no-module no module boots: every query is relayed from Unbound, a listed name included.
func TestOneBinaryWithNoModuleRelaysEveryQuery(t *testing.T) {
	up := newFakeUpstream(t)
	gw := startGatewayProcessWith(t, oneBinaryFlags(up.addr, "--no-module"))
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream ")
	query := buildQuery(t, 0x0b0b, blockedName, true)
	if got, want := udpQuery(t, serving, query), echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("with no module: got %x, want Unbound's reply %x", got, want)
	}
}

// R3: the decider command of the old command line is not an argument any more.
func TestOneBinaryRefusesADeciderCommandAfterTheDoubleDash(t *testing.T) {
	gw := startGatewayProcessWith(t, []string{"--listen", "127.0.0.1", "--port", "0", "--", "/bin/true"})
	if code := gw.exit(); code != 2 {
		t.Fatalf("exit code %d, want 2; log:\n%s", code, gw.logText())
	}
	if text := gw.logText(); !strings.Contains(text, `unexpected argument "/bin/true"`) || strings.Contains(text, "listening") {
		t.Fatalf("want the unexpected-argument error and nothing served, got:\n%s", text)
	}
}

// R4: a module that cannot boot is exit 1 with the reason, nothing stays bound, no ready file. (A directory with no ini at all
// is not such a module: the decider logs "Ini file missing" and serves without DNSBL, as the Python decider did.)
func TestOneBinaryExitsOneWhenTheModuleCannotBoot(t *testing.T) {
	dir, ready := t.TempDir(), filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = banana\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	gw := startGatewayProcessWith(t, oneBinaryFlags("127.0.0.1:5353", "--port", strconv.Itoa(port), "--module-dir", dir, "--ready-file", ready))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	text := gw.logText()
	if !strings.Contains(text, "pfb_dns_gateway: decider: ") || !strings.Contains(text, "python_enable") || strings.Contains(text, "listening") || strings.Contains(text, "ready upstream") {
		t.Fatalf("want the boot error and no readiness line, got:\n%s", text)
	}
	l, err := bindPlain("127.0.0.1", port)
	if err != nil {
		t.Fatalf("the port is still held after a failed boot: %v", err)
	}
	l.close()
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("a ready file exists although the decider never booted")
	}
}

// R5: SIGTERM while the decider is still booting stops the gateway at once: exit 0, the stopped-by-signal line, no ready file.
func TestOneBinaryStoppedBySignalWhileTheDeciderBootsExitsZero(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	gw := startGatewayProcessWith(t, oneBinaryFlags("127.0.0.1:5353", "--ready-file", ready), "PFB_FAKE_FRONTEND=block-open")
	gw.waitLine("starting pid ") // the signal handlers are in place and the boot never ends
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGTERM during the boot, want 0; log:\n%s", code, gw.logText())
	}
	text := gw.logText()
	if !strings.Contains(text, "pfb_dns_gateway: stopped by signal before the decider was ready") || strings.Contains(text, "listening") {
		t.Fatalf("want the stopped-by-signal line and no readiness line, got:\n%s", text)
	}
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("a ready file exists although the decider never booted")
	}
}

// R6: shutdown closes the decider: its observer socket is gone after the exit, and so is the ready file.
func TestOneBinaryShutdownClosesTheDecider(t *testing.T) {
	dir := shortTempDir(t)
	writeModuleDir(t, dir)
	ready := filepath.Join(t.TempDir(), "ready")
	gw := startGatewayProcessWith(t, oneBinaryFlags("127.0.0.1:5353", "--module-dir", dir, "--observer", "--ready-file", ready))
	gw.waitLine("ready upstream ")
	socket := filepath.Join(dir, "pfb_upstream.sock")
	if info, err := os.Lstat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the observer socket while serving: %v (err %v), want a socket\n%s", info, err, gw.logText())
	}
	stopGateway(t, gw)
	if _, err := os.Lstat(socket); err == nil {
		t.Fatal("the observer socket is still there after shutdown: the decider was not closed")
	}
	if _, err := os.Stat(ready); err == nil {
		t.Fatal("the ready file is still there after shutdown")
	}
}

// R7: the decider is booted after the drop, so that what it creates is the unprivileged user's: its observer socket is owned
// by that user, mode 0600, which is what lets only the user Unbound runs as report to it. Root only: it needs a user to
// drop to, and a directory that user can write to.
func TestOneBinaryObserverSocketIsOwnedByTheUserTheGatewayDroppedTo(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a real drop to another user: needs root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no user `nobody` to drop to")
	}
	uid, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		t.Fatal(err)
	}
	dir := shortTempDir(t)
	writeModuleDir(t, dir)
	if err := os.Chmod(dir, 0o777); err != nil { // the user creates the socket in it
		t.Fatal(err)
	}
	gw := startGatewayProcessWith(t, oneBinaryFlags("127.0.0.1:5353", "--user", "nobody", "--module-dir", dir, "--observer"))
	gw.waitLine("ready upstream ")
	info, err := os.Lstat(filepath.Join(dir, "pfb_upstream.sock"))
	if err != nil {
		t.Fatalf("no observer socket while serving: %v\n%s", err, gw.logText())
	}
	if got := info.Sys().(*syscall.Stat_t).Uid; int(got) != uid {
		t.Fatalf("the observer socket is owned by uid %d, want %d (nobody): the decider was booted before the drop", got, uid)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the observer socket is mode %o, want 0600", perm)
	}
}

// A module error of the one-binary gateway is a py_error.log row in --log-dir, the file the Log Browser reads, and is not on
// the gateway's own log: the module's sys.stderr was py_error.log in the Python decider.
func TestOneBinaryModuleErrorsGoToPyErrorLogInTheLogDir(t *testing.T) {
	dir, logDir := shortTempDir(t), shortTempDir(t)
	writeModuleDir(t, dir)
	ini := filepath.Join(dir, "pfb_unbound.ini")
	text, err := os.ReadFile(ini)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ini, append(text, "[GP_Bypass_List]\nrow1 = not-an-ip\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	gw := startGatewayProcessWith(t, oneBinaryFlags("127.0.0.1:5353", "--module-dir", dir, "--log-dir", logDir))
	gw.waitLine("ready upstream ")
	rows, err := os.ReadFile(filepath.Join(logDir, "py_error.log"))
	if err != nil {
		t.Fatalf("no py_error.log in the log dir: %v\n%s", err, gw.logText())
	}
	want := regexp.MustCompile(`(?m)^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\|ERROR\| \[pfBlockerNG\]: Failed to parse: GP_Bypass_List: row:row1 line:not-an-ip\n`)
	if !want.Match(rows) {
		t.Fatalf("py_error.log is %q, want a Python-format row for the bad row", rows)
	}
	if strings.Contains(gw.logText(), "GP_Bypass_List") {
		t.Fatalf("the module error is also on the gateway's log:\n%s", gw.logText())
	}
}
