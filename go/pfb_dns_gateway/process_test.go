package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as the gateway, the decider and the privilege-drop probe: the process-level tests
// start it with a role as its first argument instead of building anything.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 {
		switch os.Args[1] {
		case "--as-gateway":
			os.Exit(realMain(os.Args[2:], os.Stderr))
		case "--as-decider":
			os.Exit(fakeDecider(os.Args[2]))
		case "--as-dropper":
			os.Exit(dropAndReport(os.Args[2]))
		case "--as-ctl-client":
			os.Exit(pushAsUser(os.Args[2], os.Args[3], os.Args[4]))
		}
	}
	os.Exit(m.Run())
}

// fakeDecider is the Python side of the socketpair (fd 3). Modes:
//
//	serve           READY, then answer every QUERY with the query echoed and QR set; exit 0 at EOF
//	no-ready-exit   exit 3 at once, never READY
//	no-ready-hang   never READY; wait for EOF
//	boot-ignores-eof never READY; ignore everything, EOF included
//	ready-then-exit READY, then exit 0
//	bad-frame       READY, then a frame whose length is below the minimum
//	ignore-eof      READY, then ignore everything, EOF included
//
// PFB_FAKE_PIDFILE gets its pid and PFB_FAKE_ARGVFILE its arguments before anything else; PFB_FAKE_EXIT_DELAY (a duration) holds the exit after EOF,
// which makes a gateway that exits before its child reaches the pid check with the child still alive.
func fakeDecider(mode string) int {
	conn, err := net.FileConn(os.NewFile(3, "decision"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake decider: no fd 3:", err)
		return 4
	}
	if path := os.Getenv("PFB_FAKE_PIDFILE"); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644)
	}
	if path := os.Getenv("PFB_FAKE_ARGVFILE"); path != "" { // what the gateway handed this process after its own role words
		_ = os.WriteFile(path, []byte(strings.Join(os.Args[3:], " ")), 0o644)
	}
	switch mode {
	case "no-ready-exit":
		return 3
	case "no-ready-hang":
		_, _ = io.Copy(io.Discard, conn)
		return 0
	case "boot-ignores-eof": // a module that is still booting reads no socket, so EOF goes unnoticed
		time.Sleep(time.Hour)
		return 0
	}
	_, _ = conn.Write(pack(tReady, 0, nil))
	switch mode {
	case "ready-then-exit":
		return 0
	case "bad-frame":
		_, _ = conn.Write([]byte{0, 0, 0, 3})
		_, _ = io.Copy(io.Discard, conn)
		return 0
	case "ignore-eof":
		time.Sleep(time.Hour)
		return 0
	}
	r := bufio.NewReader(conn)
	for {
		var head [9]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			break
		}
		payload := make([]byte, int(head[0])<<24|int(head[1])<<16|int(head[2])<<8|int(head[3])-5)
		if _, err := io.ReadFull(r, payload); err != nil {
			break
		}
		if head[4] == tQuery {
			wire := payload[2+int(payload[1]):] // payload[0] is the transport byte
			answer := bytes.Clone(wire)
			answer[2] |= 0x80
			id := uint32(head[5])<<24 | uint32(head[6])<<16 | uint32(head[7])<<8 | uint32(head[8])
			_, _ = conn.Write(pack(tAnswer, id, answer))
		}
	}
	if delay, err := time.ParseDuration(os.Getenv("PFB_FAKE_EXIT_DELAY")); err == nil {
		time.Sleep(delay)
	}
	return 0
}

// dropAndReport gives up root for the named user and reports what the process is afterwards.
func dropAndReport(name string) int {
	acct, err := lookupAccount(name)
	if err != nil {
		fmt.Println("lookup:", err)
		return 1
	}
	if err := acct.drop(); err != nil {
		fmt.Println("drop:", err)
		return 1
	}
	groups, _ := os.Getgroups()
	regain := "denied"
	if syscall.Setuid(0) == nil {
		regain = "ALLOWED"
	}
	fmt.Printf("uid=%d gid=%d euid=%d egid=%d groups=%v regain-root=%s\n", os.Getuid(), os.Getgid(), os.Geteuid(), os.Getegid(), groups, regain)
	return 0
}

func decider(mode string) []string { return []string{os.Args[0], "--as-decider", mode} }

// gatewayProcess is the gateway as its own process with its stderr read line by line.
type gatewayProcess struct {
	t      *testing.T
	cmd    *exec.Cmd
	lines  chan string
	exited chan struct{}
	code   int

	mu  sync.Mutex
	log []string
}

func startGatewayProcess(t *testing.T, flags []string, deciderArgv []string) *gatewayProcess {
	t.Helper()
	args := append(append([]string{"--as-gateway"}, flags...), "--")
	cmd := exec.Command(os.Args[0], append(args, deciderArgv...)...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &gatewayProcess{t: t, cmd: cmd, lines: make(chan string, 1024), exited: make(chan struct{})}
	read := make(chan struct{})
	go func() {
		defer close(read)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			p.mu.Lock()
			p.log = append(p.log, sc.Text())
			p.mu.Unlock()
			p.lines <- sc.Text()
		}
	}()
	go func() {
		<-read // the pipe must be drained before Wait closes it
		err := cmd.Wait()
		var exit *exec.ExitError
		switch {
		case err == nil:
		case errors.As(err, &exit):
			p.code = exit.ExitCode()
		default:
			p.code = -1
		}
		close(p.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.exited
	})
	return p
}

// waitLine returns the first line (from the current position) with the prefix; it fails if the process ends or the watchdog fires first.
func (p *gatewayProcess) waitLine(prefix string) string {
	p.t.Helper()
	for {
		select {
		case l := <-p.lines:
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-p.exited:
			select { // the last lines may still be in the channel
			case l := <-p.lines:
				if strings.HasPrefix(l, prefix) {
					return l
				}
				continue
			default:
			}
			p.t.Fatalf("the gateway exited (code %d) before logging %q; log:\n%s", p.code, prefix, p.logText())
		case <-time.After(watchdog):
			p.t.Fatalf("STUCK: no %q line within the watchdog; log:\n%s", prefix, p.logText())
		}
	}
}

func (p *gatewayProcess) logText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// exit waits for the process to end and returns its exit code.
func (p *gatewayProcess) exit() int {
	p.t.Helper()
	select {
	case <-p.exited:
		return p.code
	case <-time.After(watchdog):
		p.t.Fatalf("STUCK: the gateway is still running; log:\n%s", p.logText())
		return -1
	}
}

func requireGone(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d must be gone, kill(pid, 0) = %v", pid, err)
	}
}

// waitForPid blocks until the fake decider has written its pid: a drop hook calling it makes the decider exist
// (and be known) before the code under test can kill it.
func waitForPid(t *testing.T, path string) {
	t.Helper()
	eventually(t, "the decider to write its pid", func() bool {
		b, err := os.ReadFile(path)
		return err == nil && len(b) > 0
	})
}

func readPid(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		t.Fatalf("pid file %q: %v", b, err)
	}
	return pid
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func listenAddr(t *testing.T, line string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(strings.TrimPrefix(line, "listening udp+tcp "))
	if err != nil {
		t.Fatalf("readiness line %q: %v", line, err)
	}
	return ap
}

func udpQuery(t *testing.T, to netip.AddrPort, wire []byte) []byte {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(wire); err != nil {
		t.Fatal(err)
	}
	return udpReply(t, c)
}

// G18: one unbindable --listen address is skipped and named; the good one serves.
func TestGatewaySkipsAnUnbindableListenAddressAndServesTheOthers(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "192.0.2.1", "--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf"}, decider("serve"))
	skipped := gw.waitLine("cannot listen on 192.0.2.1:0:")
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream 127.0.0.1:5353")
	if serving.Addr() != netip.MustParseAddr("127.0.0.1") || serving.Port() == 0 {
		t.Fatalf("serving on %s, want 127.0.0.1 and a real port (skipped line: %q)", serving, skipped)
	}
	query := buildQuery(t, 0x1234, "example.", true)
	if got, want := udpQuery(t, serving, query), echoWithQR(seenQuery{wire: query})[0]; !bytes.Equal(got, want) {
		t.Fatalf("answer through the gateway: got %x, want the decider's %x", got, want)
	}
	if strings.Contains(gw.logText(), "listening udp+tcp 192.0.2.1") {
		t.Fatalf("the skipped address must not be reported as listening:\n%s", gw.logText())
	}
}

// issue #3513: the process the gateway starts is handed the pfB-DNS mode flags it was given, once, after its own argv.
func TestGatewayStartsTheDeciderWithTheModeFlagsItWasGiven(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	t.Setenv("PFB_FAKE_ARGVFILE", argvFile)
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0", "--no-module", "--reply-log", "--unbound-conf", "/nonexistent/unbound.conf"}, decider("serve"))
	gw.waitLine("ready upstream ")
	got, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "--no-module --reply-log"; string(got) != want {
		t.Fatalf("the decider's arguments: got %q, want %q", got, want)
	}
}

// G18: no address binds -> exit 1, and the decider is never started.
func TestGatewayExitsWhenNoListenAddressBinds(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	gw := startGatewayProcess(t, []string{"--listen", "192.0.2.1", "--listen", "192.0.2.2", "--port", "0"}, decider("serve"))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	for _, want := range []string{"cannot listen on 192.0.2.1:0:", "cannot listen on 192.0.2.2:0:", "no address could be bound"} {
		if !strings.Contains(gw.logText(), want) {
			t.Fatalf("log lacks %q:\n%s", want, gw.logText())
		}
	}
	if _, err := os.Stat(pidfile); err == nil {
		t.Fatal("the decider was started although nothing could be bound")
	}
}

// G8 (process level): a malformed frame from the decider ends the gateway with a non-zero status and a clear line.
func TestGatewayExitsNonZeroOnAProtocolErrorFromTheDecider(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0"}, decider("bad-frame"))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	if !strings.Contains(gw.logText(), "decision protocol error:") {
		t.Fatalf("log lacks the protocol error line:\n%s", gw.logText())
	}
}

// G22: a decider that exits without ever sending READY means the gateway never serves.
func TestGatewayExitsWithoutServingWhenTheDeciderNeverBecomesReady(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0"}, decider("no-ready-exit"))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	if text := gw.logText(); strings.Contains(text, "listening") || strings.Contains(text, "ready upstream") {
		t.Fatalf("the gateway reported readiness without a READY:\n%s", text)
	}
}

// G20: SIGTERM stops accepting, ends the decider and exits 0; the child is gone before the gateway is.
func TestGatewaySIGTERMExitsZeroAfterTheDeciderIsGone(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	t.Setenv("PFB_FAKE_EXIT_DELAY", "300ms") // a gateway that does not wait for its child leaves it alive here
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0"}, decider("serve"))
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream")
	pid := readPid(t, pidfile)
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the decider (pid %d) should be running while the gateway serves: %v", pid, err)
	}
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGTERM, want 0; log:\n%s", code, gw.logText())
	}
	requireGone(t, pid)
	if c, err := net.DialTimeout("tcp", serving.String(), watchdog); err == nil {
		_ = c.Close()
		t.Fatalf("%s still accepts connections after the gateway exited", serving)
	}
}

// G19: the privilege drop really drops (root only: a process cannot change user otherwise).
func TestPrivilegeDropBecomesTheUserAndCannotComeBack(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("G19 real setuid: needs root to switch user (the ordering test below runs without it)")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("G19 real setuid: no user `nobody` to drop to")
	}
	out, err := exec.Command(os.Args[0], "--as-dropper", "nobody").CombinedOutput()
	if err != nil {
		t.Fatalf("dropper: %v\n%s", err, out)
	}
	want := fmt.Sprintf("uid=%[1]s gid=%[2]s euid=%[1]s egid=%[2]s groups=[%[2]s] regain-root=denied\n", nobody.Uid, nobody.Gid)
	if string(out) != want {
		t.Fatalf("after the drop:\n got  %q\n want %q", out, want)
	}
}

func TestUnknownUserExitsOneBeforeAnythingIsServed(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0", "--user", "pfb-no-such-user-3513"}, decider("serve"))
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	if text := gw.logText(); !strings.Contains(text, `unknown user "pfb-no-such-user-3513"`) || strings.Contains(text, "listening") {
		t.Fatalf("want the unknown-user reason and no readiness line, got:\n%s", text)
	}
}

func TestUsageErrorExitsTwo(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--port", "53"}, nil) // no decider argv after `--`
	if code := gw.exit(); code != 2 {
		t.Fatalf("exit code %d, want 2; log:\n%s", code, gw.logText())
	}
}

// SIGTERM while the decider is still booting abandons the wait for READY instead of sitting out its cap; the
// decider leaves with the socket and nothing was ever reported as ready.
func TestSIGTERMWhileTheDeciderIsStillBootingExitsZero(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0"}, decider("no-ready-hang"))
	waitForPid(t, pidfile) // the decider exists, so the gateway is waiting for its READY
	pid := readPid(t, pidfile)
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGTERM during startup, want 0; log:\n%s", code, gw.logText())
	}
	requireGone(t, pid)
	if text := gw.logText(); strings.Contains(text, "listening") || strings.Contains(text, "ready upstream") {
		t.Fatalf("readiness reported without a READY:\n%s", text)
	}
}

// in-process lifecycle -------------------------------------------------------------------------------

type capture struct {
	mu    sync.Mutex
	lines []string
}

func (c *capture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *capture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

func lifecycleConfig(t *testing.T, mode string) (config, *capture) {
	t.Helper()
	return config{
		listen: []string{"127.0.0.1"}, port: 0, upstream: "127.0.0.1:5353", timeout: watchdog,
		unboundConf: filepath.Join(t.TempDir(), "absent"), decider: decider(mode),
	}, &capture{}
}

// G19 (ordering): bind, then start the decider, then drop privileges, then wait for READY.
func TestStartupOrderIsBindThenDeciderThenDropThenReady(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	var steps []string
	var mu sync.Mutex
	record := func(s string) { mu.Lock(); steps = append(steps, s); mu.Unlock() }
	cfg.trace = record
	cfg.drop = func() error { record("drop"); return nil }
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(steps, ","); got != "bind,decider,drop,ready" {
		t.Fatalf("startup order: got %s, want bind,decider,drop,ready", got)
	}
}

func TestStartupReportsEachListenerThenTheUpstreamOnlyAfterReady(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.upstream = "127.0.0.1:5454"
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	lines := strings.Split(logs.text(), "\n")
	var port int
	for _, l := range lines {
		if strings.HasPrefix(l, "listening udp+tcp ") {
			port = int(listenAddr(t, l).Port())
		}
	}
	want := []string{"listening udp+tcp 127.0.0.1:" + strconv.Itoa(port), "ready upstream 127.0.0.1:5454"}
	if port == 0 || fmt.Sprint(lines[len(lines)-2:]) != fmt.Sprint(want) {
		t.Fatalf("log lines:\n got  %q\n want the tail %q", lines, want)
	}
}

func TestFailedDropStopsEverythingAndFreesThePort(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "serve")
	cfg.port = freePort(t)
	cfg.drop = func() error { waitForPid(t, pidfile); return errors.New("setuid refused") }
	srv, err := start(cfg, logs.logf)
	if err == nil || !strings.Contains(err.Error(), "setuid refused") {
		t.Fatalf("start: got srv=%v err=%v, want the drop error", srv, err)
	}
	requireGone(t, readPid(t, pidfile))
	l, err := bindPlain("127.0.0.1", cfg.port)
	if err != nil {
		t.Fatalf("the port is still held after a failed start: %v", err)
	}
	l.close()
}

func TestStartupGivesUpWhenTheDeciderSendsNoReadyInTime(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "no-ready-hang")
	cfg.drop = func() error { waitForPid(t, pidfile); return nil }
	cfg.readyTimeout = 100 * time.Millisecond
	srv, err := start(cfg, logs.logf)
	if err == nil || !strings.Contains(err.Error(), "READY") {
		t.Fatalf("start: got srv=%v err=%v, want a no-READY error", srv, err)
	}
	requireGone(t, readPid(t, pidfile))
	if strings.Contains(logs.text(), "listening") {
		t.Fatalf("no readiness line without READY:\n%s", logs.text())
	}
}

// G21: the decider dying while the gateway serves is fatal for the gateway.
func TestDeciderKilledWhileServingIsFatal(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "serve")
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	select {
	case err := <-srv.fatal():
		t.Fatalf("fatal before anything went wrong: %v", err)
	default:
	}
	if err := syscall.Kill(readPid(t, pidfile), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-srv.fatal():
		if err == nil || !strings.Contains(err.Error(), "decider") {
			t.Fatalf("fatal error: got %v, want one naming the decider", err)
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK: no fatal error after the decider was killed")
	}
}

func TestShutdownKillsADeciderThatIgnoresEOF(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	cfg, logs := lifecycleConfig(t, "ignore-eof")
	cfg.killAfter = 100 * time.Millisecond
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	srv.shutdown()
	requireGone(t, readPid(t, pidfile))
	if !strings.Contains(logs.text(), "killing") {
		t.Fatalf("the kill must be logged:\n%s", logs.text())
	}
	select {
	case err := <-srv.fatal():
		t.Fatalf("a requested shutdown is not fatal, got %v", err)
	default:
	}
}
