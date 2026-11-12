package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

// The test binary doubles as the gateway and the privilege-drop probe: the process-level tests start it with a role as its
// first argument instead of building anything.
func TestMain(m *testing.M) {
	ctlUID = uint32(os.Getuid()) // the control socket takes pushes from the user running the tests, root or not
	if len(os.Args) > 2 {
		switch os.Args[1] {
		case "--as-gateway":
			os.Exit(run(os.Args[2:], os.Stderr, fakeDecider()))
		case "--as-dropper":
			os.Exit(dropAndReport(os.Args[2]))
		case "--as-ctl-client":
			os.Exit(pushAsUser(os.Args[2], os.Args[3], os.Args[4]))
		}
	}
	os.Exit(m.Run())
}

// echoFrontend is the decider of a test that is not about decisions: every query is answered with itself, QR set.
type echoFrontend struct{}

func (echoFrontend) Resolve(wire []byte, _ string, _ func([]byte) []byte, _, _, _ string) []byte {
	return echoWithQR(seenQuery{wire: wire})[0]
}

func (echoFrontend) Close() {}

// fakeDecider is the decider boot of the gateway role, by what PFB_FAKE_FRONTEND names; unset, it is nil and the gateway
// boots the real one.
//
//	echo        echoFrontend. PFB_FAKE_EVENTS names an append-only file the boot writes what it saw to, in order: "before-ready
//	            ready-file=absent|present" is the state of the file PFB_FAKE_WATCH names, taken as the decider boots
//	block-open  the boot never ends
func fakeDecider() func(decider.Options) (frontend, error) {
	switch os.Getenv("PFB_FAKE_FRONTEND") {
	case "echo":
		return func(decider.Options) (frontend, error) {
			if watch := os.Getenv("PFB_FAKE_WATCH"); watch != "" {
				state := "absent"
				if _, err := os.Lstat(watch); err == nil {
					state = "present"
				}
				fakeEvent("before-ready ready-file=%s", state)
			}
			return echoFrontend{}, nil
		}
	case "block-open":
		return func(decider.Options) (frontend, error) { select {} }
	}
	return nil
}

// fakeEvent appends one line to the file PFB_FAKE_EVENTS names (nothing when it is unset).
func fakeEvent(format string, args ...any) {
	path := os.Getenv("PFB_FAKE_EVENTS")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake frontend: events:", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

// readEvents is the lines of an events file, in the order the processes wrote them.
func readEvents(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
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

// startGatewayProcess runs the gateway with echoFrontend as its decider; its control socket is a private one unless flags
// name it, so a test never touches the system's.
func startGatewayProcess(t *testing.T, flags []string) *gatewayProcess {
	t.Helper()
	return startGatewayProcessWith(t, flags, "PFB_FAKE_FRONTEND=echo")
}

// startGatewayProcessWith is startGatewayProcess with the environment given: without PFB_FAKE_FRONTEND the gateway boots the
// real decider.
func startGatewayProcessWith(t *testing.T, flags []string, env ...string) *gatewayProcess {
	t.Helper()
	if !slices.Contains(flags, "--ctl-socket") {
		flags = append(slices.Clone(flags), "--ctl-socket", filepath.Join(shortTempDir(t), "run", "ctl.sock"))
	}
	cmd := exec.Command(os.Args[0], append([]string{"--as-gateway"}, flags...)...)
	cmd.Env = append(os.Environ(), env...)
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
			p.t.Fatalf("STUCK/ENVIRONMENT: no %q line within the watchdog; log:\n%s", prefix, p.logText())
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
		p.t.Fatalf("STUCK/ENVIRONMENT: the gateway is still running; log:\n%s", p.logText())
		return -1
	}
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
	gw := startGatewayProcess(t, []string{"--listen", "192.0.2.1", "--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf"})
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

// issue #3513: the pfB-DNS mode flags the gateway was given are what the decider boots with.
func TestStartBootsTheDeciderWithTheModeFlagsItWasGiven(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	var got decider.Options
	cfg.open = func(opts decider.Options) (frontend, error) { got = opts; return echoFrontend{}, nil }
	cfg.moduleDir, cfg.logDir, cfg.noModule, cfg.replyLog = "/some/module/dir", "/some/log/dir", true, true
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if want := (decider.Options{ModuleDir: "/some/module/dir", LogDir: "/some/log/dir", NoModule: true, ReplyLog: true}); got != want {
		t.Fatalf("the decider was booted with %+v, want %+v", got, want)
	}
}

// G18: no address binds -> exit 1, and the decider is never booted.
func TestGatewayExitsWhenNoListenAddressBinds(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "192.0.2.1", "--listen", "192.0.2.2", "--port", "0"})
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	for _, want := range []string{"cannot listen on 192.0.2.1:0:", "cannot listen on 192.0.2.2:0:", "no address could be bound"} {
		if !strings.Contains(gw.logText(), want) {
			t.Fatalf("log lacks %q:\n%s", want, gw.logText())
		}
	}
	cfg, logs := lifecycleConfig(t)
	var booted int
	cfg.open = func(decider.Options) (frontend, error) { booted++; return echoFrontend{}, nil }
	cfg.listen = []string{"192.0.2.1"}
	if srv, err := start(cfg, logs.logf); err == nil {
		srv.shutdown()
		t.Fatal("start served although nothing could be bound")
	}
	if booted != 0 {
		t.Fatalf("the decider was booted %d times although nothing could be bound", booted)
	}
}

// G20: SIGTERM stops accepting and exits 0.
func TestGatewaySIGTERMExitsZeroAndStopsServing(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0"})
	serving := listenAddr(t, gw.waitLine("listening udp+tcp "))
	gw.waitLine("ready upstream")
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := gw.exit(); code != 0 {
		t.Fatalf("exit code %d after SIGTERM, want 0; log:\n%s", code, gw.logText())
	}
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
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0", "--user", "pfb-no-such-user-3513"})
	if code := gw.exit(); code != 1 {
		t.Fatalf("exit code %d, want 1; log:\n%s", code, gw.logText())
	}
	if text := gw.logText(); !strings.Contains(text, `unknown user "pfb-no-such-user-3513"`) || strings.Contains(text, "listening") {
		t.Fatalf("want the unknown-user reason and no readiness line, got:\n%s", text)
	}
}

func TestUsageErrorExitsTwo(t *testing.T) {
	gw := startGatewayProcess(t, []string{"--port", "53"}) // no --listen
	if code := gw.exit(); code != 2 {
		t.Fatalf("exit code %d, want 2; log:\n%s", code, gw.logText())
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

// closingFrontend is a decider that says when it is Closed.
type closingFrontend struct {
	echoFrontend
	closed chan struct{}
}

func (c closingFrontend) Close() { close(c.closed) }

func lifecycleConfig(t *testing.T) (config, *capture) {
	t.Helper()
	return config{
		listen: []string{"127.0.0.1"}, port: 0, upstream: "127.0.0.1:5353", timeout: watchdog,
		unboundConf: filepath.Join(t.TempDir(), "absent"),
		open:        func(decider.Options) (frontend, error) { return echoFrontend{}, nil },
	}, &capture{}
}

// G19 (ordering): bind, then drop privileges, then boot the decider in this process.
func TestStartupOrderIsBindThenDropThenReady(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	var steps []string
	var mu sync.Mutex
	record := func(s string) { mu.Lock(); steps = append(steps, s); mu.Unlock() }
	cfg.trace = record
	cfg.drop = func() error { record("drop"); return nil }
	cfg.open = func(decider.Options) (frontend, error) { record("open"); return echoFrontend{}, nil }
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(steps, ","); got != "bind,drop,open,ready" {
		t.Fatalf("startup order: got %s, want bind,drop,open,ready", got)
	}
}

func TestStartupReportsEachListenerThenTheUpstreamOnlyAfterReady(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
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
	want := []string{"listening udp+tcp 127.0.0.1:" + strconv.Itoa(port), "ready upstream 127.0.0.1:5454 pid " + strconv.Itoa(os.Getpid())}
	if port == 0 || fmt.Sprint(lines[len(lines)-2:]) != fmt.Sprint(want) {
		t.Fatalf("log lines:\n got  %q\n want the tail %q", lines, want)
	}
}

func TestFailedDropStopsEverythingAndFreesThePort(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	var booted int
	cfg.open = func(decider.Options) (frontend, error) { booted++; return echoFrontend{}, nil }
	cfg.port = freePort(t)
	cfg.drop = func() error { return errors.New("setuid refused") }
	srv, err := start(cfg, logs.logf)
	if err == nil || !strings.Contains(err.Error(), "setuid refused") {
		t.Fatalf("start: got srv=%v err=%v, want the drop error", srv, err)
	}
	if booted != 0 {
		t.Fatalf("the decider was booted %d times after the privilege drop failed, want never", booted)
	}
	l, err := bindPlain("127.0.0.1", cfg.port)
	if err != nil {
		t.Fatalf("the port is still held after a failed start: %v", err)
	}
	l.close()
}

// A decider that cannot boot, with the module or without it (the fake ignores which), is the start's error, and nothing stays bound.
func TestADeciderThatCannotBootFailsTheStartAndFreesThePort(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	cfg.open = func(decider.Options) (frontend, error) { return nil, errors.New("no pfb_unbound.ini") }
	cfg.port = freePort(t)
	srv, err := start(cfg, logs.logf)
	if err == nil || err.Error() != "decider: no pfb_unbound.ini" {
		t.Fatalf("start: got srv=%v err=%v, want the boot error", srv, err)
	}
	l, err := bindPlain("127.0.0.1", cfg.port)
	if err != nil {
		t.Fatalf("the port is still held after a failed start: %v", err)
	}
	l.close()
	if strings.Contains(logs.text(), "listening") {
		t.Fatalf("no readiness line without a decider:\n%s", logs.text())
	}
}

// A signal during the boot ends the wait (errInterrupted); the decider that finishes afterwards is Closed.
func TestAnInterruptWhileTheDeciderBootsEndsTheStart(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	release, late := make(chan struct{}), closingFrontend{closed: make(chan struct{})}
	cfg.open = func(decider.Options) (frontend, error) { <-release; return late, nil }
	interrupt := make(chan struct{})
	close(interrupt)
	cfg.interrupt = interrupt
	srv, err := start(cfg, logs.logf)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("start: got srv=%v err=%v, want errInterrupted", srv, err)
	}
	close(release)
	waitClosed(t, late.closed, "the late decider to be closed")
}

// Shutdown closes the decider after the queries in flight are done with it: Close stops what a query writes to.
func TestShutdownClosesTheDeciderOnlyAfterTheQueriesInFlightAreDrained(t *testing.T) {
	cfg, logs := lifecycleConfig(t)
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) // an Unbound that never answers holds the query's forward
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	cfg.upstream = silent.LocalAddr().String()
	fe := &drainFrontend{inflight: make(chan struct{}), closedWithQuery: make(chan bool, 1)}
	cfg.open = func(decider.Options) (frontend, error) { return fe, nil }
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	port := int(listenAddr(t, firstLine(logs.text(), "listening udp+tcp ")).Port())
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(buildQuery(t, 1, "held.example.", true)); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, fe.inflight, "the query to reach the decider")
	srv.shutdown()
	select {
	case withQuery := <-fe.closedWithQuery:
		if withQuery {
			t.Fatal("the decider was closed while a query still ran in it")
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: the decider was never closed")
	}
}

func firstLine(text, prefix string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

// drainFrontend holds a query until the gateway cancels it (its forward gives up), and records whether one was still running
// when it was closed.
type drainFrontend struct {
	inflight        chan struct{}
	running         atomic.Int32
	once            sync.Once
	closedWithQuery chan bool
}

func (f *drainFrontend) Resolve(wire []byte, _ string, fwd func([]byte) []byte, _, _, _ string) []byte {
	f.running.Add(1)
	defer f.running.Add(-1)
	f.once.Do(func() { close(f.inflight) })
	fwd(wire) // returns once the stopping gateway cancels the query
	return nil
}

func (f *drainFrontend) Close() { f.closedWithQuery <- f.running.Load() != 0 }
