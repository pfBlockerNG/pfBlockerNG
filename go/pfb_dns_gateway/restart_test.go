package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// issue #3566: root restarts the decider alone through the control socket: the 4 bytes FF FF FF FF on a connection of their
// own. The new decider is started with the first one's argv; once it is READY it takes every new query, the old one finishes
// what it holds and leaves on EOF. A new decider that never gets READY is killed and the old one goes on. The control socket
// exists in every mode, TLS or not.

var ctlRestartFrame = []byte{0xff, 0xff, 0xff, 0xff}

// send writes one frame on a connection of its own and returns the reply.
func (k *ctlRig) send(t *testing.T, frame []byte) string {
	t.Helper()
	c := dialCtl(t, k.path)
	_, _ = c.Write(frame) // a server that refuses the peer has closed already: the reply is what tells
	return ctlReply(t, c)
}

// withRestart makes the control socket's restart count its calls and return err.
func withRestart(calls *atomic.Int32, err error) func(*ctlServer) {
	return func(c *ctlServer) { c.restart = func() error { calls.Add(1); return err } }
}

func TestTheRestartFrameRestartsTheDeciderAndACertificatePushDoesNot(t *testing.T) {
	var calls atomic.Int32
	k := newCtlRig(t, withRestart(&calls, nil))
	if got := k.send(t, ctlRestartFrame); got != "ok" {
		t.Fatalf("restart frame: reply %q, want ok", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("restart frame: the restart ran %d times, want 1", n)
	}
	k.requireEmpty(t, "after a restart frame")

	leaf := k.leaf(t)
	if got := k.push(t, chainPEM(t, leaf)); got != "ok" {
		t.Fatalf("certificate push: reply %q, want ok", got)
	}
	k.requireServing(t, leaf, "after a push that followed a restart")
	if got := k.send(t, ctlFrame([]byte("x"))); !strings.HasPrefix(got, "error: ") || strings.Contains(got, "not between") {
		t.Fatalf("a 1-byte push: reply %q, want the certificate store's error, not the length's", got)
	}
	for name, n := range map[string]uint32{"zero": 0, "one over the limit": ctlMaxPEM + 1} {
		if got := k.send(t, binary.BigEndian.AppendUint32(nil, n)); got != "error: a message of "+strconv.Itoa(int(n))+" bytes is not between 1 and 65536" {
			t.Fatalf("%s: reply %q, want the length error", name, got)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("pushes and refused lengths ran the restart: %d calls, want still 1", n)
	}
}

func TestARestartThatFailsIsAnsweredWithItsReason(t *testing.T) {
	var calls atomic.Int32
	k := newCtlRig(t, withRestart(&calls, errors.New("the new decider sent no READY")))
	if got, want := k.send(t, ctlRestartFrame), "error: the new decider sent no READY"; got != want {
		t.Fatalf("reply %q, want %q", got, want)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the restart ran %d times, want 1", n)
	}
}

func TestAPeerThatIsNotRootCanNeitherRestartNorPush(t *testing.T) {
	var calls atomic.Int32
	k := newCtlRig(t, withRestart(&calls, nil))
	k.peer.Store(ctlUID + 1001)
	if got := k.send(t, ctlRestartFrame); got != "" {
		t.Fatalf("restart from a peer that is not root: reply %q, want none", got)
	}
	if got := k.push(t, chainPEM(t, k.leaf(t))); got != "" {
		t.Fatalf("push from a peer that is not root: reply %q, want none", got)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("a peer that is not root ran the restart %d times", n)
	}
	k.requireEmpty(t, "after a push from a peer that is not root")
}

// The control socket is there without TLS (a decider restart needs it in every mode); a certificate pushed to a gateway
// with no TLS transport has nowhere to go and is answered with an error.
func TestTheControlSocketIsBoundWithoutATLSTransportAndRefusesACertificate(t *testing.T) {
	cfg, logs, sock := ctlConfig(t)
	cfg.dotListen = nil
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if info, err := os.Lstat(sock); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("control socket of a gateway with no TLS: %v (err %v), want a socket", info, err)
	}
	pem, err := os.ReadFile(cfg.tlsPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := dialCtl(t, sock)
	_, _ = c.Write(ctlFrame(pem))
	if got := ctlReply(t, c); !strings.HasPrefix(got, "error: ") {
		t.Fatalf("certificate pushed to a gateway with no TLS: reply %q, want an error", got)
	}
}

// startRestartRig is an in-process gateway with no TLS, a control socket of its own and a fake decider in mode.
func startRestartRig(t *testing.T, mode string, tweak func(*config)) (*server, string) {
	t.Helper()
	cfg, logs := lifecycleConfig(t, mode)
	cfg.ctlSocket = filepath.Join(shortTempDir(t), "run", "ctl.sock")
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.shutdown)
	return srv, cfg.ctlSocket
}

func requestRestart(t *testing.T, sock string) string {
	t.Helper()
	c := dialCtl(t, sock)
	_, _ = c.Write(ctlRestartFrame)
	return ctlReply(t, c)
}

func emptyReply(context.Context, []byte) []byte { return nil }

// resolveVia asks the gateway's decider as a query from 127.0.0.1 does; a stuck decider is SERVFAIL after the watchdog.
func resolveVia(srv *server, wire []byte, fwd forwarder) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	return srv.g.resolve(ctx, netip.MustParseAddr("127.0.0.1"), false, wire, fwd)
}

// taggedPid is the pid a forward-tagged decider put after the echoed query.
func taggedPid(t *testing.T, wire, answer []byte) int {
	t.Helper()
	tag, ok := bytes.CutPrefix(answer[min(len(wire), len(answer)):], []byte("pid="))
	pid, err := strconv.Atoi(string(tag))
	if !ok || err != nil {
		t.Fatalf("answer %q is not the query echoed and tagged with a decider's pid", answer)
	}
	return pid
}

func askPid(t *testing.T, srv *server, name string) int {
	t.Helper()
	wire := buildQuery(t, 0x3566, name, true)
	return taggedPid(t, wire, resolveVia(srv, wire, emptyReply))
}

var pidInReply = regexp.MustCompile(`\(pid (\d+)\)`)

// failedPid is the pid of the new decider a failed restart names.
func failedPid(t *testing.T, reply string) int {
	t.Helper()
	m := pidInReply.FindStringSubmatch(reply)
	if m == nil {
		t.Fatalf("reply %q names no pid of the new decider", reply)
	}
	pid, _ := strconv.Atoi(m[1])
	return pid
}

func requireNoFatal(t *testing.T, srv *server, when string) {
	t.Helper()
	select {
	case err := <-srv.fatal():
		t.Fatalf("%s: the gateway failed: %v", when, err)
	default:
	}
}

func requireExited(t *testing.T, c *child, what string) {
	t.Helper()
	select {
	case <-c.exited:
	case <-time.After(watchdog):
		t.Fatalf("STUCK/ENVIRONMENT: %s (pid %d) did not exit within the watchdog", what, c.cmd.Process.Pid)
	}
}

// After `ok` every new query goes to the new decider; a query the old one already holds is answered by it, then it reads
// EOF and leaves by itself, and its leaving is not the gateway's end.
func TestARestartedDeciderTakesNewQueriesWhileTheOldOneFinishesWhatItHolds(t *testing.T) {
	srv, sock := startRestartRig(t, "forward-tagged", nil)
	_, old := srv.active()
	oldPid := old.cmd.Process.Pid

	held := buildQuery(t, 0x0101, "held.example.", true)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)
	heldAnswer := make(chan []byte, 1)
	go func() {
		heldAnswer <- resolveVia(srv, held, func(ctx context.Context, _ []byte) []byte {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: the held query never reached the old decider's FORWARD")
	}

	if got := requestRestart(t, sock); got != "ok" {
		t.Fatalf("restart: reply %q, want ok", got)
	}
	_, cur := srv.active()
	if cur == old {
		t.Fatal("after ok the old decider is still the active one")
	}
	if pid := askPid(t, srv, "after.example."); pid != cur.cmd.Process.Pid || pid == oldPid {
		t.Fatalf("a query after the restart was decided by pid %d, want the new decider %d (old %d)", pid, cur.cmd.Process.Pid, oldPid)
	}
	releaseOnce()
	if pid := taggedPid(t, held, <-heldAnswer); pid != oldPid {
		t.Fatalf("the query held across the restart was decided by pid %d, want the old decider %d", pid, oldPid)
	}
	requireExited(t, old, "the retired decider")
	if old.err != nil {
		t.Fatalf("the retired decider must leave on EOF, not be killed: %v", old.err)
	}
	if pid := askPid(t, srv, "later.example."); pid != cur.cmd.Process.Pid {
		t.Fatalf("after the old decider left, a query was decided by pid %d, want %d", pid, cur.cmd.Process.Pid)
	}
	requireNoFatal(t, srv, "after the retired decider left")
}

// requireStillActive: the old decider is the active one and answers, and the gateway did not fail.
func requireStillActive(t *testing.T, srv *server, old *child) {
	t.Helper()
	if _, cur := srv.active(); cur != old {
		t.Fatal("a failed restart replaced the active decider")
	}
	if pid := askPid(t, srv, "still.example."); pid != old.cmd.Process.Pid {
		t.Fatalf("after a failed restart a query was decided by pid %d, want the old decider %d", pid, old.cmd.Process.Pid)
	}
	requireNoFatal(t, srv, "after a failed restart")
}

func modeFile(t *testing.T, mode string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mode")
	writeMode(t, path, mode)
	t.Setenv("PFB_FAKE_MODEFILE", path)
	return path
}

func writeMode(t *testing.T, path, mode string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(mode), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestARestartWhoseDeciderSendsNoReadyInTimeKillsItAndKeepsTheOldOne(t *testing.T) {
	modes := modeFile(t, "forward-tagged")
	srv, sock := startRestartRig(t, "from-file", func(c *config) { c.restartTimeout = 300 * time.Millisecond })
	_, old := srv.active()
	writeMode(t, modes, "no-ready-hang")
	got := requestRestart(t, sock)
	if !strings.HasPrefix(got, "error: ") || !strings.Contains(got, "no READY within 300ms") {
		t.Fatalf("restart: reply %q, want the error for no READY within the bound", got)
	}
	requireGone(t, failedPid(t, got))
	requireStillActive(t, srv, old)
}

// A new decider that ends its session or exits before READY is given up at once, not at the bound.
func TestARestartWhoseDeciderFailsBeforeReadyIsGivenUpAtOnce(t *testing.T) {
	for _, mode := range []string{"no-ready-exit", "bad-frame-before-ready"} {
		t.Run(mode, func(t *testing.T) {
			modes := modeFile(t, "forward-tagged")
			srv, sock := startRestartRig(t, "from-file", func(c *config) { c.restartTimeout = time.Hour }) // a reply within the watchdog is a reply before the bound
			_, old := srv.active()
			writeMode(t, modes, mode)
			got := requestRestart(t, sock)
			if !strings.HasPrefix(got, "error: ") || !strings.Contains(got, "before READY") {
				t.Fatalf("restart: reply %q, want an error naming the failure before READY", got)
			}
			requireGone(t, failedPid(t, got))
			requireStillActive(t, srv, old)
		})
	}
}

// Once it is active, the new decider is what the gateway lives by: its end is the gateway's.
func TestTheRestartedDeciderDyingIsFatal(t *testing.T) {
	srv, sock := startRestartRig(t, "serve", nil)
	_, old := srv.active()
	if got := requestRestart(t, sock); got != "ok" {
		t.Fatalf("restart: reply %q, want ok", got)
	}
	requireExited(t, old, "the retired decider")
	requireNoFatal(t, srv, "after the retired decider left")
	_, cur := srv.active()
	if cur == old {
		t.Fatal("after ok the old decider is still the active one")
	}
	if err := syscall.Kill(cur.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-srv.fatal():
		if err == nil || !strings.Contains(err.Error(), "decider") {
			t.Fatalf("fatal error %v, want one naming the decider", err)
		}
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: no fatal error after the active (restarted) decider was killed")
	}
}

// A shutdown while the old decider still holds a query does not wait for it: once the shutdown returns, both deciders
// are closed and reaped.
func TestAShutdownDuringTheDrainReapsBothDeciders(t *testing.T) {
	srv, sock := startRestartRig(t, "forward-tagged", nil)
	_, old := srv.active()
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(sync.OnceFunc(func() { close(release) }))
	go resolveVia(srv, buildQuery(t, 0x0202, "held.example.", true), func(ctx context.Context, _ []byte) []byte {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	select {
	case <-entered:
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: the held query never reached the old decider's FORWARD")
	}
	if got := requestRestart(t, sock); got != "ok" {
		t.Fatalf("restart: reply %q, want ok", got)
	}
	_, cur := srv.active()
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	waitClosed(t, done, "the shutdown during the drain to return")
	for what, c := range map[string]*child{"the retiring decider": old, "the active decider": cur} {
		select {
		case <-c.exited:
		default:
			t.Fatalf("%s (pid %d) is still running when shutdown returned", what, c.cmd.Process.Pid)
		}
	}
	requireNoFatal(t, srv, "after a requested shutdown")
}
