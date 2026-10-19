package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// realUID is the real uid of a process, from /proc.
func realUID(t *testing.T, pid int) string {
	t.Helper()
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "Uid:" {
			return f[1]
		}
	}
	t.Fatalf("no Uid line in /proc/%d/status", pid)
	return ""
}

// F1: after the privilege drop the gateway cannot signal a decider that is still root (EPERM). SIGTERM before READY
// must still end the gateway within the bound, not sit out the decider's boot (up to 300 s, so `daemon -r` never
// restarts it). Root only, like G19: a process cannot change user otherwise.
func TestSIGTERMBeforeREADYExitsWhenTheDropMadeTheDeciderUnkillable(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("F1 real setuid: needs root to switch user")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("F1 real setuid: no user `nobody` to drop to")
	}
	pidfile := filepath.Join(t.TempDir(), "decider.pid")
	t.Setenv("PFB_FAKE_PIDFILE", pidfile)
	gw := startGatewayProcess(t, []string{"--listen", "127.0.0.1", "--port", "0", "--user", "nobody"}, decider("boot-ignores-eof"))
	waitForPid(t, pidfile)
	pid := readPid(t, pidfile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) }) // the decider is root: only this test can end it
	eventually(t, "the gateway to have dropped to nobody", func() bool { return realUID(t, gw.cmd.Process.Pid) == nobody.Uid })
	if err := gw.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The decider keeps the gateway's stderr pipe open, so the exit is read from the process, not from the pipe.
	gw.waitLine("pfb_dns_gateway: stopped by signal before the decider was ready")
	eventually(t, "the gateway process to be gone", func() bool {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(gw.cmd.Process.Pid) + "/stat")
		return err != nil || strings.Contains(string(stat), ") Z ") // a zombie has exited; the test reaps it later
	})
}

// F2: shutdown closes the decision socket first. A decider that reads nothing leaves the socket full and queries
// blocked in their write (up to the 10 s write deadline); stop() waits for those, so closing after it overruns the
// rc stop loop's 5 s KILL.
func TestShutdownDoesNotWaitForQueriesBlockedWritingToAWedgedDecider(t *testing.T) {
	cfg, logs := lifecycleConfig(t, "ignore-eof")
	cfg.killAfter = 100 * time.Millisecond
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.dec.Close)    // frees a shutdown that is stuck, so a failure does not leak it
	srv.g.stopBound = time.Hour // stop() gives up on a handler after 2 x this: at the default a shutdown that waits for the blocked query still ends in about a second and the test could not tell
	var serving string
	for _, l := range strings.Split(logs.text(), "\n") {
		if strings.HasPrefix(l, "listening udp+tcp ") {
			serving = strings.TrimPrefix(l, "listening udp+tcp ")
		}
	}
	d := srv.dec
	d.writeTimeout = time.Hour // a write that cannot complete would hold the shutdown this long
	d.wmu.Lock()
	fillSocket(t, d.conn)
	d.wmu.Unlock()
	c, err := net.Dial("udp", serving)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(buildQuery(t, 1, "blocked.example.", true)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the query to be in flight, its QUERY blocked in the full socket", func() bool { return srv.g.udpInflight.Load() == 1 })
	done := make(chan struct{})
	go func() { srv.shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(watchdog):
		t.Fatal("STUCK/ENVIRONMENT: shutdown waits for a query blocked writing to a decider that reads nothing")
	}
}

// F4: the SafeSearch chase is a second FORWARD; two silent Unbound exchanges of one timeout each must still fit the
// whole-query limit of 2 x timeout + grace. (grace < timeout, so a limit of timeout + grace would cut it short.) The limit
// is the deadline of the context each forward runs under, which the test reads instead of waiting out two timeouts: the
// query was started somewhere between `started` and the moment its forward ran, so the limit lies between the two
// distances, however slow the machine. The timeouts are hours, so a limit that is wrong by a whole timeout cannot hide in
// that gap, and nothing here waits for them: a silent exchange is a forwarder that returns nil at once.
func TestChaseOfTwoSilentForwardsStillGetsItsAnswer(t *testing.T) {
	const timeout, grace = 6 * time.Hour, 4 * time.Hour
	client := netip.MustParseAddr(clientAllowed)
	for _, c := range []struct {
		name string
		ask  func(g *gateway, wire []byte, fwd forwarder) []byte
	}{
		{"udp", func(g *gateway, wire []byte, fwd forwarder) []byte {
			return g.resolve(context.Background(), client, true, wire, fwd)
		}},
		{"tcp", func(g *gateway, wire []byte, fwd forwarder) []byte {
			return g.resolve(context.Background(), client, false, wire, fwd)
		}},
		{"doh and doq", func(g *gateway, wire []byte, fwd forwarder) []byte {
			reply, _ := g.resolveShared(context.Background(), client, wire, fwd)
			return reply
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, timeout: timeout, grace: grace})
			type forward struct {
				deadline, ran time.Time
				hasDeadline   bool
			}
			var forwards []forward // appended by the asking goroutine, read once it has answered
			fwd := func(ctx context.Context, wire []byte) []byte {
				deadline, ok := ctx.Deadline()
				forwards = append(forwards, forward{deadline, time.Now(), ok})
				return nil // Unbound said nothing for a whole timeout
			}
			wire := buildQuery(t, 0x5151, "duck.example.", true)
			started := time.Now()
			done := make(chan []byte, 1)
			go func() { done <- c.ask(r.g, wire, fwd) }()
			q := r.recvQuery()
			for range 2 {
				r.p.send(tForward, q.id, q.wire)
				r.p.expect(tReply, q.id, nil)
			}
			r.p.send(tAnswer, q.id, []byte("chased answer"))
			if got := awaitBytes(t, done); string(got) != "chased answer" {
				t.Fatalf("client reply %x, want the decider's answer: the query was cut off before the chase finished", got)
			}
			want := 2*timeout + grace
			if len(forwards) != 2 {
				t.Fatalf("%d forwards ran, want 2", len(forwards))
			}
			for i, f := range forwards {
				if !f.hasDeadline {
					t.Fatalf("forward %d ran under a context with no deadline, want a whole-query limit of %v", i, want)
				}
				if lo, hi := f.deadline.Sub(f.ran), f.deadline.Sub(started); want < lo || want > hi {
					t.Fatalf("forward %d: the whole-query limit is between %v and %v, want 2 x timeout + grace = %v", i, lo, hi, want)
				}
			}
		})
	}
}

// fillSocket writes to c until the kernel refuses more (EAGAIN): the socket is full because the kernel says so, not because
// a write was slow.
func fillSocket(t *testing.T, c net.Conn) {
	t.Helper()
	raw, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var werr error
	chunk := make([]byte, 64*1024)
	if err := raw.Control(func(fd uintptr) { // the runtime made the descriptor non-blocking: a full socket answers EAGAIN
		for {
			if _, werr = syscall.Write(int(fd), chunk); werr != nil && !errors.Is(werr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(werr, syscall.EAGAIN) {
		t.Fatalf("filling the decision socket ended with %v, want EAGAIN once it is full", werr)
	}
}

// F6: the production defaults are what rc runs with; none of them comes from a flag.
func TestProductionDefaults(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want time.Duration
	}{
		{"defaultTCPIdle", defaultTCPIdle, 30 * time.Second},
		{"defaultGrace", defaultGrace, time.Second},
		{"defaultHandshake", defaultHandshake, 10 * time.Second},
		{"defaultKillAfter", defaultKillAfter, 3 * time.Second},
		{"defaultWriteTimeout", defaultWriteTimeout, 10 * time.Second},
		{"defaultReadyTimeout", defaultReadyTimeout, 300 * time.Second},
	} {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
	g := newGateway(nil, nil, nil, time.Second, nil)
	if g.tcpIdle != defaultTCPIdle || g.grace != defaultGrace || g.handshake != defaultHandshake {
		t.Errorf("a new gateway runs with tcpIdle=%s grace=%s handshake=%s, want the defaults", g.tcpIdle, g.grace, g.handshake)
	}
	d, _, _ := newPeer(t)
	if d.writeTimeout != defaultWriteTimeout {
		t.Errorf("a new Decider writes with a %s deadline, want %s", d.writeTimeout, defaultWriteTimeout)
	}
	cfg, logs := lifecycleConfig(t, "serve")
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if srv.cfg.killAfter != defaultKillAfter || srv.cfg.readyTimeout != defaultReadyTimeout {
		t.Errorf("start() ran with killAfter=%s readyTimeout=%s, want %s and %s", srv.cfg.killAfter, srv.cfg.readyTimeout, defaultKillAfter, defaultReadyTimeout)
	}
}

// F9: no loopback default: a bare run must not bind the address that PR #3517 keeps the gateway off on :53.
func TestListenIsRequired(t *testing.T) {
	_, err := parseConfig([]string{"--", "decider"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("parseConfig without --listen: got err=%v, want an error naming --listen", err)
	}
}
