package main

import (
	"errors"
	"io"
	"net"
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
	t.Cleanup(srv.dec.Close) // frees a shutdown that is stuck, so a failure does not leak it
	var serving string
	for _, l := range strings.Split(logs.text(), "\n") {
		if strings.HasPrefix(l, "listening udp+tcp ") {
			serving = strings.TrimPrefix(l, "listening udp+tcp ")
		}
	}
	d := srv.dec
	d.writeTimeout = time.Hour // a write that cannot complete would hold the shutdown this long
	d.wmu.Lock()
	for chunk := make([]byte, 64*1024); ; {
		_ = d.conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		if _, err := d.conn.Write(chunk); err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				d.wmu.Unlock()
				t.Fatalf("filling the decision socket: %v", err)
			}
			break
		}
	}
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
		t.Fatal("STUCK: shutdown waits for a query blocked writing to a decider that reads nothing")
	}
}

// F4: the SafeSearch chase is a second FORWARD; two silent Unbound exchanges of one timeout each must still fit the
// whole-query limit of 2 x timeout + grace. (grace < timeout, so a limit of timeout + grace would cut it short.)
func TestChaseOfTwoSilentForwardsStillGetsItsAnswer(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, timeout: 600 * time.Millisecond, grace: 400 * time.Millisecond, upstream: []upstreamOption{silent()}})
			done := make(chan []byte, 1)
			go func() { done <- r.roundTrip(tr, "", buildQuery(t, 0x5151, "duck.example.", true)) }()
			q := r.recvQuery()
			for range 2 {
				r.p.send(tForward, q.id, q.wire)
				r.p.expect(tReply, q.id, nil) // Unbound said nothing for a whole timeout
			}
			r.p.send(tAnswer, q.id, []byte("chased answer"))
			if got := awaitBytes(t, done); string(got) != "chased answer" {
				t.Fatalf("client reply %x, want the decider's answer: the query was cut off before the chase finished", got)
			}
		})
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
