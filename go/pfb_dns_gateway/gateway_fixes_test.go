package main

import (
	"context"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
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

// F4: the SafeSearch chase is a second FORWARD; two silent Unbound exchanges of one timeout each must still fit the
// whole-query limit of 2 x timeout + grace. (grace < timeout, so a limit of timeout + grace would cut it short.) This
// calls resolve and resolveShared directly, not the transport handlers (the test after it covers UDP and TCP end to end).
// The limit is the deadline of the context each forward runs under, which the test reads instead of waiting out two
// timeouts: the query was started somewhere between `started` and the moment its forward ran, so the limit lies between
// the two distances, however slow the machine. The timeouts are hours, so a limit that is wrong by a whole timeout cannot
// hide in that gap, and nothing here waits for them: a silent exchange is a forwarder that returns nil at once.
func TestChaseOfTwoSilentForwardsStillGetsItsAnswer(t *testing.T) {
	const timeout, grace = 6 * time.Hour, 4 * time.Hour
	client := netip.MustParseAddr(clientAllowed)
	for _, c := range []struct {
		name string
		ask  func(g *gateway, wire []byte, fwd forwarder) []byte
	}{
		{"udp", func(g *gateway, wire []byte, fwd forwarder) []byte {
			return g.resolve(context.Background(), client, netip.Addr{}, clientUDP, wire, fwd)
		}},
		{"tcp", func(g *gateway, wire []byte, fwd forwarder) []byte {
			return g.resolve(context.Background(), client, netip.Addr{}, clientTCP, wire, fwd)
		}},
		{"doh and doq", func(g *gateway, wire []byte, fwd forwarder) []byte {
			reply, _ := g.resolveShared(context.Background(), client, netip.Addr{}, clientDoH, wire, fwd)
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

// The handlers hand resolve the whole-query limit as they find it: the test above calls resolve and resolveShared
// directly, so a UDP or TCP handler that bounded the query itself (say by timeout + grace) would not show there. Here the
// queries go through the real UDP and TCP handlers. grace is minus one timeout, which puts 2 x timeout + grace at one hour
// and timeout + grace at zero: a handler that bounded the query by timeout + grace would hand resolve a context that is over
// already, and the decider's FORWARD would never reach Unbound. The positive event is Unbound receiving that forwarded query;
// no timer runs out in the passing case, and the failing one ends at the watchdog.
func TestTheUDPAndTCPHandlersDoNotShortenTheWholeQueryLimit(t *testing.T) {
	const timeout = time.Hour
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			r := newRig(t, rigConfig{acl: aclMixed, timeout: timeout, grace: -timeout})
			var reply func() []byte
			if tr.tcp {
				c := r.tcpClient("")
				tcpSend(t, c, buildQuery(t, 0x5252, "duck.example.", true))
				reply = func() []byte { return tcpReply(t, c) }
			} else {
				c := r.udpClient("")
				if _, err := c.Write(buildQuery(t, 0x5252, "duck.example.", true)); err != nil {
					t.Fatal(err)
				}
				reply = func() []byte { return udpReply(t, c) }
			}
			q := r.recvQuery()
			r.p.send(tForward, q.id, q.wire)
			var seen seenQuery
			select {
			case seen = <-r.up.queries:
			case <-time.After(watchdog):
				t.Fatal("STUCK/ENVIRONMENT: the decider's FORWARD never reached Unbound: the query's context was over before it ran, so the handler shortened the whole-query limit")
			}
			r.p.expect(tReply, q.id, echoWithQR(seen)[0])
			r.p.send(tAnswer, q.id, []byte("answered"))
			if got := reply(); string(got) != "answered" {
				t.Fatalf("client reply %x, want the decider's answer", got)
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
		{"defaultReadyTimeout", defaultReadyTimeout, 300 * time.Second},
	} {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
	g := newGateway(nil, nil, nil, time.Second, nil)
	if g.tcpIdle != defaultTCPIdle || g.grace != defaultGrace || g.handshake != defaultHandshake || g.doqHandshakeIdle != 5*time.Second {
		t.Errorf("a new gateway runs with tcpIdle=%s grace=%s handshake=%s doqHandshakeIdle=%s, want the defaults", g.tcpIdle, g.grace, g.handshake, g.doqHandshakeIdle)
	}
	if got := g.doqQUICConfig().HandshakeIdleTimeout; got != 5*time.Second {
		t.Errorf("DoQ HandshakeIdleTimeout = %s, want 5s", got)
	}
	cfg, logs := lifecycleConfig(t)
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if srv.cfg.readyTimeout != defaultReadyTimeout || srv.cfg.shutdownBudget != defaultShutdownBudget {
		t.Errorf("start() ran with readyTimeout=%s shutdownBudget=%s, want %s and %s", srv.cfg.readyTimeout, srv.cfg.shutdownBudget, defaultReadyTimeout, defaultShutdownBudget)
	}
}

// F9: no loopback default: a bare run must not bind the address that PR #3517 keeps the gateway off on :53.
func TestListenIsRequired(t *testing.T) {
	_, err := parseConfig([]string{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Fatalf("parseConfig without --listen: got err=%v, want an error naming --listen", err)
	}
}
