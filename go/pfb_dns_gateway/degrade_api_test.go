package main

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider"
)

// issue #3848: what the gateway's tests need of the API the change adds: the decider's list of what it lost (Degraded) and the
// boot's own timer (config.bootTimer), which a test replaces so that no boot timeout waits for a clock.

// The test deciders lose nothing.
func (echoFrontend) Degraded() []decider.DegradedPart       { return nil }
func (forwardingFrontend) Degraded() []decider.DegradedPart { return nil }
func (*drainFrontend) Degraded() []decider.DegradedPart     { return nil }
func (*heldFrontend) Degraded() []decider.DegradedPart      { return nil }

// lossyFrontend is a decider that forwards every query and reports what a test says it lost.
type lossyFrontend struct {
	forwardingFrontend
	lost []decider.DegradedPart
}

func (f lossyFrontend) Degraded() []decider.DegradedPart { return f.lost }

// firesAtOnce is a boot timer that has run out when it is made.
func firesAtOnce(time.Duration) (<-chan time.Time, func() bool) {
	fired := make(chan time.Time)
	close(fired)
	return fired, func() bool { return false }
}

// A5b: a boot that outlasts readyTimeout is given up on like one that failed; the decider that finishes afterwards is Closed.
// The timeout is the test's channel, so nothing waits for a clock.
func TestADeciderThatDoesNotBootInTimeIsReplacedByOneWithNoModuleAndTheLateOneIsClosed(t *testing.T) {
	up := newFakeUpstream(t)
	cfg, logs, sock := healthyConfig(t)
	cfg.upstream = up.addr
	release, late := make(chan struct{}), closingFrontend{closed: make(chan struct{})}
	cfg.open = func(o decider.Options) (frontend, error) {
		if o.NoModule {
			return forwardingFrontend{}, nil
		}
		<-release
		return late, nil
	}
	var timers atomic.Int32
	cfg.bootTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
		if timers.Add(1) == 1 { // the boot with the module runs out of time at once
			return firesAtOnce(d)
		}
		return make(chan time.Time), func() bool { return true }
	}
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("start = %v, want the gateway to serve without the module", err)
	}
	t.Cleanup(srv.shutdown)
	requireForwarded(t, logs, up)
	requireLost(t, sock, "after the module's boot timed out", map[string]string{"dnsbl": "did not boot within"}, "dnsbl")
	close(release)
	waitClosed(t, late.closed, "the late module decider to be closed")
}

// A5c: neither boot finishes in time (the test's channels say so): the start fails, and both late deciders are Closed.
func TestStartupFailsWhenNeitherDeciderBootsInTimeAndBothLateOnesAreClosed(t *testing.T) {
	cfg, logs, _ := healthyConfig(t)
	release, started := make(chan struct{}), make(chan closingFrontend, 2)
	cfg.open = func(decider.Options) (frontend, error) {
		late := closingFrontend{closed: make(chan struct{})}
		started <- late
		<-release
		return late, nil
	}
	cfg.bootTimer = firesAtOnce
	srv, err := start(cfg, logs.logf)
	if err == nil || !strings.Contains(err.Error(), "did not boot") {
		t.Fatalf("start: got srv=%v err=%v, want a did-not-boot error", srv, err)
	}
	if strings.Contains(logs.text(), "listening") {
		t.Fatalf("no readiness line without a decider:\n%s", logs.text())
	}
	var lates []closingFrontend
	for len(lates) < 2 {
		select {
		case late := <-started:
			lates = append(lates, late)
		case <-time.After(watchdog):
			t.Fatalf("only %d of 2 boots started within the watchdog (the second is the boot with no module)", len(lates))
		}
	}
	first, second := lates[0], lates[1]
	close(release)
	waitClosed(t, first.closed, "the late decider with the module to be closed")
	waitClosed(t, second.closed, "the late decider with no module to be closed")
}

// A5d: a signal while the module boots ends the start as it always did; it is no boot error to degrade from.
func TestAnInterruptWhileTheModuleBootsEndsTheStartWithoutBootingAgainWithNoModule(t *testing.T) {
	cfg, logs, _ := healthyConfig(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cfg.open = func(decider.Options) (frontend, error) { <-release; return echoFrontend{}, nil }
	interrupt := make(chan struct{})
	close(interrupt)
	cfg.interrupt = interrupt
	var timers atomic.Int32
	cfg.bootTimer = func(time.Duration) (<-chan time.Time, func() bool) {
		timers.Add(1)
		return make(chan time.Time), func() bool { return true }
	}
	srv, err := start(cfg, logs.logf)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("start: got srv=%v err=%v, want errInterrupted", srv, err)
	}
	if n := timers.Load(); n != 1 {
		t.Fatalf("the decider was booted %d times, want once", n)
	}
}

// S3: the gateway's parts and the decider's are one list, in contract order, each part once. The decider's own rows come in any
// order here, with a part twice; the part both sides report (dnsbl) is the gateway's row, whose reason is the first error.
func TestSeveralLostPartsAreListedInContractOrderEachOnce(t *testing.T) {
	absentPEM, absentConf := t.TempDir()+"/absent.pem", t.TempDir()+"/absent.conf"
	script := &bootScript{moduleErr: errors.New("boom"), fe: lossyFrontend{lost: []decider.DegradedPart{
		{Part: "observer", Reason: "first observer"}, {Part: "statistics", Reason: "stats"}, {Part: "dnsbl", Reason: "the decider's dnsbl"},
		{Part: "dnsbl_settings", Reason: "settings"}, {Part: "observer", Reason: "second observer"},
	}}}
	_, _, sock := startFromFlags(t, script.open, "--dns-name", "fw..lan", "--ddr", "--unbound-conf", absentConf,
		"--dot-listen", "127.0.0.1", "--dot-port", "0", "--tls-pem", absentPEM)
	rows := requireLost(t, sock, "everything lost", map[string]string{"dnsbl": "decider: boom", "dnsbl_settings": "settings", "statistics": "stats", "observer": "first observer", "acl": absentConf},
		"dnsbl", "dnsbl_settings", "dns_name", "ddr", "tls_certificate", "acl", "statistics", "observer")
	for _, row := range rows {
		if row.Part == "dnsbl" && row.Reason != "decider: boom" || row.Part == "observer" && row.Reason != "first observer" {
			t.Errorf("row %+v: want the gateway's first error for dnsbl and the decider's first row for observer", row)
		}
	}
}

// S2: a reason is one line with no control characters and at most 300 bytes, cut where a character ends: a consumer rejects the
// whole status for one bad reason.
func TestAReasonLosesItsControlCharactersAndIsCutAtThreeHundredBytes(t *testing.T) {
	open := func(decider.Options) (frontend, error) {
		return lossyFrontend{lost: []decider.DegradedPart{
			{Part: "dnsbl_settings", Reason: "bad\x00reason\nwith\x1b\x7f\u0085control\xff"},
			{Part: "statistics", Reason: strings.Repeat("x", 400)},
			{Part: "observer", Reason: strings.Repeat("a", 299) + "é" + "tail"}, // the é would end at byte 301
		}}, nil
	}
	_, _, sock := startFromFlags(t, open)
	rows, _ := statusLost(t, sock)
	want := []lostRow{
		{"dnsbl_settings", "badreasonwithcontrol"},
		{"statistics", strings.Repeat("x", 300)},
		{"observer", strings.Repeat("a", 299)},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v, want %+v", rows, want)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

// S2b: a reason with nothing printable left is still a reason: the status names the part with "no reason given", since the
// consumer rejects an empty one and so the whole status.
func TestAReasonWithNothingPrintableLeftIsNoReasonGiven(t *testing.T) {
	cases := map[string]string{
		"nul":          "\x00",
		"newlines":     "\n\r\t",
		"zero-width":   "\u200b\u2060",
		"invalid utf8": "\xff\xfe",
		"printable":    "disk full",
	}
	want := map[string]string{
		"nul":          "no reason given",
		"newlines":     "no reason given",
		"zero-width":   "no reason given",
		"invalid utf8": "no reason given",
		"printable":    "disk full",
	}
	for name, in := range cases {
		if got := degradedReason(in); got != want[name] {
			t.Errorf("%s: degradedReason(%q) = %q, want %q", name, in, got, want[name])
		}
	}
}
