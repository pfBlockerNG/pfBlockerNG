package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// inUse is what bindUDP reports when another socket holds the UDP port.
func inUse() error {
	return listenError("127.0.0.1:1", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)})
}

// failingUDP fails the first n binds with err, then binds for real; calls counts every bind.
func failingUDP(n int, err error, calls *int) func(string, int) (*net.UDPConn, error) {
	return func(host string, port int) (*net.UDPConn, error) {
		*calls++
		if *calls <= n {
			return nil, err
		}
		return bindUDP(host, port)
	}
}

// Port 0 picks the TCP port first and asks for the same number for UDP: under load another socket may hold that number
// for UDP, and another pick is another number. A startup that failed on it would be a failure of luck, not of a setting.
func TestPortZeroIsPickedAgainWhenTheUDPSideOfItsNumberIsTaken(t *testing.T) {
	var calls int
	l, err := bindPlainWith("127.0.0.1", 0, failingUDP(3, inUse(), &calls))
	if err != nil {
		t.Fatalf("bindPlain on port 0 failed after %d binds: %v", calls, err)
	}
	defer l.close()
	if calls != 4 {
		t.Fatalf("%d UDP binds, want 4: three taken, then one", calls)
	}
	if tcp, udp := l.tcp.Addr().(*net.TCPAddr).Port, l.udp.LocalAddr().(*net.UDPAddr).Port; tcp != udp || tcp == 0 {
		t.Fatalf("TCP on %d and UDP on %d, want one number for both", tcp, udp)
	}
}

// A port that was asked for is never exchanged for another: the same refusal comes back at once. So does any other error.
func TestAPortThatWasAskedForIsNotPickedAgain(t *testing.T) {
	for name, c := range map[string]struct {
		port int
		err  error
	}{
		"fixed port in use":          {freePort(t), inUse()},
		"port 0, another bind error": {0, listenError("127.0.0.1:1", &net.OpError{Op: "listen", Err: os.NewSyscallError("bind", syscall.EACCES)})},
	} {
		t.Run(name, func(t *testing.T) {
			var calls int
			l, err := bindPlainWith("127.0.0.1", c.port, failingUDP(100, c.err, &calls))
			if err == nil {
				l.close()
				t.Fatal("bindPlain succeeded, want the UDP bind's error")
			}
			if calls != 1 || !errors.Is(err, errors.Unwrap(c.err)) {
				t.Fatalf("%d UDP binds and error %v, want one bind and the error it gave", calls, err)
			}
		})
	}
}

// A port 0 that is taken every time is given up on, with the error, after a few picks.
func TestPortZeroIsGivenUpOnAfterAFewPicks(t *testing.T) {
	var calls int
	l, err := bindPlainWith("127.0.0.1", 0, failingUDP(1<<20, inUse(), &calls))
	if err == nil {
		l.close()
		t.Fatal("bindPlain succeeded, want the UDP bind's error")
	}
	if !errors.Is(err, syscall.EADDRINUSE) || calls != bindPlainPicks {
		t.Fatalf("%d UDP binds and error %v, want %d binds and an address-in-use error", calls, err, bindPlainPicks)
	}
}
