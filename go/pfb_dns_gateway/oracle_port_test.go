package main

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// The oracle's Unbound is given a port the test picked: picking and binding are two steps, and under load another
// process may take the port between them. Unbound then exits with "Address already in use", which is the environment
// and not a verdict about the matcher: a fresh pick is tried, a bounded number of times and for that outcome only.

func counter(from int) func() int {
	n := from - 1
	return func() int { n++; return n }
}

func TestAPickedPortThatWasTakenIsPickedAgain(t *testing.T) {
	var tried []int
	got, err := retryOnTakenPort(8, counter(100), func(port int) (string, bool) {
		tried = append(tried, port)
		return "started on " + strconv.Itoa(port), port < 103
	})
	if err != nil {
		t.Fatalf("gave up after %v: %v", tried, err)
	}
	if got != "started on 103" || len(tried) != 4 || tried[0] != 100 || tried[3] != 103 {
		t.Fatalf("got %q after the ports %v, want a start on 103 after 100, 101, 102 were taken", got, tried)
	}
}

func TestAPortThatWasNotTakenIsNotPickedAgain(t *testing.T) {
	calls := 0
	got, err := retryOnTakenPort(8, counter(100), func(port int) (int, bool) { calls++; return port, false })
	if err != nil || got != 100 || calls != 1 {
		t.Fatalf("got %d, %v after %d tries, want 100 at the first", got, err, calls)
	}
}

func TestPortsThatAreAlwaysTakenAreGivenUpOnAfterThePicks(t *testing.T) {
	calls := 0
	_, err := retryOnTakenPort(5, counter(100), func(int) (int, bool) { calls++; return 0, true })
	if err == nil || calls != 5 {
		t.Fatalf("err %v after %d tries, want an error after exactly 5", err, calls)
	}
}

// Unbound binds the port for UDP and for TCP: a number that is free for only one of them is not a free port. The pick is
// made on a UDP socket that is closed again, so its number can be held for TCP by anyone.
func TestAPortThatIsFreeForUDPButHeldForTCPIsNotThePortTheOracleGets(t *testing.T) {
	heldTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer heldTCP.Close()
	held := heldTCP.Addr().(*net.TCPAddr).Port
	free := freeLoopbackPort(t)
	candidates := []int{held, held, free}
	pick := func() int { n := candidates[0]; candidates = candidates[1:]; return n }
	if got := freeLoopbackPortFrom(t, pick); got != free {
		t.Fatalf("got port %d, want %d: %d is held for TCP", got, free, held)
	}
}

// An Unbound that finds its port held exits with "Address already in use", and the oracle says the port was taken rather
// than failing the test. The port is held here for UDP and TCP, as another process would hold it.
func TestTheOracleUnboundReportsAPortThatIsHeldAsTaken(t *testing.T) {
	if _, err := runDocker(t, "", time.Minute, "image", "inspect", oracleImage); err != nil {
		if out, err := runDocker(t, oracleDockerfile, oracleBuildTimeout, "build", "-t", oracleImage, "-"); err != nil {
			t.Fatalf("cannot build the Unbound test image: %v\n%s", err, out)
		}
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Skipf("the TCP side of %d is held by someone else: %v", port, err)
	}
	defer tcp.Close()

	o, taken := tryOracleUnbound(t, oracleTree{}, port)
	if !taken || o != nil {
		t.Fatalf("Unbound on the held port %d: taken=%v unbound=%v, want taken and none", port, taken, o)
	}
}
