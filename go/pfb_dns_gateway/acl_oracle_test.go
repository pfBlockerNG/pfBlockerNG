package main

// Oracle: the Go ACL matcher against a REAL Unbound (Docker, host network, proxy-protocol-port).
// No Docker, or an image that cannot be built, is a FAILURE, never a skip.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	oracleImage      = "pfb-dns-frontend-unbound:trixie"
	oracleDockerfile = "FROM debian:trixie-slim\n" +
		"RUN apt-get update && apt-get install -y --no-install-recommends unbound && rm -rf /var/lib/apt/lists/*\n"
	oracleBuildTimeout = 15 * time.Minute
	oracleWatchdog     = 30 * time.Second // salvages a stuck run only; never an assertion
	oracleSentinelID   = 0xFFFF
	oracleName         = "host.oracle.test."
)

type aclRow struct{ net, action string }

func runDocker(t *testing.T, stdin string, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		if errors.Is(r.err, exec.ErrNotFound) {
			t.Fatalf("docker is required for the oracle (this must fail, not skip): %v", r.err)
		}
		return string(r.out), r.err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		t.Fatalf("STUCK/ENVIRONMENT: docker %v did not finish in %v", args, timeout)
		return "", nil
	}
}

type oracleUnbound struct {
	conn   *net.UDPConn
	port   int
	nextID uint16
}

func startOracleUnbound(t *testing.T, aclFileText string) *oracleUnbound {
	t.Helper()
	if out, err := runDocker(t, "", time.Minute, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Fatalf("docker daemon unreachable (this must fail, not skip): %v\n%s", err, out)
	}
	if _, err := runDocker(t, "", time.Minute, "image", "inspect", oracleImage); err != nil {
		if out, err := runDocker(t, oracleDockerfile, oracleBuildTimeout, "build", "-t", oracleImage, "-"); err != nil {
			t.Fatalf("cannot build the Unbound test image: %v\n%s", err, out)
		}
	}
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	dir := t.TempDir()
	conf := fmt.Sprintf(`server:
    verbosity: 1
    num-threads: 1
    interface: 127.0.0.1@%d
    proxy-protocol-port: %d
    do-ip6: yes
    chroot: ""
    username: ""
    pidfile: ""
    do-daemonize: no
    use-syslog: no
    logfile: ""
    include: "/conf/access_lists.conf"
    local-zone: "oracle.test." static
    local-data: "%s 300 IN A 192.0.2.1"
`, port, port, oracleName)
	for name, content := range map[string]string{"unbound.conf": conf, "access_lists.conf": aclFileText} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	name := fmt.Sprintf("pfb-acl-oracle-%d-%d", os.Getpid(), port)
	cmd := exec.Command("docker", "run", "--rm", "--network", "host", "--name", name,
		"-v", dir+":/conf:ro", oracleImage, "unbound", "-d", "-c", "/conf/unbound.conf")
	logR, logW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logW, logW
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start Unbound: %v", err)
	}
	_ = logW.Close()
	var (
		mu     sync.Mutex
		lines  []string
		ready  = make(chan struct{})
		exited = make(chan struct{})
	)
	go func() {
		defer close(exited)
		sc := bufio.NewScanner(logR)
		isReady := false
		for sc.Scan() {
			mu.Lock()
			lines = append(lines, sc.Text())
			mu.Unlock()
			if !isReady && strings.Contains(sc.Text(), "start of service") {
				isReady = true
				close(ready)
			}
		}
	}()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		_ = cmd.Wait()
		<-exited
		_ = logR.Close()
	})
	seen := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(lines, "\n")
	}
	select {
	case <-ready:
	case <-exited:
		t.Fatalf("Unbound exited before it was ready:\n%s", seen())
	case <-time.After(oracleWatchdog):
		t.Fatalf("STUCK/ENVIRONMENT: Unbound never printed its readiness line:\n%s", seen())
	}

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &oracleUnbound{conn: conn, port: port}
}

func dnsQuery(id uint16, name string) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1) // QTYPE A, QCLASS IN
}

// proxyV2UDP is the PROXYv2 header (command PROXY, UDP over INET or INET6) announcing src -> dst.
func proxyV2UDP(src, dst netip.AddrPort) []byte {
	family := byte(0x12)
	if src.Addr().Is6() {
		family = 0x22
	}
	body := append(src.Addr().AsSlice(), dst.Addr().AsSlice()...)
	body = binary.BigEndian.AppendUint16(body, src.Port())
	body = binary.BigEndian.AppendUint16(body, dst.Port())
	h := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, family)
	h = binary.BigEndian.AppendUint16(h, uint16(len(body)))
	return append(h, body...)
}

func (o *oracleUnbound) send(t *testing.T, id uint16, client netip.Addr) {
	t.Helper()
	dstIP := netip.MustParseAddr("127.0.0.1")
	if client.Is6() {
		dstIP = netip.MustParseAddr("::1")
	}
	datagram := append(proxyV2UDP(netip.AddrPortFrom(client, 40000), netip.AddrPortFrom(dstIP, uint16(o.port))),
		dnsQuery(id, oracleName)...)
	if _, err := o.conn.Write(datagram); err != nil {
		t.Fatalf("send for %v: %v", client, err)
	}
}

func classifyReply(b []byte) string {
	rcode := b[3] & 0x0f
	answers := binary.BigEndian.Uint16(b[6:8])
	switch {
	case rcode == 0 && answers > 0:
		return "answered"
	case rcode == 5:
		return "refused"
	}
	return fmt.Sprintf("rcode=%d answers=%d", rcode, answers)
}

// probe sends one query as `client`, then a sentinel from 127.0.0.1 on the same socket. One Unbound thread
// answers in order, so no probe reply before the sentinel's means Unbound dropped it: no sleeps needed.
func (o *oracleUnbound) probe(t *testing.T, client netip.Addr) string {
	t.Helper()
	o.nextID++
	id := o.nextID
	o.send(t, id, client)
	o.send(t, oracleSentinelID, netip.MustParseAddr("127.0.0.1"))
	outcome := "dropped"
	buf := make([]byte, 4096)
	for {
		_ = o.conn.SetReadDeadline(time.Now().Add(oracleWatchdog))
		n, err := o.conn.Read(buf)
		if err != nil {
			t.Fatalf("STUCK/ENVIRONMENT: probe for %v got no sentinel reply (127.0.0.1 must always be answered): %v", client, err)
		}
		if n < 12 {
			t.Fatalf("probe for %v: %d-byte reply is not DNS", client, n)
		}
		switch got := binary.BigEndian.Uint16(buf[:2]); got {
		case oracleSentinelID:
			return outcome
		case id:
			outcome = classifyReply(buf[:n])
		default:
			t.Fatalf("probe for %v: reply id %d is neither the probe (%d) nor the sentinel", client, got, id)
		}
	}
}

// referencePrefix and referenceAction are a deliberately naive linear scan, independent of the matcher.
func referencePrefix(t *testing.T, netblock string) netip.Prefix {
	t.Helper()
	if strings.Contains(netblock, "/") {
		p, err := netip.ParsePrefix(netblock)
		if err != nil {
			t.Fatalf("bad oracle row %q: %v", netblock, err)
		}
		return p.Masked()
	}
	return netip.PrefixFrom(mustAddr(t, netblock), mustAddr(t, netblock).BitLen())
}

// unboundDefaults are inserted by Unbound beneath the file's rows (acl_list_apply_cfg); an identical prefix
// in the file overrides them.
var unboundDefaults = []aclRow{{"127.0.0.0/8", "allow"}, {"::1", "allow"}}

func withUnboundDefaults(t *testing.T, rows []aclRow) []aclRow {
	t.Helper()
	listed := append([]aclRow(nil), rows...)
	for _, d := range unboundDefaults {
		present := false
		for _, r := range rows {
			present = present || referencePrefix(t, r.net) == referencePrefix(t, d.net)
		}
		if !present {
			listed = append(listed, d)
		}
	}
	return listed
}

// referenceAction is the most specific listed row for client; among identical prefixes the LAST line wins.
func referenceAction(t *testing.T, rows []aclRow, client netip.Addr) (action string, explicit bool) {
	t.Helper()
	best := -1
	for _, r := range rows {
		p := referencePrefix(t, r.net)
		if p.Contains(client) && p.Bits() >= best {
			best, action, explicit = p.Bits(), strings.TrimSpace(r.action), true
		}
	}
	return action, explicit
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// gridClients: inside every entry (first, second, last address), just outside both boundaries, plus extras.
func gridClients(t *testing.T, rows []aclRow, extra []string) []netip.Addr {
	t.Helper()
	seen := map[netip.Addr]bool{}
	var clients []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			clients = append(clients, a)
		}
	}
	for _, r := range rows {
		p := referencePrefix(t, r.net)
		if p.Bits() == 0 {
			continue
		}
		first, last := p.Addr(), lastAddr(p)
		add(first)
		add(first.Next())
		add(last)
		add(first.Prev())
		add(last.Next())
	}
	for _, e := range extra {
		add(mustAddr(t, e))
	}
	return clients
}

func renderACL(rows []aclRow) string {
	var b strings.Builder
	for i, r := range rows {
		if i == 3 {
			b.WriteString("#grid\n") // pfSense writes `#<aclname>` before each custom ACL's rows
		}
		b.WriteString("access-control: " + r.net + " " + r.action + "\n")
	}
	return b.String()
}

// unboundWant is Unbound's outcome for the local-data name per action; "" leaves it to the printed grid.
var unboundWant = map[string]string{
	"deny": "dropped", "refuse": "refused",
	"allow": "answered", "allow_snoop": "answered", "allow_setrd": "answered",
	"deny_non_local": "answered", "refuse_non_local": "answered",
}

func runOracleGrid(t *testing.T, rows []aclRow, extra []string) {
	t.Helper()
	text := renderACL(rows)
	a := newACL(t, text)
	un := startOracleUnbound(t, text)
	listed := withUnboundDefaults(t, rows)
	clients := gridClients(t, listed, extra)
	if len(clients) >= oracleSentinelID {
		t.Fatalf("grid of %d clients exhausts the id space", len(clients))
	}
	acting, ordered := 0, 0
	for _, c := range clients {
		ref, explicit := referenceAction(t, listed, c)
		got := a.Lookup(c)
		out := un.probe(t, c)
		t.Logf("client=%-24v reference=%-18q go=%-8v unbound=%s", c, ref, got, out)

		// Never stricter than Unbound.
		if got == ACLDrop && out != "dropped" {
			t.Errorf("%v: Go says Drop but Unbound %s", c, out)
		}
		if got == ACLRefuse && out != "refused" {
			t.Errorf("%v: Go says Refuse but Unbound %s", c, out)
		}
		if !explicit {
			if got != ACLForward {
				t.Errorf("%v: unmatched client must Forward, got %v", c, got)
			}
			continue
		}
		// Non-vacuity: where the most specific explicit entry denies or refuses, Go must act.
		want := map[string]ACLAction{"deny": ACLDrop, "refuse": ACLRefuse}[ref] // zero value is ACLForward
		if got != want {
			t.Errorf("%v: reference action %q, Go got %v, want %v", c, ref, got, want)
		}
		if want != ACLForward {
			acting++
		}
		// The reference table itself must agree with the real daemon, or the grid proves nothing.
		if exp := unboundWant[ref]; exp != "" {
			ordered++
			if out != exp {
				t.Errorf("%v: reference action %q, Unbound %s, want %s", c, ref, out, exp)
			}
		}
	}
	if acting == 0 || ordered == 0 {
		t.Errorf("vacuous grid: %d acting and %d oracle-checked clients out of %d", acting, ordered, len(clients))
	}
	t.Logf("%d clients probed, %d where Go acts", len(clients), acting)
}

func TestACLOracleGrid(t *testing.T) {
	rows := []aclRow{
		// pfSense's own prefix: localhost, then an auto network with its trailing space.
		{"127.0.0.1/32", "allow_snoop"}, {"::1", "allow_snoop"}, {"192.168.1.0/24", "allow "},
		// A1-A8
		{"100.64.1.0/24", "deny"}, {"100.64.2.0/24", "refuse"}, {"100.64.3.0/24", "allow"},
		{"100.64.4.0/24", "allow_snoop"}, {"100.64.5.0/24", "allow_setrd"}, {"100.64.6.0/24", "allow_cookie"},
		{"100.64.7.0/24", "deny_non_local"}, {"100.64.8.0/24", "refuse_non_local"},
		// P1/P3 nested IPv4 /8 /16 /24 /32
		{"10.0.0.0/8", "deny"}, {"10.1.0.0/16", "allow"}, {"10.1.2.0/24", "refuse"}, {"10.1.2.3/32", "allow_snoop"},
		{"172.16.0.0/16", "refuse"},
		// P4 host bits set, P6 bare address
		{"198.51.100.7/24", "refuse"}, {"203.0.113.9", "deny"},
		// P5 duplicates, in both orders
		{"192.0.2.0/24", "deny"}, {"192.0.2.0/24", "allow"},
		{"192.0.3.0/24", "allow"}, {"192.0.3.0/24", "deny"},
		// P2 IPv6 /32 /48 /64 /128, host bits, duplicates
		{"2001:db8::/32", "deny"}, {"2001:db8:1::/48", "refuse"}, {"2001:db8:1:2::/64", "allow"},
		{"2001:db8:1:2::5/128", "deny"}, {"2001:db8:2::7/64", "refuse"},
		{"2001:db8:3::/48", "deny"}, {"2001:db8:3::/48", "allow"},
		{"fd00:1::/32", "refuse"}, {"fd00:2::9", "deny"},
	}
	runOracleGrid(t, rows, []string{"8.8.8.8", "203.0.113.200", "2606:4700::1111", "fc00::1", "100.64.9.1"})
}

// P1/P2 /0 rows leave no unmatched client, so they get their own Unbound. Without pfSense's localhost rows,
// 127.0.0.0/8 and ::1 are reachable only through Unbound's built-in defaults, which beat the /0 rows.
func TestACLOracleDefaultRoutes(t *testing.T) {
	rows := []aclRow{
		{"192.168.1.0/24", "allow "}, {"0.0.0.0/0", "refuse"}, {"10.0.0.0/8", "deny"}, {"10.1.0.0/16", "allow"},
		{"::/0", "deny"}, {"2001:db8::/32", "refuse"}, {"2001:db8:1::/48", "allow"},
	}
	runOracleGrid(t, rows, []string{"8.8.8.8", "203.0.113.200", "2606:4700::1111", "fc00::1", "127.0.0.1", "127.9.9.9", "::1", "::2"})
}
