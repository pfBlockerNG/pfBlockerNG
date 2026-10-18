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
	"sort"
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

// oracleTree is an Unbound config laid out the way pfSense lays it out: rows of unbound.conf itself before and after
// its includes (pfBlockerNG's marked clause, an admin's custom options), access_lists.conf, and one glob include.
type oracleTree struct {
	before  []aclRow
	access  []aclRow            // access_lists.conf
	globbed map[string][]aclRow // acl.d/<name>, all read by one `include: acl.d/*.conf`
	after   []aclRow

	// implicit: access-control-view ("view") and access-control-tag ("tag") rows. Unbound allows each netblock that
	// no access-control row names; the view and tag are the ones the template defines.
	implicit []aclRow
}

// ordered is the rows in the order Unbound reads them; glob matches by name.
func (o oracleTree) ordered() []aclRow {
	rows := append(append([]aclRow(nil), o.before...), o.access...)
	names := make([]string, 0, len(o.globbed))
	for name := range o.globbed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rows = append(rows, o.globbed[name]...)
	}
	return append(rows, o.after...)
}

type oracleUnbound struct {
	conn   *net.UDPConn
	port   int
	nextID uint16
	conf   string // the unbound.conf the daemon runs, at the same path on the host and in the container
}

func startOracleUnbound(t *testing.T, tree oracleTree) *oracleUnbound {
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
    define-tag: "t1"
%s    include: "%s/access_lists.conf"
    include: "%s/acl.d/*.conf"
%s    local-zone: "oracle.test." static
    local-data: "%s 300 IN A 192.0.2.1"
view:
    name: "v1"
`, port, port, renderRows(tree.before, "    "), dir, dir, renderRows(tree.after, "    "), oracleName)
	// glibc's glob(3) fails Unbound's config when the glob's directory is missing, so the oracle always has one.
	if err := os.MkdirAll(filepath.Join(dir, "acl.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"unbound.conf": conf, "access_lists.conf": renderACL(tree.access) + renderImplicit(tree.implicit)}
	for name, rows := range tree.globbed {
		files["acl.d/"+name] = renderRows(rows, "")
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	name := fmt.Sprintf("pfb-acl-oracle-%d-%d", os.Getpid(), port)
	cmd := exec.Command("docker", "run", "--rm", "--network", "host", "--name", name,
		"-v", dir+":"+dir+":ro", oracleImage, "unbound", "-d", "-c", dir+"/unbound.conf")
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
	return &oracleUnbound{conn: conn, port: port, conf: filepath.Join(dir, "unbound.conf")}
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

func (o *oracleUnbound) send(t *testing.T, id uint16, client netip.Addr, name string) {
	t.Helper()
	dstIP := netip.MustParseAddr("127.0.0.1")
	if client.Is6() {
		dstIP = netip.MustParseAddr("::1")
	}
	datagram := append(proxyV2UDP(netip.AddrPortFrom(client, 40000), netip.AddrPortFrom(dstIP, uint16(o.port))),
		dnsQuery(id, name)...)
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
	return o.probeName(t, client, oracleName)
}

// probeName is probe for a query of name; the sentinel is always oracleName, which Unbound answers locally.
func (o *oracleUnbound) probeName(t *testing.T, client netip.Addr, name string) string {
	t.Helper()
	o.nextID++
	id := o.nextID
	o.send(t, id, client, name)
	o.send(t, oracleSentinelID, netip.MustParseAddr("127.0.0.1"), oracleName)
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

func renderRows(rows []aclRow, indent string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(indent + "access-control: " + r.net + " " + r.action + "\n")
	}
	return b.String()
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

// renderImplicit writes the implicit-allow rows; the view and tag names are the ones startOracleUnbound's template defines.
func renderImplicit(rows []aclRow) string {
	var b strings.Builder
	for _, r := range rows {
		switch r.action {
		case "view":
			b.WriteString("access-control-view: " + r.net + " v1\n")
		case "tag":
			b.WriteString("access-control-tag: " + r.net + " \"t1\"\n")
		default:
			panic("renderImplicit: unknown kind " + r.action)
		}
	}
	return b.String()
}

// withImplicit adds the `allow` Unbound gives each implicit netblock that no identical access-control row names.
func withImplicit(t *testing.T, rows, implicit []aclRow) []aclRow {
	t.Helper()
	listed := append([]aclRow(nil), rows...)
	for _, r := range implicit {
		present := false
		for _, row := range rows {
			present = present || referencePrefix(t, row.net) == referencePrefix(t, r.net)
		}
		if !present {
			listed = append(listed, aclRow{r.net, "allow"})
		}
	}
	return listed
}

// unboundWant is Unbound's outcome for the local-data name per action; "" leaves it to the printed grid.
var unboundWant = map[string]string{
	"deny": "dropped", "refuse": "refused",
	"allow": "answered", "allow_snoop": "answered", "allow_setrd": "answered",
	"deny_non_local": "answered", "refuse_non_local": "answered",
}

// outcomeAction is what the gateway must do for each outcome Unbound gives a client.
var outcomeAction = map[string]ACLAction{"dropped": ACLDrop, "refused": ACLRefuse, "answered": ACLForward}

// runOracleGrid runs the gateway's ACL on the very unbound.conf a real Unbound runs and compares them for every
// client of the grid: the gateway acts exactly as Unbound does, a client no row names included.
func runOracleGrid(t *testing.T, tree oracleTree, extra []string, wantUnmatched bool) {
	t.Helper()
	un := startOracleUnbound(t, tree)
	a := NewACL(un.conf, t.Logf)
	listed := withUnboundDefaults(t, withImplicit(t, tree.ordered(), tree.implicit))
	clients := gridClients(t, listed, extra)
	if len(clients) >= oracleSentinelID {
		t.Fatalf("grid of %d clients exhausts the id space", len(clients))
	}
	acting, ordered, unmatched := 0, 0, 0
	for _, c := range clients {
		ref, explicit := referenceAction(t, listed, c)
		got := a.Lookup(c)
		out := un.probe(t, c)
		t.Logf("client=%-24v reference=%-18q go=%-8v unbound=%s", c, ref, got, out)
		// allow_cookie: Unbound refuses a UDP query without a valid DNS cookie (this probe is UDP only); the gateway forwards it.
		if ref == "allow_cookie" {
			if got != ACLForward || out != "refused" {
				t.Errorf("%v: allow_cookie over UDP: Go says %v, Unbound %s; want forward and refused", c, got, out)
			}
			continue
		}
		want, known := outcomeAction[out]
		if !known {
			t.Errorf("%v: Unbound's outcome %q is not dropped, refused or answered", c, out)
		} else if got != want {
			t.Errorf("%v: Go says %v but Unbound %s", c, got, out)
		}
		if !explicit {
			unmatched++
			if out != "refused" {
				t.Errorf("%v: matches no row, so Unbound should refuse it, got %s", c, out)
			}
			continue
		}
		// Non-vacuity: where the most specific explicit entry denies or refuses, Go must act.
		wantRef := map[string]ACLAction{"deny": ACLDrop, "refuse": ACLRefuse}[ref] // zero value is ACLForward
		if got != wantRef {
			t.Errorf("%v: reference action %q, Go got %v, want %v", c, ref, got, wantRef)
		}
		if wantRef != ACLForward {
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
	if acting == 0 || ordered == 0 || (wantUnmatched && unmatched == 0) {
		t.Errorf("vacuous grid: %d acting, %d oracle-checked and %d unmatched clients out of %d", acting, ordered, unmatched, len(clients))
	}
	t.Logf("%d clients probed, %d where Go acts, %d matching no row", len(clients), acting, unmatched)
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
	runOracleGrid(t, oracleTree{access: rows}, []string{"8.8.8.8", "203.0.113.200", "2606:4700::1111", "fc00::1", "100.64.9.1"}, true)
}

// P1/P2 /0 rows leave no unmatched client, so they get their own Unbound. Without pfSense's localhost rows,
// 127.0.0.0/8 and ::1 are reachable only through Unbound's built-in defaults, which beat the /0 rows.
func TestACLOracleDefaultRoutes(t *testing.T) {
	rows := []aclRow{
		{"192.168.1.0/24", "allow "}, {"0.0.0.0/0", "refuse"}, {"10.0.0.0/8", "deny"}, {"10.1.0.0/16", "allow"},
		{"::/0", "deny"}, {"2001:db8::/32", "refuse"}, {"2001:db8:1::/48", "allow"},
	}
	runOracleGrid(t, oracleTree{access: rows}, []string{"8.8.8.8", "203.0.113.200", "2606:4700::1111", "fc00::1", "127.0.0.1", "127.9.9.9", "::1", "::2"}, false)
}

// File rows on prefixes identical to Unbound's localhost defaults (127.0.0.0/8, ::1) must beat them.
// 127.0.0.1/32 allow keeps the probe socket's own address and the sentinel answerable.
func TestACLOracleLocalhostRowsOverrideDefaults(t *testing.T) {
	rows := []aclRow{
		{"127.0.0.1/32", "allow"}, {"127.0.0.0/8", "deny"}, {"::1", "refuse"}, {"10.0.0.0/8", "allow"},
	}
	runOracleGrid(t, oracleTree{access: rows}, []string{"127.0.0.2", "127.9.9.9", "::1", "::2", "10.9.9.9", "8.8.8.8"}, true)
}

// pfSense's layout on a box with IPv6: the LAN's IPv6 grant is pfBlockerNG's marked clause in unbound.conf, an admin's
// custom rows come after the includes, a glob include adds more, and rows override each other across files.
func TestACLOracleIncludeTreeMarkedClauseAndGlob(t *testing.T) {
	tree := oracleTree{
		before: []aclRow{{"2001:db8:51:1::/64", "allow"}, {"10.7.0.0/24", "deny"}},
		access: []aclRow{{"127.0.0.1/32", "allow_snoop"}, {"192.168.1.0/24", "allow "}, {"10.7.0.0/24", "allow"}},
		globbed: map[string][]aclRow{
			"10-a.conf": {{"100.64.1.0/24", "refuse"}, {"2001:db8:52::/48", "allow"}},
			"20-b.conf": {{"2001:db8:53::/48", "deny"}},
		},
		after: []aclRow{{"198.51.100.0/24", "deny"}, {"192.168.1.0/24", "refuse"}, {"192.168.1.128/25", "allow"}},
	}
	runOracleGrid(t, tree, []string{"192.168.1.77", "192.168.1.200", "2001:db8:51:1::1234", "2001:db8:51:2::1", "10.7.0.5", "8.8.8.8", "2606:4700::1111"}, true)
}

// Unbound reads glob matches in name order (it sorts them), so of identical prefixes in two matched files the later
// name's row wins. The grid compares that with a real Unbound.
func TestACLOracleGlobOverlapReadInNameOrder(t *testing.T) {
	tree := oracleTree{globbed: map[string][]aclRow{
		"10-a.conf": {{"10.50.0.0/16", "deny"}, {"10.60.0.0/16", "allow"}},
		"20-b.conf": {{"10.50.0.0/16", "allow"}, {"10.60.0.0/16", "refuse"}},
	}}
	runOracleGrid(t, tree, []string{"8.8.8.8", "10.70.0.1"}, true)
}

// access-control-view and access-control-tag netblocks with no identical access-control row: Unbound allows them, a
// more specific one sits under a refuse row, and an identical one leaves the refuse row standing.
func TestACLOracleViewAndTagNetblocksWithoutARow(t *testing.T) {
	tree := oracleTree{
		access: []aclRow{{"10.7.0.0/16", "refuse"}},
		implicit: []aclRow{
			{"10.7.1.0/24", "view"}, // view under the refuse row
			{"10.7.0.0/16", "view"}, // identical to the refuse row
			{"10.8.0.0/16", "view"}, // view only
			{"10.9.0.0/16", "tag"},  // tag only
		},
	}
	runOracleGrid(t, tree, []string{"8.8.8.8", "10.10.0.1"}, true)
}

// deny_non_local and refuse_non_local act on names Unbound holds no data for. The gateway forwards those clients, so
// the decider can still answer a listed name; this pins what Unbound itself does with a non-local name.
func TestACLOracleNonLocalNames(t *testing.T) {
	un := startOracleUnbound(t, oracleTree{access: []aclRow{{"100.64.7.0/24", "deny_non_local"}, {"100.64.8.0/24", "refuse_non_local"}}})
	a := NewACL(un.conf, t.Logf)
	const elsewhere = "elsewhere.example." // outside the oracle's static local-zone oracle.test.
	for _, c := range []struct{ client, unbound string }{{"100.64.7.1", "dropped"}, {"100.64.8.1", "refused"}} {
		client := mustAddr(t, c.client)
		got, out := a.Lookup(client), un.probeName(t, client, elsewhere)
		t.Logf("client=%s name=%s go=%v unbound=%s", c.client, elsewhere, got, out)
		if got != ACLForward || out != c.unbound {
			t.Errorf("%s asking %s: Go says %v and Unbound %s; want forward and %s", c.client, elsewhere, got, out, c.unbound)
		}
	}
}
