package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The control socket is how root hands the gateway a renewed TLS certificate once the gateway no longer is root: a
// Unix stream socket in a root-only directory, kept by the gateway after its privilege drop. One message per
// connection: a 4-byte big-endian length, then that many bytes of PEM (the certificate, the CAs after it, the key);
// one reply line, `ok` or `error: <reason>`. Whoever is not root, by the kernel's credential of the peer, is closed on
// without a byte read from it.

// shortTempDir is a directory with a path short enough for a Unix socket in it (108 bytes on Linux, 104 on FreeBSD):
// t.TempDir carries the test's name.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func ctlFrame(pem []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(pem))), pem...)
}

type ctlRig struct {
	r     *rig
	c     *ctlServer
	store *certStore
	path  string
	root  *pki

	peer    atomic.Uint32 // the uid the credential of the next peer says; ctlUID, the one allowed, unless a test changes it
	peerErr atomic.Bool   // the credential cannot be read
}

// newCtlRig is a control socket in front of an empty store; its peers are root unless a test says otherwise. Options
// set what the server reads while it runs, so they go in before it starts.
func newCtlRig(t *testing.T, options ...func(*ctlServer)) *ctlRig {
	t.Helper()
	r := newRig(t, rigConfig{acl: aclMixed})
	store := newEmptyCertStore(r.logs.logf)
	path := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	c, err := bindCtl(path, store, r.logs.logf)
	if err != nil {
		t.Fatalf("bindCtl: %v", err)
	}
	k := &ctlRig{r: r, c: c, store: store, path: path, root: newPKI(t, nil, "ctl root", true)}
	k.peer.Store(ctlUID)
	c.peerUID = func(*net.UnixConn) (uint32, error) {
		if k.peerErr.Load() {
			return 0, syscall.ENOTSUP
		}
		return k.peer.Load(), nil
	}
	for _, option := range options {
		option(c)
	}
	c.serve(r.g)
	return k
}

func withDeadline(d time.Duration) func(*ctlServer) { return func(c *ctlServer) { c.deadline = d } }

func (k *ctlRig) leaf(t *testing.T) *pki { return newPKI(t, k.root, "localhost", false) }

func dialCtl(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ctlReply is what the server sent before it closed (empty when it closed with nothing to say).
func ctlReply(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && !isClosed(err) {
		t.Fatalf("reading the control socket's reply: %q, %v", line, err)
	}
	return strings.TrimRight(line, "\n")
}

// push sends one message and returns the reply.
func (k *ctlRig) push(t *testing.T, pem []byte) string {
	t.Helper()
	c := dialCtl(t, k.path)
	_, _ = c.Write(ctlFrame(pem)) // a server that refuses the peer has closed already: the reply is what tells
	return ctlReply(t, c)
}

func (k *ctlRig) requireServing(t *testing.T, want *pki, when string) {
	t.Helper()
	cert, err := k.store.getCertificate(nil)
	if err != nil || cert == nil || !bytes.Equal(cert.Certificate[0], want.der) {
		t.Fatalf("%s: the store serves %v (err %v), want serial %v", when, cert, err, want.cert.SerialNumber)
	}
}

func (k *ctlRig) requireEmpty(t *testing.T, when string) {
	t.Helper()
	if cert, err := k.store.getCertificate(nil); err == nil || cert != nil {
		t.Fatalf("%s: the store serves %v, want no certificate and an error", when, cert)
	}
}

func (k *ctlRig) logsAbout(what string) int { return strings.Count(k.r.logs.joined(), what) }

func TestAPushFromRootReplacesTheCertificateAndIsAnswered(t *testing.T) {
	k := newCtlRig(t)
	k.requireEmpty(t, "before the first push")
	first, second := k.leaf(t), k.leaf(t)

	if got := k.push(t, chainPEM(t, first)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireServing(t, first, "after the first push")
	if got := k.push(t, chainPEM(t, second)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireServing(t, second, "after the second push")
	if n := k.logsAbout("TLS certificate replaced by a push"); n != 2 {
		t.Fatalf("each push is logged once, got %d lines: %s", n, k.r.logs.joined())
	}
}

// What a push parses to is what the file at start parses to: the chain as sent, nearest CA first, then the key.
func TestAPushedChainIsServedAsSent(t *testing.T) {
	k := newCtlRig(t)
	mid := newPKI(t, k.root, "mid", true)
	leaf := newPKI(t, mid, "localhost", false)
	if got := k.push(t, chainPEM(t, leaf, mid, k.root)); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	cert, _ := k.store.getCertificate(nil)
	if len(cert.Certificate) != 3 || !bytes.Equal(cert.Certificate[1], mid.der) || !bytes.Equal(cert.Certificate[2], k.root.der) {
		t.Fatalf("the served chain has %d certificates, want leaf, intermediate, root", len(cert.Certificate))
	}
}

// Anyone but root: not read, not answered, not logged by name; one line per burst of them.
func TestAPeerThatIsNotRootIsClosedOnUnreadAndLoggedOncePerBurst(t *testing.T) {
	k := newCtlRig(t)
	k.peer.Store(ctlUID + 1001)
	leaf := k.leaf(t)
	for range 3 {
		if got := k.push(t, chainPEM(t, leaf)); got != "" {
			t.Fatalf("a peer that is not root got the reply %q, want none", got)
		}
	}
	k.requireEmpty(t, "after three pushes from another user")
	if n := k.logsAbout("control socket: refused"); n != 1 {
		t.Fatalf("three refusals in one burst must log once, got %d lines: %s", n, k.r.logs.joined())
	}
	if !strings.Contains(k.r.logs.joined(), strconv.Itoa(int(ctlUID+1001))) {
		t.Fatalf("the refusal must name the uid: %s", k.r.logs.joined())
	}

	// A push from root ends the burst: the next refusal is a burst of its own
	k.peer.Store(ctlUID)
	if got := k.push(t, chainPEM(t, leaf)); got != "ok" {
		t.Fatalf("root's push got %q", got)
	}
	k.peer.Store(ctlUID + 1001)
	if got := k.push(t, chainPEM(t, k.leaf(t))); got != "" {
		t.Fatalf("a peer that is not root got the reply %q, want none", got)
	}
	k.requireServing(t, leaf, "after the later refusal")
	if n := k.logsAbout("control socket: refused"); n != 2 {
		t.Fatalf("a refusal after a root push is a new burst: want 2 lines, got %d: %s", n, k.r.logs.joined())
	}
}

// A credential that cannot be read is no credential: closed on, like a peer that is not root.
func TestAPeerWhoseCredentialCannotBeReadIsRefused(t *testing.T) {
	k := newCtlRig(t)
	k.peerErr.Store(true)
	if got := k.push(t, chainPEM(t, k.leaf(t))); got != "" {
		t.Fatalf("got the reply %q, want none", got)
	}
	k.requireEmpty(t, "after a push with no credential")
	if k.logsAbout("control socket: refused") != 1 {
		t.Fatalf("the refusal must be logged: %s", k.r.logs.joined())
	}
}

// A message that is not a usable certificate and key changes nothing: the served certificate stays and the reply says why.
func TestAPushThatIsNotAUsableCertificateKeepsTheServedOneAndSaysWhy(t *testing.T) {
	k := newCtlRig(t)
	good := k.leaf(t)
	if got := k.push(t, chainPEM(t, good)); got != "ok" {
		t.Fatalf("the first push got %q", got)
	}
	other := k.leaf(t)
	whole := chainPEM(t, other)
	encrypted := append(other.certPEM(), "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"...)
	cases := map[string][]byte{
		"no PEM text":                        []byte("hello\n"),
		"a certificate with no key":          other.certPEM(),
		"a key with no certificate":          other.keyPEM(t),
		"the key of another one":             append(other.certPEM(), k.leaf(t).keyPEM(t)...),
		"half a message":                     whole[:len(whole)/2],
		"an encrypted key":                   encrypted,
		"a key that is not PEM":              append(other.certPEM(), []byte("-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n")...),
		"the same certificate again, no key": bytes.Repeat(other.certPEM(), 3),
	}
	for name, pem := range cases {
		reply := k.push(t, pem)
		if !strings.HasPrefix(reply, "error: ") || len(reply) <= len("error: ") {
			t.Fatalf("%s: reply %q, want `error: <reason>`", name, reply)
		}
		k.requireServing(t, good, name)
	}
	if n := k.logsAbout("TLS certificate not replaced"); n != len(cases) {
		t.Fatalf("each refused push is logged, want %d lines, got %d: %s", len(cases), n, k.r.logs.joined())
	}
}

// The length is judged before the body is read, so a hostile length costs nothing: the error comes back with only the
// 4 length bytes sent, and the connection is closed.
func TestAMessageWhoseLengthIsOutOfBoundsIsRefusedBeforeItIsRead(t *testing.T) {
	k := newCtlRig(t)
	for name, n := range map[string]uint32{"zero": 0, "one over the limit": ctlMaxPEM + 1, "four gigabytes": 0xffffffff} {
		c := dialCtl(t, k.path)
		if _, err := c.Write(binary.BigEndian.AppendUint32(nil, n)); err != nil {
			t.Fatal(err)
		}
		if reply := ctlReply(t, c); !strings.HasPrefix(reply, "error: ") || !strings.Contains(reply, "not between 1 and") {
			t.Fatalf("%s: reply %q, want the error for a length out of bounds, with no body sent", name, reply)
		}
	}
	k.requireEmpty(t, "after the refused lengths")
}

// What is not a frame is a length too: an HTTP request or a line of text is refused, nothing else is spoken on this socket.
func TestAnythingButAFrameIsRefused(t *testing.T) {
	k := newCtlRig(t)
	for name, junk := range map[string]string{"HTTP": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "a command": "reload\n", "a PROXY header": "\r\n\r\n\x00\r\nQUIT\n"} {
		c := dialCtl(t, k.path)
		_, _ = c.Write([]byte(junk))
		if reply := ctlReply(t, c); !strings.HasPrefix(reply, "error: ") {
			t.Fatalf("%s: reply %q, want an error", name, reply)
		}
	}
	k.requireEmpty(t, "after the junk")
}

// One message per connection: what follows the first is not read, so one connection cannot push twice.
func TestOnlyTheFirstMessageOfAConnectionIsRead(t *testing.T) {
	k := newCtlRig(t)
	first, second := k.leaf(t), k.leaf(t)
	c := dialCtl(t, k.path)
	if _, err := c.Write(append(ctlFrame(chainPEM(t, first)), ctlFrame(chainPEM(t, second))...)); err != nil {
		t.Fatal(err)
	}
	if got := ctlReply(t, c); got != "ok" {
		t.Fatalf("reply %q, want ok", got)
	}
	k.requireServing(t, first, "after a connection that sent two messages")
}

// A client that sends part of its message, or nothing, is cut off at the deadline with an error, and the next one is served.
func TestASlowOrSilentClientIsCutOffAndTheNextOneIsServed(t *testing.T) {
	k := newCtlRig(t, withDeadline(100*time.Millisecond))
	leaf := k.leaf(t)
	pem := chainPEM(t, leaf)

	short := dialCtl(t, k.path)
	if _, err := short.Write(ctlFrame(pem)[:len(pem)/2]); err != nil { // the length and half the body
		t.Fatal(err)
	}
	if reply := ctlReply(t, short); !strings.HasPrefix(reply, "error: ") {
		t.Fatalf("half a message: reply %q, want an error", reply)
	}
	silent := dialCtl(t, k.path)
	if reply := ctlReply(t, silent); !strings.HasPrefix(reply, "error: ") {
		t.Fatalf("a client that sent nothing: reply %q, want an error", reply)
	}
	k.requireEmpty(t, "after the cut-off clients")
	if got := k.push(t, pem); got != "ok" {
		t.Fatalf("the next client got %q, want ok", got)
	}
	k.requireServing(t, leaf, "after the next client")
}

func statOf(t *testing.T, path string) (os.FileInfo, *syscall.Stat_t) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info, info.Sys().(*syscall.Stat_t)
}

// The directory and the socket are made for root alone, whoever's umask: nothing else may even reach the socket.
func TestTheSocketAndItsDirectoryAreRootOnly(t *testing.T) {
	k := newCtlRig(t)
	dir, dst := statOf(t, filepath.Dir(k.path))
	if !dir.IsDir() || dir.Mode().Perm() != 0o700 || int(dst.Uid) != os.Geteuid() {
		t.Fatalf("directory: mode %v uid %d, want a directory 0700 owned by uid %d", dir.Mode(), dst.Uid, os.Geteuid())
	}
	sock, sst := statOf(t, k.path)
	if sock.Mode()&os.ModeSocket == 0 || sock.Mode().Perm() != 0o600 || int(sst.Uid) != os.Geteuid() {
		t.Fatalf("socket: mode %v uid %d, want a socket 0600 owned by uid %d", sock.Mode(), sst.Uid, os.Geteuid())
	}
}

// A directory that was left too open is closed again, one that is not ours is refused (a key must not go through it),
// and what an earlier gateway left at the path (a socket it could not remove after its drop) is replaced.
func TestTheDirectoryOfTheSocketIsMadePrivateOrRefused(t *testing.T) {
	logf := func(string, ...any) {}
	open := filepath.Join(shortTempDir(t), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := bindCtl(filepath.Join(open, "ctl.sock"), newEmptyCertStore(logf), logf)
	if err != nil {
		t.Fatalf("a directory left open: %v", err)
	}
	_ = c.ln.Close()
	if info, _ := statOf(t, open); info.Mode().Perm() != 0o700 {
		t.Fatalf("the directory is %v, want it closed to 0700", info.Mode().Perm())
	}

	target := shortTempDir(t)
	link := filepath.Join(shortTempDir(t), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if c, err := bindCtl(filepath.Join(link, "ctl.sock"), newEmptyCertStore(logf), logf); err == nil {
		_ = c.ln.Close()
		t.Fatal("a symlink where the directory goes was accepted")
	}

	file := filepath.Join(shortTempDir(t), "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := bindCtl(filepath.Join(file, "ctl.sock"), newEmptyCertStore(logf), logf); err == nil {
		_ = c.ln.Close()
		t.Fatal("a file where the directory goes was accepted")
	}

	stale := filepath.Join(shortTempDir(t), "stale")
	first, err := bindCtl(filepath.Join(stale, "ctl.sock"), newEmptyCertStore(logf), logf)
	if err != nil {
		t.Fatal(err)
	}
	first.ln.SetUnlinkOnClose(false) // an earlier gateway that could not remove it after its drop
	_ = first.ln.Close()
	if _, err := os.Lstat(filepath.Join(stale, "ctl.sock")); err != nil {
		t.Fatalf("the stale socket was not left behind: %v", err)
	}
	second, err := bindCtl(filepath.Join(stale, "ctl.sock"), newEmptyCertStore(logf), logf)
	if err != nil {
		t.Fatalf("a stale socket must be replaced: %v", err)
	}
	_ = second.ln.Close()
}

// The stop of the gateway closes the socket: nothing connects afterwards.
func TestStoppingTheGatewayClosesTheControlSocket(t *testing.T) {
	k := newCtlRig(t)
	if got := k.push(t, chainPEM(t, k.leaf(t))); got != "ok" {
		t.Fatalf("before the stop: %q", got)
	}
	k.r.g.stop()
	if c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: k.path, Net: "unix"}); err == nil {
		_ = c.Close()
		t.Fatal("the control socket still accepts after stop()")
	}
}

// The kernel's credential of the peer, as the platform gives it: SO_PEERCRED on Linux, LOCAL_PEERCRED on FreeBSD.
func TestPeerUIDIsTheKernelsCredentialOfTheConnectingProcess(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		t.Skipf("no peer credential call for %s", runtime.GOOS)
	}
	dir := shortTempDir(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() { c, _ := ln.AcceptUnix(); accepted <- c }()
	client := dialCtl(t, filepath.Join(dir, "s"))
	_ = client
	server := <-accepted
	defer server.Close()
	uid, err := peerUID(server)
	if err != nil || int(uid) != os.Geteuid() {
		t.Fatalf("peerUID = %d, %v; want %d, nil", uid, err, os.Geteuid())
	}
}

// The real thing, as root with a child that has given up root: the kernel says uid != 0 and the push is refused. The
// socket is opened to everyone here (a deployment never does) so that the child reaches the credential check, which is
// what is under test.
func TestARealProcessThatIsNotRootIsRefusedByTheKernelsCredential(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a real setuid: needs root to switch user")
	}
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no user `nobody` to drop to")
	}
	dir := shortTempDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, rigConfig{acl: aclMixed})
	store := newEmptyCertStore(r.logs.logf)
	path := filepath.Join(dir, "run", "ctl.sock")
	c, err := bindCtl(path, store, r.logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	c.serve(r.g) // the real credential call
	for _, p := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(path), 0o755}, {path, 0o666}} {
		if err := os.Chmod(p.path, p.mode); err != nil {
			t.Fatal(err)
		}
	}
	root := newPKI(t, nil, "real root", true)
	pemFile := filepath.Join(dir, "msg.pem")
	if err := os.WriteFile(pemFile, chainPEM(t, newPKI(t, root, "localhost", false)), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(os.Args[0], "--as-ctl-client", path, pemFile, "nobody").CombinedOutput()
	if err != nil {
		t.Fatalf("the client: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "refused" {
		t.Fatalf("a push by `nobody` ended with %q, want the connection closed with no reply", got)
	}
	if cert, err := store.getCertificate(nil); err == nil || cert != nil {
		t.Fatal("a push by a process that is not root changed the certificate")
	}
	if n := strings.Count(r.logs.joined(), "control socket: refused"); n != 1 {
		t.Fatalf("the refusal must be logged once, got %d: %s", n, r.logs.joined())
	}
}

// pushAsUser is the test binary in its --as-ctl-client role: it gives up root, pushes the PEM file and says what came back.
func pushAsUser(sock, pemFile, name string) int {
	acct, err := lookupAccount(name)
	if err != nil {
		os.Stdout.WriteString("lookup: " + err.Error() + "\n")
		return 1
	}
	pem, err := os.ReadFile(pemFile)
	if err != nil {
		os.Stdout.WriteString("read: " + err.Error() + "\n")
		return 1
	}
	if err := acct.drop(); err != nil {
		os.Stdout.WriteString("drop: " + err.Error() + "\n")
		return 1
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		os.Stdout.WriteString("dial: " + err.Error() + "\n")
		return 1
	}
	defer c.Close()
	_, _ = c.Write(ctlFrame(pem))
	_ = c.SetReadDeadline(time.Now().Add(watchdog))
	line, err := bufio.NewReader(c).ReadString('\n')
	switch {
	case line != "":
		os.Stdout.WriteString("reply: " + strings.TrimSpace(line) + "\n")
	case isClosed(err):
		os.Stdout.WriteString("refused\n")
	default:
		os.Stdout.WriteString("read: " + err.Error() + "\n")
	}
	return 0
}

// A directory that someone else owns is refused, however it is moded: its owner could replace the socket in it. Root only,
// like every test that needs a second user.
func TestADirectoryOwnedByAnotherUserIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a second owner: needs root to chown")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no user `nobody` to give the directory to")
	}
	dir := filepath.Join(shortTempDir(t), "theirs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(nobody.Uid)
	gid, _ := strconv.Atoi(nobody.Gid)
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	logf := func(string, ...any) {}
	c, err := bindCtl(filepath.Join(dir, "ctl.sock"), newEmptyCertStore(logf), logf)
	if err == nil {
		_ = c.ln.Close()
		t.Fatal("a directory owned by another user was accepted")
	}
	if !strings.Contains(err.Error(), "not owned by") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}
