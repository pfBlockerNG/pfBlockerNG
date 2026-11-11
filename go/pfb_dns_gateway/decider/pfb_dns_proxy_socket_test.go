// Tests of the observer's socket (#3791 step A): Frontend.serve_observer and _serve_observer of pfb_dns_proxy.py (removed in #3791), in Go. What
// a datagram's bytes mean is pfb_unbound_upstream_test.go's and the oracle test's; these tests are about the socket: where
// it is, who can reach it, what happens to a datagram on it and what Close leaves.
package decider

import (
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// shortDir is a module directory with a path short enough for a unix socket in it (about 104 bytes), holding an ini that
// has the resolver forward, so that a reported block is counted.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfbo")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "pfb_unbound.ini"), []byte("[MAIN]\npython_enable = true\nforwarding = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func observerPath(dir string) string { return filepath.Join(dir, "pfb_upstream.sock") }

const observerOffLine = "pfb_dns_proxy error: upstream-block detection is off: cannot listen on pfb_upstream.sock: "

// send is one datagram to the observer's socket, as pfb_upstream_observer.py sends.
func send(path string, data []byte) error {
	conn, err := net.Dial("unixgram", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(data)
	return err
}

func mustSend(t *testing.T, dir string, data []byte) {
	t.Helper()
	if err := send(observerPath(dir), data); err != nil {
		t.Fatal(err)
	}
}

// eventually polls what the observer goroutine and the log writer do on their own.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("STUCK/ENVIRONMENT: %s did not happen", what)
}

// blockRows is what the module wrote to dnsbl.log so far.
func blockRows(logDir string) []string {
	raw, _ := os.ReadFile(filepath.Join(logDir, dnsblLogName))
	if len(raw) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// socketFrontend is a module decider listening on its observer socket, its log files in a directory of its own.
func socketFrontend(t *testing.T, dir string) (*Frontend, string, *lockedLog) {
	t.Helper()
	logDir := t.TempDir()
	withLogDir(t, logDir)
	log := captureLockedLog(t)
	f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	if f.observer == nil {
		t.Fatalf("no observer socket; log = %q", log.String())
	}
	return f, logDir, log
}

// --- where it is, and what is already there ---------------------------------------------------------

func TestObserverSocketIsCreatedAtItsPathMode0600(t *testing.T) {
	dir := shortDir(t)
	socketFrontend(t, dir)
	info, err := os.Lstat(observerPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Type() != fs.ModeSocket || info.Mode().Perm() != 0o600 {
		t.Errorf("%s is %v, want a socket with mode 0600", observerPath(dir), info.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".pfb_upstream*")); len(left) != 0 {
		t.Errorf("the private directory the socket was bound in is left: %v", left)
	}
}

// A socket left by a previous proxy is replaced.
func TestObserverSocketReplacesAStaleOne(t *testing.T) {
	dir := shortDir(t)
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: observerPath(dir), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close() // the file stays, nothing listens: what a crashed proxy leaves
	before, err := os.Lstat(observerPath(dir))
	if err != nil || before.Mode().Type() != fs.ModeSocket {
		t.Fatalf("stale socket not set up: %v, %v", before, err)
	}
	log := captureLockedLog(t)
	f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	after, err := os.Lstat(observerPath(dir))
	if err != nil || f.observer == nil {
		t.Fatalf("lstat = (%v, %v), observer = %v; log = %q", after, err, f.observer, log.String())
	}
	if os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Errorf("the stale socket was not replaced by a 0600 one (same file: %v, mode %v)", os.SameFile(before, after), after.Mode())
	}
}

// Anything else at the path raises an OSError in Python's serve_observer and is left alone; DNS is served without it.
func TestObserverSocketLeavesAnythingThatIsNotASocketAloneAndServesWithoutIt(t *testing.T) {
	for name, setup := range map[string]func(path string) error{
		"a regular file": func(path string) error { return os.WriteFile(path, []byte("keep me"), 0o644) },
		"a directory":    func(path string) error { return os.Mkdir(path, 0o755) },
		// lstat: a symlink is not a socket, even one that points at a socket
		"a symlink to a socket": func(path string) error {
			target := path + ".real"
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: target, Net: "unix"})
			if err != nil {
				return err
			}
			t.Cleanup(func() { l.Close() })
			return os.Symlink(target, path)
		},
		"a dangling symlink": func(path string) error { return os.Symlink(path+".gone", path) },
	} {
		dir := shortDir(t)
		path := observerPath(dir)
		if err := setup(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		log := captureLockedLog(t)
		f := openOK(t, Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Errorf("%s: left alone? lstat = (%v, %v), was %v", name, after, err, before)
		}
		if f.observer != nil {
			t.Errorf("%s: an observer is listening", name)
		}
		if got := strings.Count(log.String(), observerOffLine); got != 1 {
			t.Errorf("%s: the off line was logged %d times, want once; log = %q", name, got, log.String())
		}
		reply := f.Resolve(queryWire(t, allowed, 0x0100), testClient, unboundAnswering192_0_2_77(t), "UDP", "", "")
		if got := raceAddresses(t, reply); got != "192.0.2.77" {
			t.Errorf("%s: the decider does not serve without the observer: %q", name, got)
		}
		f.Close()
		if after, err := os.Lstat(path); err != nil || !os.SameFile(before, after) {
			t.Errorf("%s: Close touched what was not its own: %v, %v", name, after, err)
		}
	}
}

// #3511: the socket is created restricted, not chmod-ed after the bind. It is bound inside a fresh 0700 directory in the
// module directory, restricted there, and only then published at its path (an atomic link or rename of that restricted
// socket): at no moment is the final path a socket of a wider mode. The worst umask (none) is the one that would make the
// bind alone create it 0777. The published socket is the one that listens.
func TestObserverSocketOnlyAppearsAtItsPathAsARestrictedSocket(t *testing.T) {
	dir := shortDir(t)
	logDir := t.TempDir()
	withLogDir(t, logDir)
	var publishes int
	var from, to string
	var privateMode, socketMode fs.FileMode
	var finalAbsent bool
	previous := observerPublish
	t.Cleanup(func() { observerPublish = previous })
	observerPublish = func(oldpath, newpath string) error {
		publishes++
		from, to = oldpath, newpath
		if info, err := os.Stat(filepath.Dir(oldpath)); err == nil {
			privateMode = info.Mode()
		}
		if info, err := os.Lstat(oldpath); err == nil {
			socketMode = info.Mode()
		}
		_, err := os.Lstat(newpath)
		finalAbsent = os.IsNotExist(err)
		return previous(oldpath, newpath)
	}
	umask := syscall.Umask(0)
	f, err := Open(Options{LogDir: testLogDir, ModuleDir: dir, Observer: true})
	syscall.Umask(umask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)

	if publishes != 1 || to != observerPath(dir) {
		t.Fatalf("publishes = %d, last onto %q, want one onto %q", publishes, to, observerPath(dir))
	}
	if filepath.Dir(filepath.Dir(from)) != dir || !strings.HasPrefix(filepath.Base(filepath.Dir(from)), ".pfb_upstream") {
		t.Errorf("the socket was bound at %q, want a fresh directory directly inside the module directory", from)
	}
	if !privateMode.IsDir() || privateMode.Perm() != 0o700 {
		t.Errorf("the directory it was bound in is %v, want a directory of mode 0700", privateMode)
	}
	if socketMode.Type() != fs.ModeSocket || socketMode.Perm() != 0o600 {
		t.Errorf("at the publish the socket is %v, want a socket of mode 0600", socketMode)
	}
	if !finalAbsent {
		t.Errorf("the final path existed before the publish put the socket there")
	}
	if _, err := os.Lstat(filepath.Dir(from)); !os.IsNotExist(err) {
		t.Errorf("the private directory is left after the publish (lstat: %v)", err)
	}
	if info, err := os.Lstat(observerPath(dir)); err != nil || info.Mode().Perm() != 0o600 || info.Mode().Type() != fs.ModeSocket {
		t.Errorf("final path = (%v, %v), want a socket of mode 0600", info, err)
	}
	mustSend(t, dir, observerReport(t, nil)) // reachable through its final name once the temporary name is gone
	eventually(t, "the report sent to the final path to be heard", func() bool { return len(blockRows(logDir)) > 0 })
}

// The final path is published without replacing: whatever appears there after the lstat (a file another process created in
// that moment) is not this decider's to overwrite. The publish refuses, the file is left byte for byte, and DNS is served
// without the observer.
func TestObserverSocketPublishNeverReplacesWhatAppearsAtItsPathAfterTheLstat(t *testing.T) {
	dir := shortDir(t)
	path := observerPath(dir)
	previous := observerPublish
	t.Cleanup(func() { observerPublish = previous })
	observerPublish = func(oldpath, newpath string) error {
		if err := os.WriteFile(newpath, []byte("not mine"), 0o644); err != nil {
			t.Error(err)
		}
		return previous(oldpath, newpath)
	}
	log := captureLockedLog(t)
	f := openOK(t, Options{ModuleDir: dir, LogDir: testLogDir, Observer: true})

	if got, err := os.ReadFile(path); err != nil || string(got) != "not mine" {
		t.Errorf("the file that appeared at %s = (%q, %v), want it left byte for byte", path, got, err)
	}
	if f.observer != nil {
		t.Errorf("an observer is listening after the publish was refused")
	}
	if got := strings.Count(log.String(), observerOffLine); got != 1 || !strings.Contains(log.String(), path) {
		t.Errorf("the off line (naming %s) was logged %d times, want once; log = %q", path, got, log.String())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".pfb_upstream-*")); len(left) != 0 {
		t.Errorf("the private directory is left after a refused publish: %v", left)
	}
}

func TestObserverSocketAsksForAReceiveBufferOf256KiB(t *testing.T) {
	f, _, _ := socketFrontend(t, shortDir(t))
	raw, err := f.observer.conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var optErr error
	if err := raw.Control(func(fd uintptr) { got, optErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF) }); err != nil || optErr != nil {
		t.Fatal(err, optErr)
	}
	if got < 256*1024 { // the kernel may double what it is given, never halve it below what it grants
		t.Errorf("SO_RCVBUF = %d, want at least %d", got, 256*1024)
	}
}

// --- datagrams -------------------------------------------------------------------------------------

// A valid report is a row and a count, as inside Unbound. A bad one is dropped with one warning for the lifetime of the
// decider, and the reader goes on.
func TestObserverSocketTurnsAReportIntoARowAndACountAndDropsBadOnesWithOneWarning(t *testing.T) {
	dir := shortDir(t)
	f, logDir, log := socketFrontend(t, dir)
	for _, bad := range [][]byte{
		{},                 // empty datagram
		{'{'},              // one byte
		[]byte("not json"), // not JSON
		[]byte(`[1,2,3]`),  // JSON of the wrong shape
		rawReport(`1`, `"x."`, `"A"`, `true`, `{}`), // wrong types
	} {
		mustSend(t, dir, bad)
	}
	mustSend(t, dir, observerReport(t, nil))
	eventually(t, "the valid report's row", func() bool { return len(blockRows(logDir)) > 0 })
	f.Close()

	if got := strings.Count(log.String(), "malformed upstream report from the observer, ignored (further ones silently): "); got != 1 {
		t.Errorf("the malformed-report warning was logged %d times over %d bad datagrams, want once; log = %q", got, 5, log.String())
	}
	if rows := blockRows(logDir); len(rows) != 1 || !strings.Contains(rows[0], "blocked.example") {
		t.Errorf("dnsbl.log rows = %q, want exactly the valid report's", rows)
	}
	if got := sqlValue(t, filepath.Join(dir, "pfb_py_dnsbl.sqlite"), "SELECT counter FROM dnsbl WHERE groupname='Upstream'"); got != int64(1) {
		t.Errorf("Upstream counter = %v, want 1: the valid report only", got)
	}
}

// MAX_REPORT_BYTES is a datagram's size, not a report's: one of exactly that many bytes is read whole, one byte more is
// dropped as oversize (the reader's buffer is larger than the limit, so that it is not cut to a size that fits).
func TestObserverSocketTakesAReportOfExactlyMaxReportBytesAndDropsOneByteMore(t *testing.T) {
	dir := shortDir(t)
	f, logDir, log := socketFrontend(t, dir)
	pad := func(size int) []byte {
		report := observerReport(t, nil)
		return append(report, bytes.Repeat([]byte(" "), size-len(report))...) // JSON ignores trailing space
	}
	mustSend(t, dir, pad(maxReportBytes+1))
	mustSend(t, dir, pad(maxReportBytes))
	eventually(t, "the report of exactly the limit", func() bool { return len(blockRows(logDir)) > 0 })
	f.Close()
	if want := fmt.Sprintf("%d bytes: a report is one datagram of at most %d", maxReportBytes+1, maxReportBytes); !strings.Contains(log.String(), want) {
		t.Errorf("log = %q, want it to say %q", log.String(), want)
	}
	if rows := blockRows(logDir); len(rows) != 1 {
		t.Errorf("rows = %q, want one: the report of exactly the limit, not the oversize one", rows)
	}
}

// A flood while Close runs: nothing panics, Close returns, and the socket is gone.
func TestObserverSocketCloseUnderAFloodEndsTheReaderAndUnlinksTheSocket(t *testing.T) {
	dir := shortDir(t)
	f, _, _ := socketFrontend(t, dir)
	report := observerReport(t, nil)
	stop := make(chan struct{})
	var flood sync.WaitGroup
	for range 4 {
		flood.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				data := report
				if i%3 == 1 {
					data = []byte("garbage")
				}
				_ = send(observerPath(dir), data) // refused once the socket is closed: the sender does not care
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		f.Close()
	}()
	chWait(t, "Close under a flood", closed)
	close(stop)
	flood.Wait()
	if _, err := os.Lstat(observerPath(dir)); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after Close (lstat: %v)", err)
	}
}

// --- Close -----------------------------------------------------------------------------------------

func TestObserverSocketIsUnlinkedByCloseAndASecondCloseDoesNothing(t *testing.T) {
	dir := shortDir(t)
	f, _, _ := socketFrontend(t, dir)
	f.Close()
	if _, err := os.Lstat(observerPath(dir)); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after Close (lstat: %v)", err)
	}
	if err := send(observerPath(dir), []byte("x")); err == nil {
		t.Errorf("a datagram was accepted after Close")
	}
	// a later proxy's socket at the same path is not this one's to remove
	other, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: observerPath(dir), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f.Close()
	if _, err := os.Lstat(observerPath(dir)); err != nil {
		t.Errorf("a second Close removed a socket that is not this decider's: %v", err)
	}
}

// --- a reader that panics or sticks, and the order of Close ---------------------------------------------

// gatedLog is a log whose first write of a line holding match panics (panics) or blocks until release is closed.
type gatedLog struct {
	*lockedLog
	match            string
	panics           bool
	once             sync.Once
	entered, release chan struct{}
}

func (g *gatedLog) Write(p []byte) (int, error) {
	if strings.Contains(string(p), g.match) {
		g.once.Do(func() {
			if g.panics {
				panic("log writer blew up")
			}
			close(g.entered)
			<-g.release
		})
	}
	return g.lockedLog.Write(p)
}

// A panic in the report handler (here: the log write of the first malformed report) is logged and the reader goes on:
// the next valid report is still a row. Python's asyncio logs an exception of datagram_received and reads on.
func TestObserverSocketRecoversAPanicOfTheReportHandlerAndProcessesTheNextReport(t *testing.T) {
	dir := shortDir(t)
	logDir := t.TempDir()
	withLogDir(t, logDir)
	log := captureLockedLog(t)
	logOutput = &gatedLog{lockedLog: log, match: "malformed upstream report", panics: true}
	f := openOK(t, Options{ModuleDir: dir, LogDir: testLogDir, Observer: true})
	if f.observer == nil {
		t.Fatalf("no observer socket; log = %q", log.String())
	}

	mustSend(t, dir, []byte("not json"))
	eventually(t, "the failure of the handler to be logged", func() bool {
		return strings.Contains(log.String(), "upstream report handler failed: log writer blew up")
	})
	mustSend(t, dir, observerReport(t, nil))
	eventually(t, "the next valid report's row", func() bool { return len(blockRows(logDir)) > 0 })
}

// A reader that does not end (here: stuck in the log write of a report) holds Close for watcherStopWait and no longer: one
// line says so, and the socket is unlinked all the same.
func TestObserverSocketCloseGivesUpOnAStuckReaderAfterTheBound(t *testing.T) {
	shortStopWait(t)
	dir := shortDir(t)
	withLogDir(t, t.TempDir())
	log := captureLockedLog(t)
	gate := &gatedLog{lockedLog: log, match: "malformed upstream report", entered: make(chan struct{}), release: make(chan struct{})}
	logOutput = gate
	f := openOK(t, Options{ModuleDir: dir, LogDir: testLogDir, Observer: true})
	t.Cleanup(func() { close(gate.release) }) // runs before Close's own cleanup: the stuck reader ends first

	mustSend(t, dir, []byte("not json"))
	chWait(t, "the reader to stick in its log write", gate.entered)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		f.Close()
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatalf("Close is still waiting for a stuck reader: the wait is not bounded")
	}
	if got := strings.Count(log.String(), "observer socket reader did not stop"); got != 1 {
		t.Errorf("Close logged %d lines about the stuck reader, want 1; log = %q", got, log.String())
	}
	if _, err := os.Lstat(observerPath(dir)); !os.IsNotExist(err) {
		t.Errorf("the socket is still there after Close gave up on the reader (lstat: %v)", err)
	}
}

// Close stops the observer before the module deinits, so that no report meets a closing module: when deinit starts (its
// first step is the reload watcher's stop, hooked here) the socket is gone and refuses a datagram.
func TestCloseStopsTheObserverBeforeTheModuleDeinits(t *testing.T) {
	dir := shortDir(t)
	f, _, _ := socketFrontend(t, dir)
	var called bool
	var lstatErr, sendErr error
	stopWatcher := f.module.reloadStop
	f.module.reloadStop = func() {
		called = true
		_, lstatErr = os.Lstat(observerPath(dir))
		sendErr = send(observerPath(dir), []byte("x"))
		if stopWatcher != nil {
			stopWatcher()
		}
	}
	f.Close()
	if !called {
		t.Fatal("deinit did not stop the reload watcher: the hook never ran")
	}
	if !os.IsNotExist(lstatErr) || sendErr == nil {
		t.Errorf("when deinit started the socket was still there (lstat: %v, send: %v), want it closed and unlinked", lstatErr, sendErr)
	}
}
