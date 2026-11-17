package feedfetch_test

// Guards for behaviour the parity corpus and the transfer tests left unpinned (#3911, "Test gaps"): each test here fails
// when the production line it names is removed. Corpus rows cover what PHP can run too; these need a TLS origin, a
// resolver that changes its answer, a process tree, a bound source address or an unexported helper.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedfetch"
)

// quickFetcher is fetcherFor with a retry pause that cannot slow a failing run.
func quickFetcher(t *testing.T) (*feedfetch.Fetcher, feedfetch.Feed) {
	t.Helper()
	f, feed := fetcherFor(t)
	f.RetryDelay = time.Millisecond
	return f, feed
}

// countingServer answers every request with h and counts them; its URL is returned.
func countingServer(t *testing.T, h http.HandlerFunc) (string, *atomic.Int32) {
	t.Helper()
	hits := new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, hits
}

// rsyncStandIn installs the corpus's stand-in rsync (it records its arguments and its `ulimit -f` beside itself and
// writes "r\n" to its destination) and returns its path and directory.
func rsyncStandIn(t *testing.T) (bin, dir string) {
	t.Helper()
	script, err := os.ReadFile("../../../tests/feedfetch/fixtures/fake-rsync.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	bin = filepath.Join(dir, "rsync")
	for name, content := range map[string]struct {
		data []byte
		mode os.FileMode
	}{"rsync": {script, 0o700}, "rsync.body": {[]byte("r\n"), 0o600}, "rsync.exit": {[]byte("0"), 0o600}} {
		if err := os.WriteFile(filepath.Join(dir, name), content.data, content.mode); err != nil {
			t.Fatal(err)
		}
	}
	return bin, dir
}

// entryLookups is how often the entry gate asks the resolver: a probe with nothing published decides right after it,
// before any transfer.
func entryLookups(t *testing.T, req feedfetch.Request) int32 {
	t.Helper()
	f, feed := quickFetcher(t)
	var asked atomic.Int32
	answer := f.Resolve
	f.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		asked.Add(1)
		return answer(ctx, host)
	}
	if res := f.Probe(context.Background(), feed, req); !res.OK || res.Decision != feedfetch.Changed || asked.Load() == 0 {
		t.Fatalf("calibration probe %+v asked the resolver %d times, want changed after at least one lookup", res, asked.Load())
	}
	return asked.Load()
}

// rebindAfter makes f's resolver answer as before for `entry` lookups and with a private address from then on: DNS
// rebinding between the entry gate and the transfer. It returns the lookup count.
func rebindAfter(f *feedfetch.Fetcher, entry int32) *atomic.Int32 {
	asked := new(atomic.Int32)
	answer := f.Resolve
	f.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if asked.Add(1) > entry {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil
		}
		return answer(ctx, host)
	}
	return asked
}

const nonPermitted = "feed host resolves to a non-permitted address"

// The transfer vets the host again, so a name that turns private after the entry gate (DNS rebinding) is never dialled:
// removing the vet in fetchHTTP or fetchRsync lets the request through.
func TestAHostThatTurnsPrivateAfterTheEntryGateIsRefusedAtTransferTime(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		url, hits := countingServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new\n") })
		// "localhost" resolves for the system too, so a transfer that skipped its own vet would reach the server.
		req := feedfetch.Request{URL: "http://localhost:" + port(t, url) + "/list", Timeout: 10 * time.Second}
		entry := entryLookups(t, req)

		stable, stableFeed := quickFetcher(t)
		if res := stable.Ingest(context.Background(), stableFeed, req); !res.OK || hits.Load() != 1 {
			t.Fatalf("with a stable answer the feed must be fetched: %+v, %d requests", res, hits.Load())
		}

		f, feed := quickFetcher(t)
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
		asked := rebindAfter(f, entry)
		res := f.Ingest(context.Background(), feed, req)
		if res.OK || res.Reason != nonPermitted || hits.Load() != 1 || published(t, feed) != "old\n" || asked.Load() <= entry {
			t.Fatalf("a rebound host must be refused at transfer time: %+v, %d requests in all (1 before), published %q, %d lookups (%d at entry)",
				res, hits.Load(), published(t, feed), asked.Load(), entry)
		}
	})

	t.Run("rsync", func(t *testing.T) {
		req := feedfetch.Request{URL: "rsync://localhost/feeds/list.txt", Rsync: true, Timeout: 10 * time.Second}
		bin, tools := rsyncStandIn(t)
		entry := entryLookups(t, req)

		stable, stableFeed := quickFetcher(t)
		stable.RsyncBin = bin
		if res := stable.Ingest(context.Background(), stableFeed, req); !res.OK {
			t.Fatalf("with a stable answer rsync must run: %+v", res)
		}
		os.Remove(filepath.Join(tools, "rsync.argv"))

		f, feed := quickFetcher(t)
		f.RsyncBin = bin
		os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
		asked := rebindAfter(f, entry)
		res := f.Ingest(context.Background(), feed, req)
		_, err := os.Stat(filepath.Join(tools, "rsync.argv"))
		if res.OK || res.Reason != nonPermitted || err == nil || published(t, feed) != "old\n" || asked.Load() <= entry {
			t.Fatalf("a rebound rsync host must be refused before rsync starts: %+v, rsync started: %v, published %q, %d lookups (%d at entry)",
				res, err == nil, published(t, feed), asked.Load(), entry)
		}
	})
}

// alive is a process that has not exited: a zombie awaiting its reaper is gone.
func alive(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) && b[i+2] == 'Z' {
			return false
		}
	}
	return true
}

// gone waits for the process to be dead: the pipe that ended Ingest closes a moment before the kernel finishes the exit.
// The bound only keeps a survivor from hanging the run.
func gone(pid int) bool {
	for range 1000 {
		if !alive(pid) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// ingestRsyncCancelled runs an Ingest of the stand-in `script` (installed as the rsync binary), cancels it once the
// stand-in has written every file in pidFiles (its directory is the stand-in's own), and returns the pids they hold
// after Ingest returned. A pid still alive at the end of a failing run is killed.
func ingestRsyncCancelled(t *testing.T, script string, pidFiles ...string) (feedfetch.Result, []int) {
	t.Helper()
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "rsync"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	f, feed := quickFetcher(t)
	f.RsyncBin = filepath.Join(tools, "rsync")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan feedfetch.Result, 1)
	go func() {
		done <- f.Ingest(ctx, feed, feedfetch.Request{URL: "rsync://feed.example/feeds/list.txt", Rsync: true})
	}()

	pids := make([]int, len(pidFiles))
	t.Cleanup(func() {
		for _, pid := range pids {
			if pid > 0 && alive(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	for i, name := range pidFiles {
		// A generous watchdog only: the stand-in writes its pids at once.
		for deadline := time.Now().Add(30 * time.Second); pids[i] == 0; time.Sleep(5 * time.Millisecond) {
			b, _ := os.ReadFile(filepath.Join(tools, name))
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 {
				pids[i] = n
			} else if time.Now().After(deadline) {
				cancel()
				<-done
				t.Fatalf("STUCK/ENVIRONMENT: the stand-in rsync never wrote %s", name)
			}
		}
	}
	cancel()
	return <-done, pids
}

// The deadline ends the whole process group: a descendant of rsync (the ssh of an rsync-over-ssh, here a sleep) dies
// with it. Without `Setpgid` only the shell is killed and the descendant lives on after WaitDelay closed the pipe.
func TestAnRsyncDescendantDiesWithItsParentAtTheDeadline(t *testing.T) {
	res, pids := ingestRsyncCancelled(t, "#!/bin/sh\n"+
		"dir=$(dirname \"$0\")\n"+
		"sleep 60 &\n"+
		"echo $! >\"${dir}/child.pid\"\n"+
		"echo $$ >\"${dir}/self.pid\"\n"+
		"wait\n", "child.pid", "self.pid")
	if res.OK {
		t.Fatalf("an rsync stopped at its deadline must not publish: %+v", res)
	}
	for i, name := range []string{"descendant", "rsync"} {
		if !gone(pids[i]) {
			t.Errorf("the %s (pid %d) survived the deadline", name, pids[i])
		}
	}
}

// A process that ignores SIGTERM is killed after the grace period, descendants included: only the group KILL reaches a
// descendant that ignores TERM too (the direct child is also killed by WaitDelay, the descendant is not).
func TestAnRsyncThatIgnoresTermIsKilledWithItsDescendants(t *testing.T) {
	res, pids := ingestRsyncCancelled(t, "#!/bin/sh\n"+
		"trap '' TERM\n"+
		"dir=$(dirname \"$0\")\n"+
		"sleep 60 &\n"+
		"echo $! >\"${dir}/child.pid\"\n"+
		"echo $$ >\"${dir}/self.pid\"\n"+
		"wait\n", "child.pid", "self.pid")
	if res.OK {
		t.Fatalf("an rsync killed at its deadline must not publish: %+v", res)
	}
	for i, name := range []string{"descendant", "rsync"} {
		if !gone(pids[i]) {
			t.Errorf("the %s (pid %d) that ignores TERM survived the KILL escalation", name, pids[i])
		}
	}
}

// rsync runs under twice the ceiling as a file-size limit (`ulimit -f` counts 512-byte blocks) and under its own 5 s
// I/O timeout, against the vetted address.
func TestRsyncRunsUnderTheFileSizeLimitAndItsIOTimeout(t *testing.T) {
	bin, tools := rsyncStandIn(t)
	f, feed := quickFetcher(t)
	f.RsyncBin = bin
	const ceiling = 1 << 20
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "rsync://feed.example/feeds/list.txt", Rsync: true, MaxBytes: ceiling, Timeout: 30 * time.Second})
	if !res.OK {
		t.Fatalf("ingest: %+v", res)
	}
	limit, _ := os.ReadFile(filepath.Join(tools, "rsync.ulimit"))
	if got, want := strings.TrimSpace(string(limit)), strconv.Itoa(ceiling/256); got != want {
		t.Errorf("rsync ran under `ulimit -f` %q, want %q (twice the %d-byte ceiling in 512-byte blocks)", got, want, ceiling)
	}
	argv, _ := os.ReadFile(filepath.Join(tools, "rsync.argv"))
	args := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
	if len(args) != 3 || args[0] != "--timeout=5" || args[1] != "rsync://127.0.0.1/feeds/list.txt" {
		t.Errorf("rsync arguments %q, want [--timeout=5 rsync://127.0.0.1/feeds/list.txt <destination>]", args)
	}
}

// A partial body from a failed attempt never reaches the published copy: the next attempt starts from an empty file
// (#1072). The partial body is longer than the full one, so a missing truncate and a missing rewind both show.
func TestARetryStartsFromAnEmptyBody(t *testing.T) {
	var calls atomic.Int32
	url, hits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Length", "64")
			io.WriteString(w, strings.Repeat("P", 32)) // closes short of its Content-Length
			return
		}
		io.WriteString(w, "full\n")
	})
	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:" + port(t, url) + "/list", Timeout: 10 * time.Second})
	if !res.OK || hits.Load() != 2 || published(t, feed) != "full\n" {
		t.Fatalf("the retry must publish exactly the full body: %+v after %d requests, published %q", res, hits.Load(), published(t, feed))
	}
}

// With a retry pause longer than the caller's deadline the first attempt is the only one: the pause ends with the
// context instead of being skipped. Counts only; a pause that was skipped lets attempts two and three through.
func TestARetryPauseEndsWithTheContext(t *testing.T) {
	url, hits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close() // no answer at all: the attempt fails
		}
	})
	f, feed := quickFetcher(t)
	f.RetryDelay = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := f.Ingest(ctx, feed, feedfetch.Request{URL: "http://feed.example:" + port(t, url) + "/list", Timeout: 10 * time.Second})
	if res.OK || res.Reason != "curl_incomplete" || hits.Load() != 1 {
		t.Fatalf("a retry pause past the deadline must leave one attempt: %+v after %d requests", res, hits.Load())
	}
}

// A final 221 or 226 is a published answer like a 200 (pfb_download: 200, 221, 226).
func TestStatus221And226ArePublished(t *testing.T) {
	for _, status := range []int{221, 226} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			url, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				io.WriteString(w, "ftp-style\n")
			})
			f, feed := quickFetcher(t)
			res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: "http://feed.example:" + port(t, url) + "/list", Timeout: 10 * time.Second})
			if !res.OK || res.Status != status || published(t, feed) != "ftp-style\n" {
				t.Fatalf("a %d answer must be published: %+v, published %q", status, res, published(t, feed))
			}
		})
	}
}

// The request leaves from the source address the Outpost configured.
func TestTheRequestLeavesFromTheBindAddress(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.2:0")
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("127.0.0.2 is not a loopback address on this host")
	} else if err != nil {
		t.Fatal(err)
	}
	probe.Close()

	var mu sync.Mutex
	var from []string
	url, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		mu.Lock()
		from = append(from, host)
		mu.Unlock()
		io.WriteString(w, "bound\n")
	})
	f, feed := quickFetcher(t)
	req := feedfetch.Request{URL: "http://feed.example:" + port(t, url) + "/list", Timeout: 10 * time.Second}
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("unbound ingest: %+v", res)
	}
	req.BindAddr = netip.MustParseAddr("127.0.0.2")
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("bound ingest: %+v", res)
	}
	if want := []string{"127.0.0.1", "127.0.0.2"}; fmt.Sprint(from) != fmt.Sprint(want) {
		t.Fatalf("the server saw the requests come from %v, want %v (without and with BindAddr)", from, want)
	}
}

// A local file is held to the ceiling like any download: exactly the ceiling is kept, one byte more is refused by name
// and the published copy stays.
func TestALocalFileOverTheCeilingIsRefused(t *testing.T) {
	src := t.TempDir()
	f, feed := quickFetcher(t)
	f.Policy.LocalDirs = []string{src}
	list := filepath.Join(src, "list.txt")
	req := feedfetch.Request{URL: "file://" + list, MaxBytes: 16}

	os.WriteFile(list, []byte("0123456789abcde\n"), 0o600) // 16 bytes
	if res := f.Ingest(context.Background(), feed, req); !res.OK || published(t, feed) != "0123456789abcde\n" {
		t.Fatalf("a file of exactly the ceiling must be published: %+v, published %q", res, published(t, feed))
	}
	os.WriteFile(list, []byte("0123456789abcdef\n"), 0o600) // 17 bytes
	res := f.Ingest(context.Background(), feed, req)
	if res.OK || res.Reason != "local_too_large" || published(t, feed) != "0123456789abcde\n" {
		t.Fatalf("a file over the ceiling must be refused, keeping the published copy: %+v, published %q", res, published(t, feed))
	}
	if _, err := os.Stat(filepath.Join(feed.Dir, "FEED.raw")); !os.IsNotExist(err) {
		t.Fatalf("the refused file's staged copy survived: %v", err)
	}
}

// A name that resolves only to ::1 is the host itself, however it is spelled, so it is fetched at the web root without
// the internal-address filter refusing it and refused below the root. (A bracketed [::1] literal is refused outright:
// entry-bracketed-ipv6.) Without ::1 among the loopbacks the filter would refuse the name as a private address.
func TestANameThatResolvesToLoopbackV6IsSelfHosted(t *testing.T) {
	ln6, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("::1 cannot listen here: %v", err)
	}
	// "localhost" may reach either loopback, so both answer.
	ln4, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(ln6.Addr().(*net.TCPAddr).Port))
	if err != nil {
		ln6.Close()
		t.Fatal(err)
	}
	var hits atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "v6\n")
	})}
	go srv.Serve(ln6)
	go srv.Serve(ln4)
	t.Cleanup(func() { srv.Close() })

	f, feed := quickFetcher(t)
	f.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("::1")}, nil
	}
	base := "http://localhost:" + strconv.Itoa(ln6.Addr().(*net.TCPAddr).Port)
	if res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: base + "/list", Timeout: 10 * time.Second}); !res.OK || published(t, feed) != "v6\n" {
		t.Fatalf("a self-hosted feed at the web root must be fetched: %+v, published %q", res, published(t, feed))
	}
	before := hits.Load()
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: base + "/dir/list", Timeout: 10 * time.Second})
	if res.OK || res.Reason != "" || hits.Load() != before {
		t.Fatalf("a self-hosted feed below the root is refused without a vet reason and without a request: %+v, %d new requests",
			res, hits.Load()-before)
	}
}

// sniffListener serves TLS and plain HTTP on one port, told apart by the first byte of a connection (0x16 opens a TLS
// handshake), so a redirect can change scheme and keep host and port.
type sniffListener struct {
	net.Listener
	cfg *tls.Config
}

type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (c *peeked) Read(p []byte) (int, error) { return c.r.Read(p) }

func (l sniffListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		br := bufio.NewReader(c)
		first, err := br.Peek(1)
		if err != nil {
			c.Close()
			continue
		}
		conn := &peeked{c, br}
		if first[0] == 0x16 {
			return tls.Server(conn, l.cfg), nil
		}
		return conn, nil
	}
}

// Credentials go to the origin only, and an origin is scheme, host and port (#1919, #1953): a redirect from https to
// http on the same host and port must drop them. Removing the scheme leg of the origin comparison sends them in clear.
func TestCredentialsAreNotSentOnToAnotherSchemeOfTheSameHostAndPort(t *testing.T) {
	seed := httptest.NewUnstartedServer(http.NotFoundHandler())
	seed.StartTLS() // only for its certificate: the test server below shares the port between TLS and plain HTTP
	cfg, cert := seed.TLS.Clone(), seed.Certificate()
	seed.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	var mu sync.Mutex
	var seen []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s tls=%v authorization=%q", r.URL.Path, r.TLS != nil, r.Header.Get("Authorization")))
		mu.Unlock()
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "http://example.com:"+p+"/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "scheme\n")
	})}
	go srv.Serve(sniffListener{ln, cfg})
	t.Cleanup(func() { srv.Close() })

	f, feed := quickFetcher(t)
	f.RootCAs = x509.NewCertPool()
	f.RootCAs.AddCert(cert)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "https://example.com:" + p + "/start", Username: "user", Password: "secret", Timeout: 10 * time.Second})
	want := []string{`/start tls=true authorization="Basic dXNlcjpzZWNyZXQ="`, `/next tls=false authorization=""`}
	mu.Lock()
	defer mu.Unlock()
	if !res.OK || published(t, feed) != "scheme\n" || fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("the https origin gets the credentials and the http hop none: %+v, published %q, hops %q, want %q",
			res, published(t, feed), seen, want)
	}
}

// A host name is case-blind (PHP compares origins with strcasecmp): a redirect to the same host in other letter case
// stays on the origin and keeps the credentials.
func TestARedirectToTheOriginInOtherLetterCaseKeepsTheCredentials(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s %s authorization=%q", r.URL.Path, r.Host, r.Header.Get("Authorization")))
		mu.Unlock()
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "http://FEED.Example:"+strings.TrimPrefix(r.Host, "feed.example:")+"/next")
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "case\n")
	}))
	defer srv.Close()
	p := port(t, srv.URL)

	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{
		URL: "http://feed.example:" + p + "/start", Username: "user", Password: "secret", Timeout: 10 * time.Second})
	want := []string{
		`/start feed.example:` + p + ` authorization="Basic dXNlcjpzZWNyZXQ="`,
		`/next FEED.Example:` + p + ` authorization="Basic dXNlcjpzZWNyZXQ="`,
	}
	mu.Lock()
	defer mu.Unlock()
	if !res.OK || published(t, feed) != "case\n" || fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("both hops are the origin and get the credentials: %+v, published %q, hops %q, want %q",
			res, published(t, feed), seen, want)
	}
}
