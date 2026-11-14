package feedfetch_test

// What the ftp client does that the parity corpus cannot say: its source address (the corpus's Python server records
// what it was sent, not who sent it), a transfer after the host turned private, a reply without end, a self-hosted URL
// (PHP reads that one by another route), a proxy (the corpus has no proxy fixture on the PHP side yet), an attempt that
// changes between tries, a URL that names no file (cURL lists the directory, this client refuses), and a cancelled
// context. The ftp rows of the corpus are the proof for everything cURL does the same way.

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

// ftpStub is a one-file ftp server on 127.0.0.1 ("stub\n" for any RETR) that records where each connection came from.
type ftpStub struct {
	ln      net.Listener
	hits    atomic.Int32                         // control connections
	retrs   atomic.Int32                         // RETR commands
	greet   func(net.Conn)                       // replaces the whole session when set
	replies map[string]string                    // a command's reply line instead of the stub's own; {port}, {hi}, {lo} in EPSV and PASV
	retr    func(n int) (body string, drop bool) // the data of the n-th RETR (from 1); drop ends both connections after it
	mu      sync.Mutex
	from    []string // the source address of every control and data connection, in order of arrival
}

func newFTPStub(t *testing.T, greet func(net.Conn)) *ftpStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ftpStub{ln: ln, greet: greet}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.session(c)
		}
	}()
	return s
}

func (s *ftpStub) url(path string) string {
	return "ftp://feed.example:" + strconv.Itoa(s.ln.Addr().(*net.TCPAddr).Port) + path
}

func (s *ftpStub) note(c net.Conn) {
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	s.mu.Lock()
	s.from = append(s.from, host)
	s.mu.Unlock()
}

func (s *ftpStub) sources() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.from...)
}

func (s *ftpStub) session(c net.Conn) {
	defer c.Close()
	s.hits.Add(1)
	s.note(c)
	if s.greet != nil {
		s.greet(c)
		return
	}
	var data net.Listener
	defer func() {
		if data != nil {
			data.Close()
		}
	}()
	io.WriteString(c, "220 stub\r\n")
	in := bufio.NewReader(c)
	reply := func(cmd, own string, port int) {
		if custom, ok := s.replies[cmd]; ok {
			own = custom
		}
		own = strings.NewReplacer("{port}", strconv.Itoa(port), "{hi}", strconv.Itoa(port>>8), "{lo}", strconv.Itoa(port&255)).Replace(own)
		io.WriteString(c, own+"\r\n")
	}
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		cmd, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch cmd = strings.ToUpper(cmd); cmd {
		case "USER":
			reply(cmd, "331 password", 0)
		case "PASS":
			reply(cmd, "230 in", 0)
		case "EPSV", "PASV":
			if data != nil {
				data.Close()
			}
			if data, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
				return
			}
			own := "229 Entering Extended Passive Mode (|||{port}|)"
			if cmd == "PASV" {
				own = "227 Entering Passive Mode (127,0,0,1,{hi},{lo})"
			}
			reply(cmd, own, data.Addr().(*net.TCPAddr).Port)
		case "SIZE":
			reply(cmd, "213 5", 0)
		case "RETR":
			body, drop := "stub\n", false
			if s.retr != nil {
				body, drop = s.retr(int(s.retrs.Add(1)))
			}
			io.WriteString(c, "150 go\r\n")
			dc, err := data.Accept()
			if err != nil {
				return
			}
			s.note(dc)
			io.WriteString(dc, body)
			dc.Close()
			if drop {
				return // no 226: the deferred close ends the control connection too
			}
			reply("RETR_END", "226 done", 0)
		case "QUIT":
			io.WriteString(c, "221 bye\r\n")
			return
		default: // TYPE, MDTM
			reply(cmd, "200 ok", 0)
		}
	}
}

// ftpFeed is a request for path on the stub, with the transfer limits a test run needs.
func ftpFeed(s *ftpStub, path string) feedfetch.Request {
	return feedfetch.Request{URL: s.url(path), Timeout: 10 * time.Second}
}

func TestAnFTPFeedIsFetchedFromTheStub(t *testing.T) {
	stub := newFTPStub(t, nil)
	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt"))
	if !res.OK || published(t, feed) != "stub\n" || res.Status != 226 {
		t.Fatalf("the stub's file must be published with the 226 that ended the transfer: %+v, published %q", res, published(t, feed))
	}
}
func TestFailedIngestDropsFTPSizeSidecar(t *testing.T) {
	stub := newFTPStub(t, func(c net.Conn) { io.WriteString(c, "500 refused\r\n") })
	f, feed := quickFetcher(t)
	if err := os.WriteFile(filepath.Join(feed.Dir, feed.Name+".orig.size"), []byte("5"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt"))
	if res.OK {
		t.Fatalf("failed FTP ingest unexpectedly succeeded: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(feed.Dir, feed.Name+".orig.size")); !os.IsNotExist(err) {
		t.Fatalf("failed ingest must drop the SIZE baseline, stat error %v", err)
	}
}

// Both connections of a transfer leave from the source address the Outpost configured (CURLOPT_INTERFACE covers the
// data connection too).
func TestTheFTPConnectionsLeaveFromTheBindAddress(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.2:0")
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("127.0.0.2 is not a loopback address on this host")
	} else if err != nil {
		t.Fatal(err)
	}
	probe.Close()

	stub := newFTPStub(t, nil)
	f, feed := quickFetcher(t)
	req := ftpFeed(stub, "/list.txt")
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("unbound ingest: %+v", res)
	}
	req.BindAddr = netip.MustParseAddr("127.0.0.2")
	if res := f.Ingest(context.Background(), feed, req); !res.OK {
		t.Fatalf("bound ingest: %+v", res)
	}
	want := []string{"127.0.0.1", "127.0.0.1", "127.0.0.2", "127.0.0.2"}
	if got := stub.sources(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the stub saw its control and data connections come from %v, want %v (without and with BindAddr)", got, want)
	}
}

// The transfer vets the host again, so a name that turns private after the entry gate (DNS rebinding) is never dialled.
func TestAnFTPHostThatTurnsPrivateAfterTheEntryGateIsRefusedAtTransferTime(t *testing.T) {
	stub := newFTPStub(t, nil)
	// "localhost" resolves for the system too, so a transfer that skipped its own vet would reach the stub.
	req := ftpFeed(stub, "/list.txt")
	req.URL = strings.Replace(req.URL, "feed.example", "localhost", 1)
	entry := entryLookups(t, req) - 1 // the calibration FTP probe also re-vets at transfer time
	entryHits := stub.hits.Load()
	if entryHits != 1 {
		t.Fatalf("a probe without a published baseline must RETR once, got %d connections", entryHits)
	}

	stable, stableFeed := quickFetcher(t)
	if res := stable.Ingest(context.Background(), stableFeed, req); !res.OK || stub.hits.Load() != entryHits+1 {
		t.Fatalf("with a stable answer the feed must be fetched: %+v, %d connections after %d from the entry probe", res, stub.hits.Load(), entryHits)
	}

	before := stub.hits.Load()
	f, feed := quickFetcher(t)
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
	asked := rebindAfter(f, entry)
	res := f.Ingest(context.Background(), feed, req)
	if res.OK || res.Reason != nonPermitted || stub.hits.Load() != before || published(t, feed) != "old\n" || asked.Load() <= entry {
		t.Fatalf("a rebound host must be refused at transfer time: %+v, %d connections in all (no new connection after %d), published %q, %d lookups (%d at entry)",
			res, stub.hits.Load(), before, published(t, feed), asked.Load(), entry)
	}
}

// A reply whose continuation lines never end is cut off after a bounded read, not buffered until the transfer deadline.
func TestAnFTPReplyWithoutAnEndIsCutOff(t *testing.T) {
	const flood = 64 << 20
	var sent atomic.Int64
	stub := newFTPStub(t, func(c net.Conn) {
		chunk := []byte(strings.Repeat("220-never ends\r\n", 4096))
		for sent.Load() < flood {
			n, err := c.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
		io.Copy(io.Discard, c) // all of it was read: wait for the client to give up
	})
	f, feed := quickFetcher(t)
	req := ftpFeed(stub, "/list.txt")
	req.Timeout = 2 * time.Second
	res := f.Ingest(context.Background(), feed, req)
	if res.OK || res.Reason != "curl_incomplete" || sent.Load() >= flood/2 {
		t.Fatalf("a reply without an end must fail the attempts after a bounded read: %+v, the server wrote %d of %d bytes",
			res, sent.Load(), int64(flood))
	}
}

// cURL fetches ftp through an HTTP proxy by asking the proxy for the ftp URL itself: an absolute-form GET, no CONNECT,
// the proxy's credentials as for http and the feed's as Basic. The proxy's answer is an HTTP answer, retried and held to
// the ceiling like one, and the ftp server is never dialled.
func TestAnFTPFeedIsFetchedThroughTheProxyAsAnHTTPRequest(t *testing.T) {
	stub := newFTPStub(t, nil)
	var mu sync.Mutex
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.RequestURI+" "+r.Header.Get("Proxy-Authorization")+" "+r.Header.Get("Authorization"))
		first := len(seen) == 1
		mu.Unlock()
		if first {
			if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
				c.Close() // no answer: the first attempt fails
			}
			return
		}
		io.WriteString(w, "via proxy\n")
	}))
	defer proxy.Close()

	f, feed := quickFetcher(t)
	f.Proxy, _ = url.Parse(proxy.URL)
	f.Proxy.User = url.UserPassword("puser", "ppass")
	req := ftpFeed(stub, "/list.txt")
	req.Username, req.Password = "u", "p"
	res := f.Ingest(context.Background(), feed, req)
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	line := "GET " + req.URL + " " + basic("puser:ppass") + " " + basic("u:p")
	if !res.OK || res.Status != 200 || published(t, feed) != "via proxy\n" || fmt.Sprint(seen) != fmt.Sprint([]string{line, line}) ||
		stub.hits.Load() != 0 {
		t.Fatalf("the feed must come from the proxy on the second attempt: %+v, published %q, proxy saw %q, want twice %q, %d ftp connections",
			res, published(t, feed), seen, line, stub.hits.Load())
	}

	f, feed = quickFetcher(t)
	f.Proxy, _ = url.Parse(proxy.URL)
	req.MaxBytes = 4
	if res := f.Ingest(context.Background(), feed, req); res.OK || res.Reason != "download_too_large" || published(t, feed) != "<none>" {
		t.Fatalf("the proxy's answer over the ceiling must be refused: %+v, published %q", res, published(t, feed))
	}
}

// A self-hosted ftp URL at the web root is fetched by the ftp client (PHP reads it with its ftp stream wrapper); one in a
// subdirectory is refused before any connection, as PHP refuses it.
func TestASelfHostedFTPFeedAtTheWebRootIsFetchedOverFTP(t *testing.T) {
	stub := newFTPStub(t, nil)
	self := "ftp://127.0.0.1:" + strconv.Itoa(stub.ln.Addr().(*net.TCPAddr).Port)
	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, feedfetch.Request{URL: self + "/list.txt", Timeout: 10 * time.Second})
	if !res.OK || res.Status != 226 || published(t, feed) != "stub\n" {
		t.Fatalf("a self-hosted ftp feed at the web root must be fetched over ftp: %+v, published %q", res, published(t, feed))
	}
	f, feed = quickFetcher(t)
	res = f.Ingest(context.Background(), feed, feedfetch.Request{URL: self + "/dir/list.txt", Timeout: 10 * time.Second})
	if res.OK || stub.hits.Load() != 1 {
		t.Fatalf("a self-hosted ftp feed in a subdirectory must be refused without a connection: %+v, %d connections in all (1 before)",
			res, stub.hits.Load())
	}
}

// A partial body from a failed attempt never reaches the published copy: the next attempt starts from an empty file
// (#1072). The server knows no SIZE and the partial body is longer than the full one, so a missing truncate and a
// missing rewind both show.
func TestAnFTPRetryStartsFromAnEmptyBody(t *testing.T) {
	stub := newFTPStub(t, nil)
	stub.replies = map[string]string{"SIZE": "502 SIZE not implemented"}
	stub.retr = func(n int) (string, bool) {
		if n == 1 {
			return strings.Repeat("P", 32), true
		}
		return "full\n", false
	}
	f, feed := quickFetcher(t)
	res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt"))
	if !res.OK || stub.retrs.Load() != 2 || published(t, feed) != "full\n" {
		t.Fatalf("the retry must publish exactly the full body: %+v after %d RETRs, published %q", res, stub.retrs.Load(), published(t, feed))
	}
}

// An MDTM at or before the epoch is no modification time, as PHP skips a filetime that is not positive: the published
// copy keeps the time it was written.
func TestAnFTPModificationTimeAtOrBeforeTheEpochIsNotApplied(t *testing.T) {
	for _, mdtm := range []string{"19700101000000", "19691231000000"} {
		stub := newFTPStub(t, nil)
		stub.replies = map[string]string{"MDTM": "213 " + mdtm}
		f, feed := quickFetcher(t)
		res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt"))
		info, err := os.Stat(filepath.Join(feed.Dir, feed.Name+".orig"))
		if !res.OK || err != nil || info.ModTime().Unix() <= 0 {
			t.Fatalf("MDTM %s must not become the published copy's time: %+v, stat %v, mtime %v", mdtm, res, err, info)
		}
	}
}

// The context ends a transfer that waits on a reply forever. A transfer that ignored it would hang: the watchdog fails
// the test instead of letting it run into go test's own timeout (it guards a hang, it measures nothing).
func TestACancelledContextEndsAnFTPTransfer(t *testing.T) {
	accepted := make(chan struct{})
	var once sync.Once
	stub := newFTPStub(t, func(c net.Conn) {
		io.WriteString(c, "220 stub\r\n")
		bufio.NewReader(c).ReadString('\n') // the login has begun: the client is past its dial and waits for the reply
		once.Do(func() { close(accepted) })
		io.Copy(io.Discard, c) // never replies: the client gives up when its context ends
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-accepted
		cancel()
	}()
	f, feed := quickFetcher(t)
	req := ftpFeed(stub, "/list.txt")
	req.Timeout = time.Hour
	done := make(chan feedfetch.Result, 1)
	go func() { done <- f.Ingest(ctx, feed, req) }()
	select {
	case res := <-done:
		if res.OK || published(t, feed) != "<none>" {
			t.Fatalf("a transfer whose context ended must fail without publishing: %+v, published %q", res, published(t, feed))
		}
	case <-time.After(time.Minute):
		t.Fatal("the transfer did not end with its context")
	}
}

// cURL lists a directory when the URL names no file; this client only retrieves files.
func TestAnFTPURLThatNamesNoFileIsRefused(t *testing.T) {
	stub := newFTPStub(t, nil)
	for _, path := range []string{"", "/", "/dir/", "/dir/%2e%2e/", "/dir/.."} {
		f, feed := quickFetcher(t)
		res := f.Ingest(context.Background(), feed, ftpFeed(stub, path))
		if res.OK || res.Reason != "feed ftp URL names no file" || stub.hits.Load() != 0 {
			t.Fatalf("the URL %q names no file and must be refused without a connection: %+v, %d connections", path, res, stub.hits.Load())
		}
	}
}
