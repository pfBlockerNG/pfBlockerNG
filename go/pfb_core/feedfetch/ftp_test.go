package feedfetch_test

// What the ftp client does that the parity corpus cannot say: its source address (the corpus's Python server records
// what it was sent, not who sent it), a transfer after the host turned private, a reply without end, a feed cURL would
// handle differently on purpose (a proxy, a URL that names no file), and a cancelled context. The ftp rows of the corpus
// are the proof for everything cURL does the same way.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	ln    net.Listener
	hits  atomic.Int32   // control connections
	greet func(net.Conn) // replaces the whole session when set
	mu    sync.Mutex
	from  []string // the source address of every control and data connection, in order of arrival
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
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		cmd, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			io.WriteString(c, "331 password\r\n")
		case "PASS":
			io.WriteString(c, "230 in\r\n")
		case "EPSV":
			if data, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
				return
			}
			fmt.Fprintf(c, "229 Entering Extended Passive Mode (|||%d|)\r\n", data.Addr().(*net.TCPAddr).Port)
		case "SIZE":
			io.WriteString(c, "213 5\r\n")
		case "RETR":
			io.WriteString(c, "150 go\r\n")
			dc, err := data.Accept()
			if err != nil {
				return
			}
			s.note(dc)
			io.WriteString(dc, "stub\n")
			dc.Close()
			io.WriteString(c, "226 done\r\n")
		case "QUIT":
			io.WriteString(c, "221 bye\r\n")
			return
		default: // TYPE, MDTM
			io.WriteString(c, "200 ok\r\n")
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
	entry := entryLookups(t, req)

	stable, stableFeed := quickFetcher(t)
	if res := stable.Ingest(context.Background(), stableFeed, req); !res.OK || stub.hits.Load() != 1 {
		t.Fatalf("with a stable answer the feed must be fetched: %+v, %d connections", res, stub.hits.Load())
	}

	f, feed := quickFetcher(t)
	os.WriteFile(filepath.Join(feed.Dir, "FEED.orig"), []byte("old\n"), 0o600)
	asked := rebindAfter(f, entry)
	res := f.Ingest(context.Background(), feed, req)
	if res.OK || res.Reason != nonPermitted || stub.hits.Load() != 1 || published(t, feed) != "old\n" || asked.Load() <= entry {
		t.Fatalf("a rebound host must be refused at transfer time: %+v, %d connections in all (1 before), published %q, %d lookups (%d at entry)",
			res, stub.hits.Load(), published(t, feed), asked.Load(), entry)
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

// cURL fetches ftp through an HTTP proxy by asking the proxy; the client here cannot, and must not go around it.
func TestAnFTPFeedIsNotFetchedAroundTheProxy(t *testing.T) {
	stub := newFTPStub(t, nil)
	f, feed := quickFetcher(t)
	f.Proxy, _ = url.Parse("http://127.0.0.1:1")
	res := f.Ingest(context.Background(), feed, ftpFeed(stub, "/list.txt"))
	if res.OK || res.Reason != "ftp is not supported through a proxy" || stub.hits.Load() != 0 {
		t.Fatalf("an ftp feed under a proxy must be refused without a connection: %+v, %d connections", res, stub.hits.Load())
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
	if res := f.Ingest(ctx, feed, req); res.OK || published(t, feed) != "<none>" {
		t.Fatalf("a transfer whose context ended must fail without publishing: %+v, published %q", res, published(t, feed))
	}
}
