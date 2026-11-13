package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Hardening of the skeleton's fences: an error code outside the table, an unreadable caller credential, a socket
// directory Core must not take over, uid flags beyond 32 bits, and a mutating request whose caller goes away.

func TestAnErrorCodeOutsideTheTableIsAnsweredAsInternal(t *testing.T) {
	var runs atomic.Int64
	bad := func(context.Context, []byte) (any, error) { runs.Add(1); return nil, newError("typo_code", "x") }
	h := start(t, func(o *options) {
		o.methods["Bad"] = method{call: bad}
		o.methods["BadMutating"] = method{mutating: true, call: bad}
	}, nil)
	wantError(t, h.post("/v1/Bad", `{}`), http.StatusInternalServerError, "internal")
	// A mutating method's first answer is replayed: it must be a complete one, and the method still runs once
	wantError(t, h.post("/v1/BadMutating", `{"requestId":"t-1"}`), http.StatusInternalServerError, "internal")
	wantError(t, h.post("/v1/BadMutating", `{"requestId":"t-1"}`), http.StatusInternalServerError, "internal")
	if n := runs.Load(); n != 2 {
		t.Errorf("methods ran %d times, want 2", n)
	}
}

func TestACallerWhoseCredentialCannotBeReadIsRefused(t *testing.T) {
	// Given the reader fails while reporting uid 0, which is also the allowed uid: a refusal must not depend on the uid
	c := &counter{}
	h := start(t, func(o *options) {
		o.allowUID = 0
		o.peerUID = func(*net.UnixConn) (uint32, error) { return 0, errors.New("no credential") }
	}, c)
	wantError(t, h.post("/v1/GetVersion", `{}`), http.StatusUnauthorized, "unauthenticated")
	wantError(t, h.post("/v1/TestIncrement", `{"requestId":"a"}`), http.StatusUnauthorized, "unauthenticated")
	if n := c.runs.Load(); n != 0 {
		t.Errorf("TestIncrement ran %d times, want 0", n)
	}
}

func scratchDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenRefusesASocketDirectoryThatIsNotPrivate(t *testing.T) {
	// A shared directory (say /tmp, 1777) is never taken over: Core does not chmod it, it refuses to start
	run := filepath.Join(scratchDir(t), "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(options{socket: filepath.Join(run, "api.sock"), methods: productionMethods(), logf: t.Logf}); err == nil {
		t.Fatal("listen took over a shared directory")
	}
	info, err := os.Lstat(run)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModeSticky|os.ModePerm) != os.ModeSticky|0o777 {
		t.Errorf("the shared directory's mode changed to %v", info.Mode())
	}
}

func TestListenRefusesASymlinkedSocketDirectory(t *testing.T) {
	dir := scratchDir(t)
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "run")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(options{socket: filepath.Join(link, "api.sock"), methods: productionMethods(), logf: t.Logf}); err == nil {
		t.Fatal("listen accepted a symlink as the socket directory")
	}
}

func TestListenRefusesASocketDirectoryOwnedBySomeoneElse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handing a directory to another user needs root (the CI Go gate runs the tests as root)")
	}
	run := filepath.Join(scratchDir(t), "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(run, 12345, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(options{socket: filepath.Join(run, "api.sock"), methods: productionMethods(), logf: t.Logf}); err == nil {
		t.Fatal("listen used a directory another user owns")
	}
}

func TestSocketGroupHandsTheDirectoryAndSocketToThatGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("handing a file to a group the user is not in needs root (the CI Go gate runs the tests as root)")
	}
	gid := os.Getgid() + 1
	h := start(t, func(o *options) { o.socketGroup = gid; o.groupSet = true }, nil)
	for _, path := range []string{h.socket, filepath.Dir(h.socket)} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); int(st.Gid) != gid {
			t.Errorf("%s group = %d, want %d", path, st.Gid, gid)
		}
	}
}

func TestRunRefusesAUIDBeyond32Bits(t *testing.T) {
	// 4294967296 would wrap to uid 0 (root) in a 32-bit uid. A cancelled context: a run that wrongly starts stops at once.
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	for _, flag := range []string{"--allow-uid", "--client-uid"} {
		var stderr bytes.Buffer
		args := []string{"--socket", filepath.Join(scratchDir(t), "run", "api.sock"), flag, strconv.FormatUint(1<<32, 10)}
		if code := run(stopped, args, &stderr); code != 2 {
			t.Errorf("run %v = %d, want 2; stderr %q", args, code, stderr.String())
		}
	}
}

func TestAMutatingMethodFinishesWhenItsCallerGoesAway(t *testing.T) {
	// Given a mutating method that honours its context, called by a caller that is already gone (its request context is
	// cancelled before the handler runs: the deterministic form of a disconnect mid-call)
	var runs atomic.Int64
	h := start(t, func(o *options) {
		o.methods["Slow"] = method{mutating: true, call: func(ctx context.Context, params []byte) (any, error) {
			var p struct {
				RequestID string `json:"requestId"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return map[string]int64{"count": runs.Add(1)}, nil
		}}
	}, nil)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), peerKey{}, peer{uid: uint32(os.Getuid())}))
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/Slow", bytes.NewReader([]byte(`{"requestId":"g-1"}`)))
	h.srv.handle(httptest.NewRecorder(), req)
	// Then the method ran to its end: a retry of the same requestId gets its result
	wantJSON(t, h.post("/v1/Slow", `{"requestId":"g-1"}`), http.StatusOK, `{"count":1}`)
	if n := runs.Load(); n != 1 {
		t.Errorf("Slow completed %d times, want 1", n)
	}
}

func TestReplayNeverForgetsARequestStillRunning(t *testing.T) {
	// Given a cache of one entry whose only entry is still running
	cache := newReplayCache(1)
	var runs atomic.Int64
	release := make(chan struct{})
	first := make(chan response, 1)
	digest := [32]byte{1}
	go func() {
		first <- cache.do(context.Background(), "M", "a", digest, func() response {
			runs.Add(1)
			<-release
			return response{status: http.StatusOK, body: []byte(`{"n":1}`)}
		})
	}()
	waitFor(t, func() bool { return runs.Load() == 1 })
	// When another request arrives and fills the cache
	cache.do(context.Background(), "M", "b", digest, func() response { return response{status: http.StatusOK} })
	// Then a repeat of the running one still waits for it rather than running it again
	repeat := make(chan response, 1)
	go func() {
		repeat <- cache.do(context.Background(), "M", "a", digest, func() response {
			runs.Add(1)
			return response{status: http.StatusTeapot}
		})
	}()
	waitFor(t, func() bool { return cache.waiting("M", "a") == 1 || runs.Load() > 1 })
	close(release)
	got := <-repeat
	<-first
	if runs.Load() != 1 || got.status != http.StatusOK {
		t.Errorf("the running request ran %d times and its repeat got %d, want 1 run and the first's 200", runs.Load(), got.status)
	}
}

// limits is what listen configured on the HTTP server (docs/misc/core-api-protocol.md, Limits and timeouts).
type limits struct {
	readHeader, read, write, idle time.Duration
	maxHeaderBytes                int
	maxBody                       int64
}

func limitsOf(s *server) limits {
	return limits{s.http.ReadHeaderTimeout, s.http.ReadTimeout, s.http.WriteTimeout, s.http.IdleTimeout, s.http.MaxHeaderBytes, s.o.maxBody}
}

func TestListenDefaultsAreTheDocumentedLimits(t *testing.T) {
	h := start(t, nil, nil)
	want := limits{readHeader: 5 * time.Second, read: 10 * time.Second, write: 45 * time.Second, idle: 60 * time.Second, maxHeaderBytes: 16384, maxBody: 1 << 20}
	if got := limitsOf(h.srv); got != want {
		t.Errorf("limits = %+v, want %+v", got, want)
	}
}

func TestListenTakesItsLimitsFromItsOptions(t *testing.T) {
	h := start(t, func(o *options) {
		o.readHeaderTimeout, o.readTimeout, o.idleTimeout = 1*time.Second, 2*time.Second, 3*time.Second
		o.maxHeaderBytes, o.maxBody = 4096, 2048
	}, nil)
	want := limits{readHeader: 1 * time.Second, read: 2 * time.Second, write: 45 * time.Second, idle: 3 * time.Second, maxHeaderBytes: 4096, maxBody: 2048}
	if got := limitsOf(h.srv); got != want {
		t.Errorf("limits = %+v, want %+v", got, want)
	}
}

// rawConn is a client connection for a hand-written HTTP exchange; its deadline is the outer salvage watchdog only.
func rawConn(t *testing.T, h *harness) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(watchdog))
	return conn
}

// notStuck fails the test when err is the watchdog expiring: the server kept open what it had to close by itself.
func notStuck(t *testing.T, err error, what string) {
	t.Helper()
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("STUCK: the server kept %s open past the %v watchdog", what, watchdog)
	}
}

func TestStalledRequestBodyIsCutOff(t *testing.T) {
	h := start(t, func(o *options) { o.readTimeout = 50 * time.Millisecond }, nil)
	conn := rawConn(t, h)
	// The header is complete and promises 10 body bytes; 1 comes and no more
	if _, err := conn.Write([]byte("POST /v1/GetVersion HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nx")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	notStuck(t, err, "a request whose body never ended")
	if bytes.Contains(got, []byte("200 OK")) {
		t.Errorf("a request whose body never ended was answered: %q", got)
	}
}

func TestAnIdleKeepAliveConnectionIsClosed(t *testing.T) {
	h := start(t, func(o *options) { o.idleTimeout = 50 * time.Millisecond }, nil)
	conn := rawConn(t, h)
	br := bufio.NewReader(conn)
	if _, err := conn.Write([]byte("POST /v1/GetVersion HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the first reply: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first reply status = %d, want 200", resp.StatusCode)
	}
	// The reply is complete and nothing else is sent: the server must hang up by itself
	_, err = br.ReadByte()
	notStuck(t, err, "an idle keep-alive connection")
	if !errors.Is(err, io.EOF) {
		t.Errorf("reading an idle connection = %v, want io.EOF (closed by the server)", err)
	}
}

func TestAHeaderOverMaxHeaderBytesIsRefused(t *testing.T) {
	h := start(t, func(o *options) { o.maxHeaderBytes = 1024 }, nil)
	conn := rawConn(t, h)
	// net/http reads a few KiB beyond MaxHeaderBytes before it refuses: the pad is far beyond that, yet below the default
	pad := strings.Repeat("a", 8<<10)
	if _, err := conn.Write([]byte("POST /v1/GetVersion HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nX-Pad: " + pad + "\r\n\r\n{}")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	notStuck(t, err, "an oversized header")
	if err != nil {
		t.Fatalf("reading the reply: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}

func TestAPanickingMethodIsAnInternalErrorAndLogged(t *testing.T) {
	var logs syncBuffer
	h := start(t, func(o *options) {
		o.methods["Boom"] = method{call: func(context.Context, []byte) (any, error) { panic("kaboom") }}
		o.logf = func(format string, args ...any) { fmt.Fprintf(&logs, format+"\n", args...) }
	}, nil)
	wantError(t, h.post("/v1/Boom", `{}`), http.StatusInternalServerError, "internal")
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "Boom") && strings.Contains(line, "panicked") {
			return
		}
	}
	t.Errorf("no log line names the method and says it panicked; log:\n%s", logs.String())
}

func TestEveryAnswerIsNotCacheable(t *testing.T) {
	h := start(t, nil, nil)
	for _, c := range []struct {
		name, path string
		status     int
	}{{"a result", "/v1/GetVersion", http.StatusOK}, {"an error", "/v1/NoSuchMethod", http.StatusNotFound}} {
		t.Run(c.name, func(t *testing.T) {
			got := h.post(c.path, `{}`)
			if got.status != c.status {
				t.Fatalf("status = %d, want %d (body %s)", got.status, c.status, got.body)
			}
			if cc := got.header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

func TestRequestIDIsPrintableASCIIWithoutSpaces(t *testing.T) {
	c := &counter{}
	h := start(t, nil, c)
	body := func(id string) string {
		b, _ := json.Marshal(map[string]string{"requestId": id})
		return string(b)
	}
	// The ends of the printable range 0x21 to 0x7e: just outside it is refused, on it is accepted
	refused := []string{"a b", "a\x7f", "a\u00e9"}
	accepted := []string{"!", "~"}
	for _, id := range refused {
		t.Run("refuses "+strconv.QuoteToASCII(id), func(t *testing.T) {
			wantError(t, h.post("/v1/TestIncrement", body(id)), http.StatusBadRequest, "invalid_argument", "requestId")
		})
	}
	for _, id := range accepted {
		t.Run("accepts "+strconv.QuoteToASCII(id), func(t *testing.T) {
			if got := h.post("/v1/TestIncrement", body(id)); got.status != http.StatusOK {
				t.Errorf("status = %d, want 200 (body %s)", got.status, got.body)
			}
		})
	}
	if n := c.runs.Load(); n != int64(len(accepted)) {
		t.Errorf("TestIncrement ran %d times, want %d (only the accepted requestIds)", n, len(accepted))
	}
}

func TestDecodeParamsNamesTheFieldOfAWrongTypedValue(t *testing.T) {
	var p struct {
		A int `json:"a"`
	}
	err := decodeParams([]byte(`{"a":"x"}`), &p)
	var e *apiError
	if !errors.As(err, &e) {
		t.Fatalf("error = %v (%T), want an *apiError", err, err)
	}
	want := []fieldError{{Field: "a", Message: "must be a JSON int"}}
	if e.Code != codeInvalidArgument || !reflect.DeepEqual(e.FieldErrors, want) {
		t.Errorf("error code %q with fields %+v, want %q with %+v", e.Code, e.FieldErrors, codeInvalidArgument, want)
	}
}
