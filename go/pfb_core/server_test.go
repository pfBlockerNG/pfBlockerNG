package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Outer salvage watchdog for one exchange with the server: it only unsticks a hung test, it is never an assertion about duration.
const watchdog = 30 * time.Second

// counter is the test-only mutating method: every execution adds one and answers the new count.
type counter struct {
	runs    atomic.Int64
	release chan struct{} // nil: answer at once; else each execution waits for it (a concurrent duplicate can arrive meanwhile)
	entered chan struct{} // nil, or told once per execution that it started
}

func (c *counter) method() method {
	return method{mutating: true, call: func(ctx context.Context, params []byte) (any, error) {
		var p struct {
			RequestID string `json:"requestId"`
			Add       int64  `json:"add"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if c.entered != nil {
			c.entered <- struct{}{}
		}
		if c.release != nil {
			<-c.release
		}
		return map[string]int64{"count": c.runs.Add(1)}, nil
	}}
}

type harness struct {
	t       *testing.T
	srv     *server
	socket  string
	client  *http.Client
	done    chan error
	stopped bool
}

// start serves the production methods plus the test-only mutating TestIncrement on a fresh private socket.
func start(t *testing.T, edit func(*options), c *counter) *harness {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfbcore") // short: a Unix socket path is limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "run", "api.sock")
	methods := productionMethods()
	if c != nil {
		methods["TestIncrement"] = c.method()
	}
	o := options{socket: socket, allowUID: uint32(os.Getuid()), methods: methods, logf: t.Logf}
	if edit != nil {
		edit(&o)
	}
	socket = o.socket
	srv, err := listen(o)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := &harness{t: t, srv: srv, socket: socket, done: make(chan error, 1)}
	go func() { h.done <- srv.serve() }()
	t.Cleanup(h.stop)
	h.client = &http.Client{Timeout: watchdog, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	return h
}

// stop shuts the server down once (later calls do nothing) and checks that serve returned cleanly.
func (h *harness) stop() {
	h.t.Helper()
	if h.stopped {
		return
	}
	h.stopped = true
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	defer cancel()
	if err := h.srv.shutdown(ctx); err != nil {
		h.t.Errorf("shutdown: %v", err)
	}
	if err := <-h.done; err != nil {
		h.t.Errorf("serve returned %v after shutdown, want nil", err)
	}
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (h *harness) do(httpMethod, path, body string) reply {
	h.t.Helper()
	req, err := http.NewRequest(httpMethod, "http://pfb-core"+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", httpMethod, path, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("%s %s: reading the reply: %v", httpMethod, path, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: got}
}

func (h *harness) post(path, body string) reply {
	h.t.Helper()
	return h.do(http.MethodPost, path, body)
}

// wantJSON compares the reply with the documented one: the status, the JSON content type and the body, as JSON values.
func wantJSON(t *testing.T, got reply, status int, body string) {
	t.Helper()
	if got.status != status {
		t.Errorf("status = %d, want %d (body %s)", got.status, status, got.body)
	}
	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var have, want any
	if err := json.Unmarshal(got.body, &have); err != nil {
		t.Fatalf("reply body is not JSON: %v\n%s", err, got.body)
	}
	if err := json.Unmarshal([]byte(body), &want); err != nil {
		t.Fatalf("bad expectation %s: %v", body, err)
	}
	h, _ := json.Marshal(have)
	w, _ := json.Marshal(want)
	if !bytes.Equal(h, w) {
		t.Errorf("body:\n have %s\n want %s", h, w)
	}
}

// wantError checks the one error envelope: the code's documented HTTP status, the code, and a non-empty message.
func wantError(t *testing.T, got reply, status int, code string, fields ...string) {
	t.Helper()
	if got.status != status {
		t.Errorf("status = %d, want %d (body %s)", got.status, status, got.body)
	}
	if ct := got.header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var env struct {
		Error struct {
			Code        string `json:"code"`
			Message     string `json:"message"`
			FieldErrors []struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			} `json:"fieldErrors"`
		} `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(got.body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("reply is not the error envelope: %v\n%s", err, got.body)
	}
	if env.Error.Code != code {
		t.Errorf("error code = %q, want %q (body %s)", env.Error.Code, code, got.body)
	}
	if env.Error.Message == "" {
		t.Errorf("error message is empty (body %s)", got.body)
	}
	var have []string
	for _, f := range env.Error.FieldErrors {
		if f.Message == "" {
			t.Errorf("field error %q has no message", f.Field)
		}
		have = append(have, f.Field)
	}
	if strings.Join(have, ",") != strings.Join(fields, ",") {
		t.Errorf("fieldErrors fields = %q, want %q (body %s)", have, fields, got.body)
	}
}

const versionReply = `{"service":"pfblockerng-core","apiVersion":"v1","status":"serving"}`

func TestGetVersionAnswersTheDocumentedResponse(t *testing.T) {
	h := start(t, nil, nil)
	wantJSON(t, h.post("/v1/GetVersion", `{}`), http.StatusOK, versionReply)
	// An empty body is the empty parameter object, so `curl -X POST` alone asks for the version
	wantJSON(t, h.post("/v1/GetVersion", ``), http.StatusOK, versionReply)
}

func TestMalformedJSONIsInvalidArgument(t *testing.T) {
	h := start(t, nil, nil)
	for _, body := range []string{`{"x":`, `not json`, `[]`, `"text"`, `{} {}`, `null`} {
		t.Run(body, func(t *testing.T) {
			wantError(t, h.post("/v1/GetVersion", body), http.StatusBadRequest, "invalid_argument")
		})
	}
}

func TestUnknownParameterIsAFieldError(t *testing.T) {
	h := start(t, nil, nil)
	wantError(t, h.post("/v1/GetVersion", `{"bogus":1}`), http.StatusBadRequest, "invalid_argument", "bogus")
}

func TestUnknownMethodOrVersionIsNotFound(t *testing.T) {
	h := start(t, nil, nil)
	for _, path := range []string{"/v1/NoSuchMethod", "/v2/GetVersion", "/GetVersion", "/v1/", "/v1/GetVersion/extra"} {
		t.Run(path, func(t *testing.T) {
			wantError(t, h.post(path, `{}`), http.StatusNotFound, "not_found")
		})
	}
}

func TestOnlyPostIsAllowed(t *testing.T) {
	h := start(t, nil, nil)
	got := h.do(http.MethodGet, "/v1/GetVersion", "")
	wantError(t, got, http.StatusMethodNotAllowed, "method_not_allowed")
	if allow := got.header.Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestOversizedBodyIsPayloadTooLarge(t *testing.T) {
	const limit = 64
	h := start(t, func(o *options) { o.maxBody = limit }, nil)
	fits := `{}` + strings.Repeat(" ", limit-2)
	wantJSON(t, h.post("/v1/GetVersion", fits), http.StatusOK, versionReply)
	wantError(t, h.post("/v1/GetVersion", fits+" "), http.StatusRequestEntityTooLarge, "payload_too_large")
}

func TestDefaultBodyLimitIsOneMebibyte(t *testing.T) {
	h := start(t, nil, nil)
	fits := `{}` + strings.Repeat(" ", 1<<20-2)
	wantJSON(t, h.post("/v1/GetVersion", fits), http.StatusOK, versionReply)
	wantError(t, h.post("/v1/GetVersion", fits+" "), http.StatusRequestEntityTooLarge, "payload_too_large")
}

func TestUnauthenticatedCallerIsRefusedBeforeTheMethodRuns(t *testing.T) {
	// Given the caller's uid is the allowed one, the call runs
	c := &counter{}
	allowed := start(t, nil, c)
	wantJSON(t, allowed.post("/v1/TestIncrement", `{"requestId":"a"}`), http.StatusOK, `{"count":1}`)

	// When the kernel reports a caller uid that is not the allowed one, every method is refused and nothing runs
	refused := start(t, func(o *options) { o.allowUID = uint32(os.Getuid()) + 1 }, c)
	wantError(t, refused.post("/v1/GetVersion", `{}`), http.StatusUnauthorized, "unauthenticated")
	wantError(t, refused.post("/v1/TestIncrement", `{"requestId":"b"}`), http.StatusUnauthorized, "unauthenticated")
	if n := c.runs.Load(); n != 1 {
		t.Errorf("TestIncrement ran %d times, want 1 (the refused call must not run)", n)
	}
}

func TestRepeatedRequestIDReplaysTheFirstResult(t *testing.T) {
	c := &counter{}
	h := start(t, nil, c)
	first := h.post("/v1/TestIncrement", `{"requestId":"r-1","add":1}`)
	wantJSON(t, first, http.StatusOK, `{"count":1}`)
	second := h.post("/v1/TestIncrement", `{"requestId":"r-1","add":1}`)
	wantJSON(t, second, http.StatusOK, `{"count":1}`)
	if !bytes.Equal(first.body, second.body) {
		t.Errorf("replay body %s differs from the first %s", second.body, first.body)
	}
	if n := c.runs.Load(); n != 1 {
		t.Fatalf("TestIncrement ran %d times for one requestId, want 1", n)
	}
	// A new requestId is a new request
	wantJSON(t, h.post("/v1/TestIncrement", `{"requestId":"r-2","add":1}`), http.StatusOK, `{"count":2}`)
}

func TestRepeatedRequestIDReplaysAnErrorResultToo(t *testing.T) {
	c := &counter{}
	h := start(t, nil, c)
	// The first result is a validation error from the method itself: replayed, never re-run
	wantError(t, h.post("/v1/TestIncrement", `{"requestId":"e-1","bogus":true}`), http.StatusBadRequest, "invalid_argument", "bogus")
	wantError(t, h.post("/v1/TestIncrement", `{"requestId":"e-1","bogus":true}`), http.StatusBadRequest, "invalid_argument", "bogus")
	if n := c.runs.Load(); n != 0 {
		t.Errorf("TestIncrement counted %d, want 0", n)
	}
}

func TestConcurrentDuplicateRunsOnce(t *testing.T) {
	c := &counter{release: make(chan struct{}), entered: make(chan struct{}, 2)}
	h := start(t, nil, c)
	var wg sync.WaitGroup
	replies := make([]reply, 2)
	wg.Add(1)
	go func() { defer wg.Done(); replies[0] = h.post("/v1/TestIncrement", `{"requestId":"c-1"}`) }()
	<-c.entered // the first execution is in flight
	wg.Add(1)
	go func() { defer wg.Done(); replies[1] = h.post("/v1/TestIncrement", `{"requestId":"c-1"}`) }()
	// The duplicate waits for the first result rather than running: release once the duplicate is known to be waiting
	waitFor(t, func() bool { return h.srv.replay.waiting("TestIncrement", "c-1") == 1 })
	close(c.release)
	wg.Wait()
	for _, r := range replies {
		wantJSON(t, r, http.StatusOK, `{"count":1}`)
	}
	if n := c.runs.Load(); n != 1 {
		t.Errorf("TestIncrement ran %d times for two concurrent identical requests, want 1", n)
	}
}

func TestRequestIDReusedForADifferentRequestConflicts(t *testing.T) {
	c := &counter{}
	h := start(t, nil, c)
	wantJSON(t, h.post("/v1/TestIncrement", `{"requestId":"d-1","add":1}`), http.StatusOK, `{"count":1}`)
	wantError(t, h.post("/v1/TestIncrement", `{"requestId":"d-1","add":2}`), http.StatusConflict, "conflict", "requestId")
	if n := c.runs.Load(); n != 1 {
		t.Errorf("TestIncrement ran %d times, want 1", n)
	}
}

func TestMutatingRequestNeedsAValidRequestID(t *testing.T) {
	c := &counter{}
	h := start(t, nil, c)
	for _, body := range []string{`{}`, `{"requestId":""}`, `{"requestId":7}`, `{"requestId":"` + strings.Repeat("x", 129) + `"}`, `{"requestId":"a\u0001b"}`} {
		t.Run(body[:min(len(body), 20)], func(t *testing.T) {
			wantError(t, h.post("/v1/TestIncrement", body), http.StatusBadRequest, "invalid_argument", "requestId")
		})
	}
	// 128 printable characters is the longest accepted
	wantJSON(t, h.post("/v1/TestIncrement", `{"requestId":"`+strings.Repeat("x", 128)+`"}`), http.StatusOK, `{"count":1}`)
	if n := c.runs.Load(); n != 1 {
		t.Errorf("TestIncrement ran %d times, want 1 (only the valid requestId)", n)
	}
}

func TestSocketAndItsDirectoryArePrivate(t *testing.T) {
	h := start(t, nil, nil)
	info, err := os.Lstat(h.socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want a socket of mode 0600", info.Mode())
	}
	dir, err := os.Lstat(filepath.Dir(h.socket))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("socket directory mode = %v, want 0700", dir.Mode().Perm())
	}
}

func TestListenRefusesANonSocketAtThePath(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "api.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(options{socket: path, methods: productionMethods(), logf: t.Logf}); err == nil {
		t.Fatal("listen replaced a regular file at the socket path")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep me" {
		t.Errorf("the file at the socket path was changed: %q", got)
	}
}

func TestListenReplacesAStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "api.sock")
	// A socket left behind by a server that was killed (no shutdown ran) is replaced by the next start
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket is not there: %v", err)
	}
	next := start(t, func(o *options) { o.socket = path }, nil)
	wantJSON(t, next.post("/v1/GetVersion", `{}`), http.StatusOK, versionReply)
}

func TestShutdownRemovesTheSocket(t *testing.T) {
	h := start(t, nil, nil)
	h.stop()
	if _, err := os.Lstat(h.socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after shutdown: %v", err)
	}
}

func TestStalledRequestHeaderIsCutOff(t *testing.T) {
	h := start(t, func(o *options) { o.readHeaderTimeout = 50 * time.Millisecond }, nil)
	conn, err := net.Dial("unix", h.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("POST /v1/GetVersion HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}
	// The header never ends: the server must hang up by itself. The deadline only salvages a stuck run.
	_ = conn.SetReadDeadline(time.Now().Add(watchdog))
	got, err := io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("STUCK: the server kept a stalled request open past the %v watchdog", watchdog)
	}
	if bytes.Contains(got, []byte("200 OK")) {
		t.Errorf("a request whose header never ended was answered: %q", got)
	}
}

func TestRunNeedsTheSocketFlag(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Errorf("run without --socket = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--socket") {
		t.Errorf("stderr does not name --socket: %q", stderr.String())
	}
}

func TestRunServesUntilCancelledAndRemovesTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "api.sock")
	ctx, cancel := context.WithCancel(context.Background())
	var stderr syncBuffer
	code := make(chan int, 1)
	go func() {
		code <- run(ctx, []string{"--socket", socket, "--state-dir", filepath.Join(dir, "state"), "--allow-uid", strconv.Itoa(os.Getuid())}, &stderr)
	}()
	waitFor(t, func() bool { return strings.Contains(stderr.String(), "serving API v1 on "+socket) })
	client := &http.Client{Timeout: watchdog, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	resp, err := client.Post("http://pfb-core/v1/GetVersion", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"apiVersion":"v1"`)) {
		t.Errorf("GetVersion = %d %s", resp.StatusCode, body)
	}
	client.CloseIdleConnections()
	cancel()
	if c := <-code; c != 0 {
		t.Errorf("run = %d after cancel, want 0; stderr:\n%s", c, stderr.String())
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after run returned: %v", err)
	}
}

// waitFor polls a condition the server publishes; the deadline only salvages a stuck run.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(watchdog)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: condition not reached within the %v watchdog", watchdog)
		}
		time.Sleep(time.Millisecond)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
