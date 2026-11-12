package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
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
