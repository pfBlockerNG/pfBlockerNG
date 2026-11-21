//go:build linux || freebsd

package feedparse

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// lifetimeRun owns the watchdog, cooperative release FIFOs and Run goroutine,
// including when an assertion fails before the script reports readiness.
type lifetimeRun struct {
	t                 *testing.T
	dir, norm, staged string
	ctx               context.Context
	cancel            context.CancelFunc
	fifo              map[string]*os.File
	done              chan PreScriptResult
	joined            bool
	child             bool
}

func newLifetimeRun(t *testing.T, body string, child bool) *lifetimeRun {
	t.Helper()
	r := &lifetimeRun{t: t, dir: t.TempDir(), fifo: make(map[string]*os.File), child: child}
	r.ctx, r.cancel = context.WithTimeout(context.Background(), watchdog)
	r.norm, r.staged = filepath.Join(r.dir, "feed.norm"), filepath.Join(r.dir, "feed.pre")
	t.Setenv("PFB_LIFETIME_DIR", r.dir)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PFB_LIFETIME_EXE", exe)
	t.Cleanup(r.cleanup)
	for _, name := range []string{"ready", "childready", "childstarted", "leaderrelease", "childrelease", "handled", "post", "request", "ack", "alive"} {
		path := filepath.Join(r.dir, name)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("create %s FIFO: %v", name, err)
		}
		flags := os.O_RDWR | syscall.O_NONBLOCK
		if name == "alive" {
			flags = os.O_RDONLY | syscall.O_NONBLOCK
		}
		f, err := os.OpenFile(path, flags, 0)
		if err != nil {
			t.Fatalf("open %s FIFO: %v", name, err)
		}
		r.fifo[name] = f
	}
	if err := os.WriteFile(r.norm, []byte("original.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(r.dir, "script.sh")
	text := "#!/bin/sh\ncd \"$PFB_LIFETIME_DIR\" || exit 90\n" + body
	if err := os.WriteFile(script, []byte(text), 0o700); err != nil {
		t.Fatal(err)
	}
	r.done = make(chan PreScriptResult, 1)
	go func() { r.done <- RunPreScript(r.ctx, script, r.norm, r.staged, nil) }()
	return r
}

func (r *lifetimeRun) event(name string) {
	r.t.Helper()
	f := r.fifo[name]
	if err := f.SetReadDeadline(time.Now().Add(guard)); err != nil {
		r.t.Fatalf("bound %s handshake: %v", name, err)
	}
	var b [1]byte
	if n, err := f.Read(b[:]); n != 1 || err != nil {
		r.t.Fatalf("%s handshake = %d bytes, %v; want one acknowledged byte", name, n, err)
	}
}

func (r *lifetimeRun) release(name string) {
	r.t.Helper()
	if _, err := r.fifo[name].WriteString("x\n"); err != nil {
		r.t.Fatalf("release %s: %v", name, err)
	}
}

func (r *lifetimeRun) result() PreScriptResult {
	r.t.Helper()
	select {
	case got := <-r.done:
		r.joined = true
		return got
	case <-time.After(guard):
		r.t.Fatal("RunPreScript did not return; want a bounded completed run")
		return PreScriptResult{}
	}
}

func (r *lifetimeRun) files(got PreScriptResult, success bool) {
	r.t.Helper()
	want := PreScriptResult{Path: r.norm, Reason: PreScriptCancelled}
	if success {
		want = PreScriptResult{OK: true, Path: r.staged}
	}
	if got != want {
		r.t.Errorf("RunPreScript = %+v; want %+v", got, want)
	}
	if b, err := os.ReadFile(r.norm); err != nil || string(b) != "original.example\n" {
		r.t.Errorf("original norm = %q, %v; want original.example\\n unchanged", b, err)
	}
	b, err := os.ReadFile(r.staged)
	if success {
		if err != nil || string(b) != "transformed.example\n" {
			r.t.Errorf("staged = %q, %v; want transformed.example\\n", b, err)
		}
		got.Cleanup()
		if _, err := os.Stat(r.staged); !os.IsNotExist(err) {
			r.t.Errorf("staged after Cleanup: %v; want not-exist", err)
		}
	} else if !os.IsNotExist(err) {
		r.t.Errorf("staged after timeout = %q, %v; want not-exist", b, err)
	}
}

func (r *lifetimeRun) childGone(immediate bool) {
	r.t.Helper()
	// Readiness proves a real child holds this writer; EOF is not a PID/zombie probe.
	f := r.fifo["alive"]
	var b [1]byte
	if immediate {
		// Do not let a delayed grace timer satisfy the before-return contract.
		conn, err := f.SyscallConn()
		if err != nil {
			r.t.Fatal(err)
		}
		var n int
		var readErr error
		if err := conn.Control(func(fd uintptr) { n, readErr = syscall.Read(int(fd), b[:]) }); err != nil {
			r.t.Fatal(err)
		}
		if n != 0 || readErr != nil {
			r.t.Errorf("attached child at RunPreScript return: read = %d, %v; want EOF (no live writer)", n, readErr)
		}
		return
	}
	if err := f.SetReadDeadline(time.Now().Add(guard)); err != nil {
		r.t.Fatal(err)
	}
	if n, err := f.Read(b[:]); n != 0 || err != io.EOF {
		r.t.Errorf("detached helper after acknowledgement: read = %d, %v; want EOF (helper exited)", n, err)
	}
}

func (r *lifetimeRun) cleanup() {
	r.cancel()
	defer func() {
		for _, f := range r.fifo {
			_ = f.Close()
		}
	}()
	// Release every controlled reader before joining, without signaling stale PIDs.
	for _, name := range []string{"leaderrelease", "childrelease", "request"} {
		if f := r.fifo[name]; f != nil {
			if _, err := f.WriteString("quit\n"); err != nil {
				r.t.Errorf("salvage release %s: %v; want a delivered release", name, err)
			}
		}
	}
	if r.done != nil && !r.joined {
		select {
		case <-r.done:
		case <-time.After(guard):
			r.t.Error("salvage: RunPreScript goroutine did not finish after cooperative release")
		}
	}
	if r.done != nil && r.child {
		f := r.fifo["childstarted"]
		if err := f.SetReadDeadline(time.Now().Add(guard)); err != nil {
			r.t.Errorf("salvage child-start deadline: %v", err)
		} else {
			var b [1]byte
			if n, err := f.Read(b[:]); n != 1 || err != nil {
				r.t.Errorf("salvage child-start = %d bytes, %v; want writer-open acknowledgement", n, err)
			} else {
				r.childGone(false)
			}
		}
	}
}

const lifetimeAttachedChild = `(
 trap '' TERM
 exec 9> alive
 echo x > childstarted
 echo x > childready
 read -r line < childrelease
) &
read -r line < childready
`

func TestPreScriptKillsAnIgnoringChildAfterItsLeaderDiesOnTerm(t *testing.T) {
	r := newLifetimeRun(t, lifetimeAttachedChild+`echo x > ready
read -r line < leaderrelease
`, true)
	r.event("ready")
	r.cancel()
	got := r.result()
	r.childGone(true)
	r.files(got, false)
}

func TestPreScriptImmediatelyCleansAnAttachedChildAfterSuccessfulLeaderExit(t *testing.T) {
	r := newLifetimeRun(t, lifetimeAttachedChild+`printf 'transformed.example\n' > "$1"
echo x > ready
exit 0
`, true)
	r.event("ready")
	got := r.result()
	r.childGone(true)
	r.files(got, true)
	if err := r.ctx.Err(); err != nil {
		t.Errorf("successful run context = %v; want no deadline or cancellation", err)
	}
}

func TestPreScriptKeepsTheRunningLeadersTermGrace(t *testing.T) {
	r := newLifetimeRun(t, `trap 'echo x > handled; read -r line < leaderrelease; echo x > post; exit 0' TERM
echo x > ready
( while read -r line < request; do [ "$line" = quit ] && exit 0; done ) & wait $!
`, false)
	r.event("ready")
	r.cancel()
	r.event("handled")
	r.release("leaderrelease")
	r.event("post")
	r.files(r.result(), false)
}

func TestPreScriptAllowsAnIntentionallyDetachedSurvivor(t *testing.T) {
	r := newLifetimeRun(t, `PFB_LIFETIME_HELPER=detach "$PFB_LIFETIME_EXE" -test.run '^TestPreScriptLifetimeHelper$' </dev/null >/dev/null 2>&1 &
read -r line < childready
printf 'transformed.example\n' > "$1"
echo x > ready
exit 0
`, true)
	r.event("ready")
	r.files(r.result(), true)
	if err := r.ctx.Err(); err != nil {
		t.Errorf("successful detached run context = %v; want active context", err)
	}
	r.release("request")
	r.event("ack")
	r.childGone(false)
}

// The detached helper uses the host syscall, not an optional external setsid utility.
func TestPreScriptLifetimeHelper(t *testing.T) {
	if os.Getenv("PFB_LIFETIME_HELPER") != "detach" {
		return
	}
	if _, err := syscall.Setsid(); err != nil {
		os.Exit(91)
	}
	signal.Ignore(syscall.SIGTERM)
	dir := os.Getenv("PFB_LIFETIME_DIR")
	alive, err := os.OpenFile(filepath.Join(dir, "alive"), os.O_WRONLY, 0)
	if err != nil {
		os.Exit(93)
	}
	defer alive.Close()
	request, err := os.OpenFile(filepath.Join(dir, "request"), os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		os.Exit(94)
	}
	defer request.Close()
	if err := request.SetReadDeadline(time.Now().Add(guard)); err != nil {
		os.Exit(95)
	}
	for _, name := range []string{"childstarted", "childready", "ack"} {
		if name == "ack" {
			var b [1]byte
			if n, err := request.Read(b[:]); n != 1 || err != nil {
				os.Exit(96)
			}
		}
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			os.Exit(97)
		}
		_, err = f.WriteString("x\n")
		f.Close()
		if err != nil {
			os.Exit(98)
		}
	}
}
