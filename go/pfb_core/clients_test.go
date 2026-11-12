package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// More than one local process calls Core: PHP (root) and pfb-dns under its own user (map #3813, owner 2026-11-12). Each
// further client is admitted by its uid (--client-uid); --socket-group opens the socket's directory and the socket to that
// group, so that a non-root client can reach it at all, while the kernel credential still decides who is served.

func TestAFurtherLocalClientUIDIsServed(t *testing.T) {
	// Given the caller is not the privileged uid but is a listed client
	h := start(t, func(o *options) {
		o.allowUID = uint32(os.Getuid()) + 1
		o.clientUIDs = []uint32{uint32(os.Getuid()) + 2, uint32(os.Getuid())}
	}, nil)
	wantJSON(t, h.post("/v1/GetVersion", `{}`), http.StatusOK, versionReply)
}

func TestAnUnlistedUIDIsRefusedEvenWithClientsListed(t *testing.T) {
	h := start(t, func(o *options) {
		o.allowUID = uint32(os.Getuid()) + 1
		o.clientUIDs = []uint32{uint32(os.Getuid()) + 2}
	}, nil)
	wantError(t, h.post("/v1/GetVersion", `{}`), http.StatusUnauthorized, "unauthenticated")
}

func TestSocketGroupOpensTheSocketToThatGroupOnly(t *testing.T) {
	gid := os.Getgid() // a group the test may hand its own files to
	h := start(t, func(o *options) { o.socketGroup = gid; o.groupSet = true }, nil)
	for path, want := range map[string]os.FileMode{h.socket: 0o660, filepath.Dir(h.socket): 0o750} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", path, info.Mode().Perm(), want)
		}
		if st := info.Sys().(*syscall.Stat_t); int(st.Gid) != gid {
			t.Errorf("%s group = %d, want %d", path, st.Gid, gid)
		}
	}
	wantJSON(t, h.post("/v1/GetVersion", `{}`), http.StatusOK, versionReply)
}

func TestWithoutASocketGroupAnOpenedDirectoryIsClosedAgain(t *testing.T) {
	// Given a directory an earlier start with --socket-group left at 0750
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	run := filepath.Join(dir, "run")
	if err := os.Mkdir(run, 0o750); err != nil {
		t.Fatal(err)
	}
	// When Core starts without one, the directory is root's alone again
	start(t, func(o *options) { o.socket = filepath.Join(run, "api.sock") }, nil)
	info, err := os.Lstat(run)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestRunTakesClientUIDsAndASocketGroup(t *testing.T) {
	for _, bad := range [][]string{{"--client-uid", "x"}, {"--client-uid", "-1"}, {"--socket-group", "staff"}} {
		var stderr bytes.Buffer
		if code := run(context.Background(), append([]string{"--socket", "/nonexistent/api.sock"}, bad...), &stderr); code != 2 {
			t.Errorf("run %q = %d, want 2 (a usage error); stderr %q", bad, code, stderr.String())
		}
	}
	dir, err := os.MkdirTemp("", "pfbcore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "run", "api.sock")
	ctx, cancel := context.WithCancel(context.Background())
	var stderr syncBuffer
	code := make(chan int, 1)
	go func() {
		code <- run(ctx, []string{"--socket", socket, "--state-dir", filepath.Join(dir, "state"), "--allow-uid", strconv.Itoa(os.Getuid() + 1),
			"--client-uid", strconv.Itoa(os.Getuid() + 2), "--client-uid", strconv.Itoa(os.Getuid()),
			"--socket-group", strconv.Itoa(os.Getgid())}, &stderr)
	}()
	waitFor(t, func() bool { return bytes.Contains([]byte(stderr.String()), []byte("serving API v1 on "+socket)) })
	info, err := os.Lstat(socket)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("socket = %v %v, want mode 0660", info, err)
	}
	cancel()
	if c := <-code; c != 0 {
		t.Errorf("run = %d, want 0; stderr:\n%s", c, stderr.String())
	}
	for _, want := range []string{"uid " + strconv.Itoa(os.Getuid()+1), strconv.Itoa(os.Getuid() + 2), strconv.Itoa(os.Getuid())} {
		if !bytes.Contains([]byte(stderr.String()), []byte(want)) {
			t.Errorf("the start line does not name the served uid %s:\n%s", want, stderr.String())
		}
	}
}
