package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const maintenanceLifetimeTimeout = 20 * time.Second

type maintenanceLifetimePeer struct {
	conn net.Conn
	read *bufio.Reader
	role string
}

type maintenanceLifetimeFixture struct {
	t        *testing.T
	dir      string
	state    string
	listener *net.UnixListener
	accepted chan *maintenanceLifetimePeer
	mu       sync.Mutex
	peers    []*maintenanceLifetimePeer
}

func newMaintenanceLifetimeFixture(t *testing.T) *maintenanceLifetimeFixture {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "payload.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f := &maintenanceLifetimeFixture{t: t, dir: dir, state: state, listener: listener,
		accepted: make(chan *maintenanceLifetimePeer, 4)}
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		peers := append([]*maintenanceLifetimePeer(nil), f.peers...)
		f.mu.Unlock()
		// Release owned payloads cooperatively even if the observer or an assertion already failed.
		for _, peer := range peers {
			_ = peer.conn.SetDeadline(time.Now().Add(maintenanceLifetimeTimeout))
			_, _ = fmt.Fprintln(peer.conn, "finish")
			_ = peer.conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			peer := &maintenanceLifetimePeer{conn: conn, read: bufio.NewReader(conn)}
			f.mu.Lock()
			f.peers = append(f.peers, peer)
			f.mu.Unlock()
			_ = conn.SetDeadline(time.Now().Add(maintenanceLifetimeTimeout))
			role, err := peer.read.ReadString('\n')
			if err != nil {
				_ = conn.Close()
				continue
			}
			peer.role = strings.TrimSpace(role)
			f.accepted <- peer
		}
	}()
	return f
}

func maintenanceLifetimeQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func (f *maintenanceLifetimeFixture) script(role string) string {
	f.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(f.dir, role+".sh")
	body := "#!/bin/sh\n" +
		"export PFB_MAINTENANCE_LIFETIME_SOCKET=" + maintenanceLifetimeQuote(f.listener.Addr().String()) + "\n" +
		"export PFB_MAINTENANCE_LIFETIME_ROLE=" + maintenanceLifetimeQuote(role) + "\n" +
		"export PFB_MAINTENANCE_LIFETIME_DIR=" + maintenanceLifetimeQuote(f.dir) + "\n" +
		"exec " + maintenanceLifetimeQuote(executable) + " -test.run '^TestMaintenanceLifetimePayload$'\n"
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *maintenanceLifetimeFixture) peer(role string) *maintenanceLifetimePeer {
	f.t.Helper()
	select {
	case peer := <-f.accepted:
		if peer.role != role {
			f.t.Fatalf("payload role = %q, want %q", peer.role, role)
		}
		return peer
	case <-time.After(maintenanceLifetimeTimeout):
		f.t.Fatalf("STUCK: %s payload did not connect", role)
	}
	return nil
}

func maintenanceLifetimeExchange(t *testing.T, peer *maintenanceLifetimePeer, command, want string) {
	t.Helper()
	_ = peer.conn.SetDeadline(time.Now().Add(maintenanceLifetimeTimeout))
	if _, err := fmt.Fprintln(peer.conn, command); err != nil {
		t.Fatalf("%s payload rejected %s: %v", peer.role, command, err)
	}
	got, err := peer.read.ReadString('\n')
	if err != nil || strings.TrimSpace(got) != want {
		t.Fatalf("%s payload reply to %s = %q (%v), want %q", peer.role, command, got, err, want)
	}
}

func maintenanceLifetimeWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(maintenanceLifetimeTimeout):
		t.Fatal("STUCK: maintenance observer or worker did not return")
	}
	return nil
}

func TestMaintenanceLifetimeObserverCancellationLeavesTransactionAndLogOwnerAlive(t *testing.T) {
	f := newMaintenanceLifetimeFixture(t)
	observer, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- maintenance(f.script("maintenance"), f.state)(observer) }()
	peer := f.peer("maintenance")
	cancel()
	if err := maintenanceLifetimeWait(t, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("canceling observation = %v, want context cancellation or normal return", err)
	}

	// The independent worker still owns the socket and regular-file transcript after Core stops observing.
	maintenanceLifetimeExchange(t, peer, "ping", "pong")
	logPath := filepath.Join(f.state, "maintenance.log")
	for _, suffix := range []string{"", ".lock", ".request", ".result", ".status"} {
		if _, err := os.Stat(logPath + suffix); err != nil {
			t.Errorf("missing independent maintenance path %s: %v", logPath+suffix, err)
		}
	}
	maintenanceLifetimeExchange(t, peer, "finish", "finished")
	if got, err := os.ReadFile(filepath.Join(f.dir, "maintenance.finished")); err != nil || string(got) != "maintenance-finished\n" {
		t.Errorf("transaction completion = %q (%v)", got, err)
	}
	if got, err := os.ReadFile(logPath); err != nil || !bytes.Contains(got, []byte("maintenance-finished\n")) {
		t.Errorf("log owner lost post-observation output: %q (%v)", got, err)
	}
}

func TestMaintenanceLifetimeLeaseRefusalIsBenignAndIndependentOfUpdateLease(t *testing.T) {
	f := newMaintenanceLifetimeFixture(t)
	maintenancePath := maintenance(f.script("maintenance"), f.state)
	observer, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- maintenancePath(observer) }()
	maintenancePeer := f.peer("maintenance")
	cancel()
	if err := maintenanceLifetimeWait(t, firstDone); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("first observer cancellation = %v", err)
	}

	logPath := filepath.Join(f.state, "maintenance.log")
	before, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- maintenancePath(context.Background()) }()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Errorf("busy maintenance = %v, want benign nil skip", err)
		}
	case peer := <-f.accepted:
		t.Errorf("busy maintenance admitted a second %s payload", peer.role)
		maintenanceLifetimeExchange(t, peer, "finish", "finished")
	case <-time.After(maintenanceLifetimeTimeout):
		t.Fatal("STUCK: busy maintenance neither refused nor returned")
	}
	after, err := os.Stat(logPath)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Errorf("busy retry changed maintenance log inode/size: before=%v after=%v err=%v", before, after, err)
	}

	updateLog, err := os.OpenFile(filepath.Join(f.state, "update.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	updateDone := make(chan error, 1)
	updateCommand := update.Command{Path: f.script("update")}
	go func() {
		defer updateLog.Close()
		_, err := updateCommand.Run(context.Background(), update.Request{Trigger: "apply"}, updateLog)
		updateDone <- err
	}()
	updatePeer := f.peer("update")
	maintenanceLifetimeExchange(t, maintenancePeer, "finish", "finished")
	maintenanceLifetimeExchange(t, updatePeer, "finish", "finished")
	if err := maintenanceLifetimeWait(t, updateDone); err != nil {
		t.Errorf("independent Update = %v, want success", err)
	}
	for _, role := range []string{"maintenance", "update"} {
		other := "update"
		if role == "update" {
			other = "maintenance"
		}
		log, err := os.ReadFile(filepath.Join(f.state, role+".log"))
		if err != nil || !bytes.Contains(log, []byte(role+"-finished\n")) || bytes.Contains(log, []byte(other+"-finished\n")) {
			t.Errorf("separate %s log = %q (%v)", role, log, err)
		}
	}
}

// The worker payload is released through its owned socket, never through stored PID authority.
func TestMaintenanceLifetimePayload(t *testing.T) {
	endpoint := os.Getenv("PFB_MAINTENANCE_LIFETIME_SOCKET")
	if endpoint == "" {
		return
	}
	role, dir := os.Getenv("PFB_MAINTENANCE_LIFETIME_ROLE"), os.Getenv("PFB_MAINTENANCE_LIFETIME_DIR")
	conn, err := net.DialTimeout("unix", endpoint, maintenanceLifetimeTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintln(os.Stdout, role+"-started")
	if _, err := fmt.Fprintln(conn, role); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(maintenanceLifetimeTimeout))
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		switch scanner.Text() {
		case "ping":
			if _, err := fmt.Fprintln(conn, "pong"); err != nil {
				t.Fatal(err)
			}
		case "finish":
			if err := os.WriteFile(filepath.Join(dir, role+".finished"), []byte(role+"-finished\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(os.Stdout, role+"-finished")
			fmt.Fprintln(conn, "finished")
			return
		default:
			t.Fatalf("unknown owned payload command %q", scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("STUCK/TRANSPORT: owned payload socket ended: %v", err)
	}
}
