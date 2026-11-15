//go:build freebsd

package process_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

const nativeServiceMode = "PFB_NATIVE_SERVICE_WORKER"
const nativeServicePayload = "owned-native-filter-payload"

type nativeServiceReport struct {
	Role    string
	PID     int
	PGID    int
	Payload string
}

type nativeServicePeer struct {
	net.Conn
	reader *bufio.Reader
	report nativeServiceReport
}

// TestNativeServiceWorker is re-executed only by owned leaf wrappers, never by a real service.
func TestNativeServiceWorker(t *testing.T) {
	role := os.Getenv(nativeServiceMode)
	if role == "" {
		return
	}
	// Bounded salvage does not signal a PID that could have been reused.
	time.AfterFunc(2*stuck, func() { os.Exit(124) })
	payload := nativeServicePayload
	if role == "reader" {
		if _, err := fmt.Fprintln(os.Stdout, payload); err != nil {
			os.Exit(125)
		}
	} else if role == "php" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			os.Exit(125)
		}
		payload = strings.TrimSuffix(line, "\n")
	}
	conn, err := net.Dial("unix", os.Getenv("PFB_NATIVE_SERVICE_SOCKET"))
	if err != nil {
		os.Exit(125)
	}
	if err := json.NewEncoder(conn).Encode(nativeServiceReport{role, os.Getpid(), syscall.Getpgrp(), payload}); err != nil {
		os.Exit(125)
	}
	reader := bufio.NewReader(conn)
	for {
		request, err := reader.ReadString('\n')
		if err != nil {
			os.Exit(125)
		}
		switch request {
		case "post-cancel\n":
			_, err = io.WriteString(conn, "alive-after-cancel\n")
		case "release\n":
			_, _ = io.WriteString(conn, "completed\n")
			// The socket remains open until process exit: EOF proves completion.
			os.Exit(0)
		default:
			os.Exit(125)
		}
		if err != nil {
			os.Exit(125)
		}
	}
}

func TestNativeReloadSurvivesUpdateCancellation(t *testing.T) {
	nativeServiceCancellation(t, "reload")
}

func TestNativeGeneratedTailPipelineSurvivesUpdateCancellation(t *testing.T) {
	nativeServiceCancellation(t, "tail")
}

func TestNativeGeneratedClogPipelineSurvivesUpdateCancellation(t *testing.T) {
	nativeServiceCancellation(t, "clog")
}

func nativeServiceCancellation(t *testing.T, kind string) {
	t.Helper()
	cmd, dir := program(t, "")
	// Paths are substituted inside the installed shell's quoting, not re-quoted.
	if !regexp.MustCompile(`^[/a-zA-Z0-9_.-]+$`).MatchString(dir) {
		t.Fatalf("fixture directory cannot safely replace a shell leaf: %q", dir)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "control.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(stuck)); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	leaf := func(role string) string {
		return write(role, "#!/bin/sh\n"+nativeServiceMode+"="+role+" PFB_NATIVE_SERVICE_SOCKET="+quote(listener.Addr().String())+" exec "+quote(exe)+" -test.run='^TestNativeServiceWorker$'\n", 0o700)
	}
	var launch string
	roles := []string{"reload"}
	if kind == "reload" {
		worker := leaf("reload")
		php := write("reload.php", "<?php\nrequire '/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';\n$pfb = ['filter_configure_sync' => "+quote(worker)+"];\nexit(pfb_filter_reload_exec() === 0 ? 0 : 1);\n", 0o600)
		launch = "/usr/local/bin/php -f " + quote(php)
	} else {
		roles = []string{"reader", "php"}
		launch = nativeInstalledPipeline(t, kind, leaf("reader"), leaf("php"), dir)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "hold"), 0o600); err != nil {
		t.Fatal(err)
	}
	write("update.sh", "#!/bin/sh\nD="+quote(dir)+"\nprintf '%s\\n' \"$$\" > \"$D/update.pid\"\n"+launch+"\nstatus=$?\nprintf '%s\\n' \"$status\" > \"$D/launched\"\n[ \"$status\" -eq 0 ] || exit \"$status\"\nread owned_release < \"$D/hold\"\n", 0o700)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(stuck):
			t.Error("STUCK: canceled Update did not finish during cleanup")
		}
	})
	done := make(chan error, 1)
	log := newLog(t)
	go func() {
		defer close(finished)
		_, err := cmd.Run(ctx, update.Request{}, log)
		done <- err
	}()
	peers := make(map[string]*nativeServicePeer)
	t.Cleanup(func() {
		for _, peer := range peers {
			_ = peer.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(peer, "release\n")
			_ = peer.Close()
		}
	})
	for range roles {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Fatalf("owned service did not become ready: %v", err)
		}
		t.Cleanup(func() {
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "release\n")
			_ = conn.Close()
		})
		peer := &nativeServicePeer{Conn: conn, reader: bufio.NewReader(conn)}
		if err := conn.SetDeadline(time.Now().Add(stuck)); err != nil {
			t.Fatal(err)
		}
		line, err := peer.reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(line, &peer.report); err != nil {
			t.Fatal(err)
		}
		if _, duplicate := peers[peer.report.Role]; duplicate {
			_ = conn.Close()
			t.Fatalf("duplicate service role %q", peer.report.Role)
		}
		peers[peer.report.Role] = peer
	}
	awaitFile(t, filepath.Join(dir, "update.pid"))
	pidBytes, err := os.ReadFile(filepath.Join(dir, "update.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(dir, "launched"))
	status, err := os.ReadFile(filepath.Join(dir, "launched"))
	if err != nil || string(status) != "0\n" {
		t.Fatalf("installed launch status = %q, %v", status, err)
	}
	updateGroup, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("actual Update is not running: %v", err)
	}
	if parentGroup := syscall.Getpgrp(); parentGroup == updateGroup {
		t.Fatalf("test parent and actual Update share PGID %d", updateGroup)
	}
	group := 0
	for _, role := range roles {
		peer := peers[role]
		if peer == nil {
			t.Fatalf("missing worker %q", role)
		}
		r := peer.report
		if r.PID <= 0 || r.PGID <= 0 || r.PGID == updateGroup || r.Payload != nativeServicePayload {
			t.Fatalf("worker not detached with real payload: %+v; Update PGID %d", r, updateGroup)
		}
		if group != 0 && group != r.PGID {
			t.Fatalf("pipeline workers have different groups: %d and %d", group, r.PGID)
		}
		group = r.PGID
	}
	select {
	case err := <-done:
		t.Fatalf("actual Update exited before cancellation: %v", err)
	default:
	}
	cancel()
	if err := recv(t, done, "actual Update cancellation"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Update cancellation error = %v", err)
	}
	for _, role := range roles {
		peer := peers[role]
		if _, err := io.WriteString(peer, "post-cancel\n"); err != nil {
			t.Fatalf("%s died with Update: %v", role, err)
		}
		if line, err := peer.reader.ReadString('\n'); err != nil || line != "alive-after-cancel\n" {
			t.Fatalf("%s post-cancel acknowledgement = %q, %v", role, line, err)
		}
	}
	for _, role := range roles {
		peer := peers[role]
		if _, err := io.WriteString(peer, "release\n"); err != nil {
			t.Fatal(err)
		}
		if line, err := peer.reader.ReadString('\n'); err != nil || line != "completed\n" {
			t.Fatalf("%s completion = %q, %v", role, line, err)
		}
		if _, err := peer.reader.ReadByte(); err != io.EOF {
			t.Fatalf("%s did not exit and close its owned socket: %v", role, err)
		}
		_ = peer.Close()
		delete(peers, role)
	}
}

func nativeInstalledPipeline(t *testing.T, kind, reader, php, dir string) string {
	t.Helper()
	body, err := os.ReadFile("/usr/local/etc/rc.d/pfb_filter.sh")
	if err != nil {
		t.Fatalf("installed generated filter service unavailable: %v", err)
	}
	readerPath := "/usr/bin/tail_pfb"
	files := []string{"/var/log/filter.log", "/var/log/pfblockerng/dnsbl.log", "/var/log/pfblockerng/dns_reply.log"}
	if kind == "clog" {
		readerPath = "/usr/local/sbin/clog_pfb"
		files = files[:1]
	}
	var launches []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, readerPath+" ") && strings.Contains(line, "/usr/local/bin/php_pfb ") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			launches = append(launches, line)
		}
	}
	if len(launches) != 1 {
		t.Fatalf("cannot safely extract exact installed %s launch: found %d statements", kind, len(launches))
	}
	line := launches[0]
	t.Logf("exact installed %s pipeline: %s", kind, line)
	if strings.HasSuffix(strings.TrimSpace(line), "\\") || !strings.Contains(line, "|") {
		t.Fatalf("unsupported installed %s launch shape: %s", kind, line)
	}
	replacements := [][2]string{{readerPath, reader}, {"/usr/local/bin/php_pfb", php}, {"/usr/local/pkg/pfblockerng/pfblockerng.inc", filepath.Join(dir, "unused.inc")}}
	for i, file := range files {
		replacements = append(replacements, [2]string{file, filepath.Join(dir, fmt.Sprintf("owned-log-%d", i))})
	}
	for _, replacement := range replacements {
		if strings.Count(line, replacement[0]) != 1 {
			t.Fatalf("cannot safely replace leaf %q in installed launch", replacement[0])
		}
		line = strings.Replace(line, replacement[0], replacement[1], 1)
	}
	return line
}
