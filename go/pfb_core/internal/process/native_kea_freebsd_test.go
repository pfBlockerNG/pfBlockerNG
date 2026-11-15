//go:build freebsd

package process_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// Temporary diagnostic, not a Kea safety assertion: either ownership outcome is evidence.
// Run only in the disposable native harness; failed cooperative cleanup requires VM teardown.
func TestNativeKeaOwnershipDiscrimination(t *testing.T) {
	if os.Getenv("PFB_NATIVE_KEA_PROBE") != "1" {
		t.Fatal("requires explicit disposable-lab opt-in PFB_NATIVE_KEA_PROBE=1; run only in the approved disposable native harness")
	}
	for _, family := range []string{"4", "6"} {
		t.Run("dhcp"+family, func(t *testing.T) { nativeKeaOwnership(t, family) })
	}
}

func nativeKeaOwnership(t *testing.T, family string) {
	t.Helper()
	binary := "/usr/local/sbin/kea-dhcp" + family
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	command, dir := program(t, "")
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	if len(socket) >= 104 {
		t.Fatal("private control socket exceeds FreeBSD sockaddr_un path bound")
	}
	config := filepath.Join(dir, "owned.json")
	pidfile := filepath.Join(dir, "owned.kea-dhcp"+family+".pid")
	settings := map[string]any{
		"interfaces-config": map[string]any{"interfaces": []string{}},
		"valid-lifetime":    4000,
		"lease-database": map[string]any{
			"type": "memfile", "persist": false,
			"name": filepath.Join(dir, "leases.csv"), "lfc-interval": 0,
		},
		"subnet" + family: []any{},
		"control-socket":  map[string]any{"socket-type": "unix", "socket-name": socket},
		"loggers": []any{map[string]any{
			"name": "kea-dhcp" + family, "severity": "INFO",
			"output_options": []any{map[string]any{"output": filepath.Join(dir, "kea.log")}},
		}},
	}
	if family == "6" {
		settings["preferred-lifetime"] = 3000
		settings["data-directory"] = dir
		settings["server-id"] = map[string]any{
			"type": "EN", "enterprise-id": 2495, "identifier": "87ABEF7A5BB545", "persist": false,
		}
	}
	payload, err := json.Marshal(map[string]any{"Dhcp" + family: settings})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	// -t is setup only: the installed manual explicitly says it does not open control sockets.
	lintLog, err := os.OpenFile(filepath.Join(dir, "lint.log"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	lintCtx, lintCancel := context.WithTimeout(context.Background(), 5*time.Second)
	lint := exec.CommandContext(lintCtx, binary, "-t", config)
	lint.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir)
	lint.Stdout, lint.Stderr = lintLog, lintLog
	err = lint.Run()
	lintCancel()
	_ = lintLog.Close()
	if err != nil {
		text, _ := nativeKeaRead(filepath.Join(dir, "lint.log"))
		t.Fatalf("isolated config setup failed (not ownership evidence): %v; %s", err, text)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "hold"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Match native mwexec_bg's nohup + background launch; no setsid, helper group, or leaf reaper.
	body := "#!/bin/sh\nD=" + quote(dir) + "\nexport KEA_PIDFILE_DIR=\"$D\"\nprintf '%s\\n' \"$$\" > \"$D/update.pid\"\n/usr/bin/nohup " + quote(binary) + " -c " + quote(config) + " > /dev/null 2>&1 &\nread owned_release < \"$D/hold\"\n"
	if err := os.WriteFile(command.Path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	log := newLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	joined := false
	pid := 0
	t.Cleanup(func() {
		cancel()
		if !joined {
			select {
			case err := <-done:
				t.Logf("cleanup Update join: %v", err)
			case <-time.After(10 * time.Second):
				t.Error("Update cleanup join deadline exceeded; disposable VM teardown required")
			}
		}
		// Also covers delayed startup after an earlier readiness/pidfile failure.
		deadline := time.Now().Add(5 * time.Second)
		for {
			reply, controlErr := nativeKeaControl(socket, "shutdown")
			if controlErr == nil {
				t.Logf("private cleanup shutdown: %s", reply)
			}
			_, statErr := os.Lstat(pidfile)
			if errors.Is(statErr, os.ErrNotExist) && errors.Is(controlErr, syscall.ENOENT) {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("private Kea cleanup unconfirmed: control=%v pidfile=%v; VM teardown is the remaining bound", controlErr, statErr)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if pid > 0 {
			if err := nativeKeaAwaitDeath(pid, 3*time.Second); err != nil {
				t.Errorf("Kea exit unconfirmed after cooperative cleanup: %v; VM teardown required", err)
			}
		}
		for _, name := range []string{"kea.log", "update.log"} {
			path := filepath.Join(dir, name)
			if name == "update.log" {
				path = log.Name()
			}
			text, err := nativeKeaRead(path)
			t.Logf("%s: %s (read=%v)", name, text, err)
		}
	})
	go func() { _, err := command.Run(ctx, update.Request{}, log); done <- err }()
	var ready []byte
	deadline := time.Now().Add(10 * time.Second)
	for {
		ready, err = nativeKeaControl(socket, "list-commands")
		if err == nil {
			break
		}
		select {
		case runErr := <-done:
			joined = true
			t.Fatalf("Update exited before readiness: %v; control=%v", runErr, err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("private Kea readiness deadline: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var reply struct {
		Arguments []string `json:"arguments"`
	}
	if err := json.Unmarshal(ready, &reply); err != nil || !slices.Contains(reply.Arguments, "shutdown") {
		t.Fatalf("real list-commands lacks cooperative shutdown: %s (%v)", ready, err)
	}
	t.Logf("real private readiness: %s", ready)
	readPID := func(path string) int {
		text, err := nativeKeaRead(path)
		if err != nil {
			t.Fatal(err)
		}
		value, err := strconv.Atoi(strings.TrimSpace(string(text)))
		if err != nil || value <= 1 {
			t.Fatalf("invalid private PID %q: %v", text, err)
		}
		return value
	}
	pid = readPID(pidfile)
	updatePID := readPID(filepath.Join(dir, "update.pid"))
	updatePGID, err := syscall.Getpgid(updatePID)
	if err != nil {
		t.Fatalf("actual Update not running: %v", err)
	}
	keaPGID, err := syscall.Getpgid(pid)
	if err != nil {
		t.Fatalf("actual Kea pidfile process not running: %v", err)
	}
	parentPGID := syscall.Getpgrp()
	if updatePGID == parentPGID {
		t.Fatal("Update is not isolated from the test parent")
	}
	ownership := "detached-from-Update-group"
	if keaPGID == updatePGID {
		ownership = "inherited-Update-group"
	}
	t.Logf("DISCRIMINATION ONLY: binary=%s argv=[-c %s] Kea PID=%d PGID=%d Update PID=%d PGID=%d parent PGID=%d ownership=%s", binary, config, pid, keaPGID, updatePID, updatePGID, parentPGID, ownership)
	cancel()
	select {
	case err := <-done:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Update cancellation = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Update cancellation join deadline exceeded")
	}
	post, postErr := nativeKeaControl(socket, "list-commands")
	deathErr := nativeKeaAwaitDeath(pid, time.Second)
	t.Logf("POST-CANCEL CLASSIFICATION ONLY: control=%s error=%v deathObservation=%v (nil means ESRCH observed)", post, postErr, deathErr)
	if postErr != nil && deathErr != nil {
		t.Error("post-cancel state inconclusive: neither control response nor process disappearance")
	}
}

func nativeKeaRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not an owned regular file: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

func nativeKeaControl(socket, command string) ([]byte, error) {
	conn, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		return nil, err
	}
	if err := json.NewEncoder(conn).Encode(map[string]string{"command": command}); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&raw); err != nil {
		return nil, err
	}
	var reply struct {
		Result *int `json:"result"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil || reply.Result == nil || *reply.Result != 0 {
		return raw, fmt.Errorf("Kea %s response unsuccessful: %s (%v)", command, raw, err)
	}
	return raw, nil
}

func nativeKeaAwaitDeath(pid int, bound time.Duration) error {
	deadline := time.Now().Add(bound)
	for {
		_, err := syscall.Getpgid(pid)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil || time.Now().After(deadline) {
			return fmt.Errorf("PID %d still observable or query failed: %v", pid, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
