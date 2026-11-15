package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestWorkerTerminalStatusesPreserveActualProgramDisposition(t *testing.T) {
	for _, tc := range []struct {
		name, body, message string
		exit, signal        int
		outcome             bool
	}{
		{"success", `printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n' >&3`, "", 0, 0, true},
		{"nonzero", `printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n' >&3; exit 3`, "exit status 3", 3, 0, true},
		{"nonzero and invalid result", `echo bad >&3; exit 3`, "exit status 3", 3, 0, false},
		{"signal", `printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n' >&3; kill -TERM $$`, "signal: terminated", -1, int(syscall.SIGTERM), true},
		{"deferred ignores bad result", `echo bad >&3; exit 75`, "deferred", 75, 0, false},
		{"invalid result", `echo bad >&3`, "not one JSON object", 0, 0, false},
		{"truncated result retains finished feed", `printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n{"ver' >&3`, "not one JSON object", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := program(t, tc.body)
			log := independentLog(t)
			result, err := p.Run(context.Background(), Request{Trigger: "apply"}, log)
			if (tc.message == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tc.message) {
				t.Errorf("Run = %+v, %v; want message %q", result, err, tc.message)
			}
			if (result.Outcomes["ipv4:a_v4"] == "success") != tc.outcome {
				t.Errorf("finished outcome = %+v, want present=%t", result, tc.outcome)
			}
			state := awaitWorkerCompletion(t, log.Name())
			if state.Signal != tc.signal || tc.exit >= 0 && (state.ExitCode == nil || *state.ExitCode != tc.exit) {
				t.Errorf("durable exit disposition = %+v, want exit%d signal%d", state, tc.exit, tc.signal)
			}
		})
	}
}

func TestWorkerTerminalRecordPreservesCoreDumpAsData(t *testing.T) {
	valid := validWorkerJSON(t)
	state, err := decodeWorkerState(strings.NewReader(valid[:len(valid)-1] + `,"finishedAt":101,"signal":6,"coreDumped":true}`))
	if err != nil {
		t.Fatalf("valid core-dump disposition rejected: %v", err)
	}
	_, err = state.outcome()
	if err == nil || !strings.Contains(err.Error(), "core dumped") {
		t.Fatalf("core-dump error = %v, want actual core-dump disposition retained", err)
	}
}

func TestWorkerSpawnFailurePublishesFailureAndReleasesOwnership(t *testing.T) {
	log := independentLog(t)
	_, err := (&Command{Path: filepath.Join(t.TempDir(), "missing")}).Run(context.Background(), Request{Trigger: "apply"}, log)
	if err == nil {
		t.Fatal("missing program reported success")
	}
	state := awaitWorkerCompletion(t, log.Name())
	if state.Failure == "" || state.ExitCode != nil || state.Signal != 0 {
		t.Fatalf("spawn failure state = %+v, want failure without invented program status", state)
	}
}

func TestWorkerRequiresValidReleaseAndRequestBeforeLaunchingProgram(t *testing.T) {
	for _, mode := range []string{"EOF", "wrong byte", "malformed request", "missing descriptors"} {
		t.Run(mode, func(t *testing.T) {
			p, dir := program(t, `echo unadmitted > "$D/started"`)
			log := independentLog(t)
			lock, err := operationLock(log.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			body := strings.Replace(validWorkerJSON(t), "/bin/true", p.Path, 1)
			if mode == "malformed request" {
				body = "{"
			}
			if err := os.WriteFile(log.Name()+".request", []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			request, err := os.Open(log.Name() + ".request")
			if err != nil {
				t.Fatal(err)
			}
			defer request.Close()
			result, err := os.OpenFile(log.Name()+".result", os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			ready, readyW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer ready.Close()
			defer readyW.Close()
			release, releaseW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer release.Close()
			defer releaseW.Close()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(self, workerArg, log.Name())
			cmd.Stdout, cmd.Stderr = log, log
			if mode != "missing descriptors" {
				cmd.ExtraFiles = []*os.File{request, lock, log, result, readyW, release}
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			readyW.Close()
			release.Close()
			if err := ready.SetReadDeadline(time.Now().Add(stuck)); err != nil {
				t.Fatal(err)
			}
			var ack [1]byte
			_, ackErr := io.ReadFull(ready, ack[:])
			if mode == "EOF" || mode == "wrong byte" {
				if ackErr != nil || ack[0] != 1 {
					t.Fatalf("ownership ack = %v, %v; want1", ack, ackErr)
				}
				if mode == "wrong byte" {
					if _, err := releaseW.Write([]byte{2}); err != nil {
						t.Fatal(err)
					}
				}
			} else if ackErr == nil {
				t.Fatalf("invalid setup acknowledged ownership: %v", ack)
			}
			releaseW.Close()
			lock.Close()
			if err := cmd.Wait(); err == nil {
				t.Error("uncommitted worker reported success")
			}
			if _, err := os.Stat(filepath.Join(dir, "started")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unadmitted program started: %v", err)
			}
			free, err := operationLock(log.Name())
			if err != nil {
				t.Fatalf("aborted worker retained lifetime lock: %v", err)
			}
			free.Close()
		})
	}
}

func TestWorkerControlDescriptorsDoNotKeepLockInSurvivingService(t *testing.T) {
	p, dir := program(t, `sh -c 'exec 4<> "$D/service"; echo ready > "$D/service-ready"; read release <&4; echo done > "$D/service-done"' &
while [ ! -f "$D/service-ready" ]; do :; done
printf '{"version":1}\n' >&3`)
	// D must reach the actual exec descendant, not only its launching shell.
	body, err := os.ReadFile(p.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Path, []byte(strings.Replace(string(body), "D='", "export D='", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "service"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	_, runErr := p.Run(context.Background(), Request{Trigger: "apply"}, log)
	lock, lockErr := operationLock(log.Name())
	if lockErr == nil {
		lock.Close()
	}
	fd, err := syscall.Open(filepath.Join(dir, "service"), syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("intentional service did not survive completion: %v", err)
	}
	f := os.NewFile(uintptr(fd), "service-release")
	_, err = fmt.Fprintln(f, "finish")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(dir, "service-done"))
	if runErr != nil || lockErr != nil {
		t.Fatalf("Run/independent lifetime lock reacquire = %v/%v; control descriptor leaked to service", runErr, lockErr)
	}
}

func TestWorkerBoundsFinalOutputEvenAfterObserverLeaves(t *testing.T) {
	p, dir := program(t, `exec 4<> "$D/release"
echo ready > "$D/ready"
read release <&4
dd if=/dev/zero bs=1048576 count=9 2>/dev/null
printf '\nnewest-output\n'`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := independentLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	_ = recv(t, ended, "observer did not stop")
	releaseIndependent(t, dir)
	_ = awaitWorkerCompletion(t, log.Name())
	info, err := log.Stat()
	if err != nil || info.Size() > maxLog/2 {
		t.Fatalf("completed log size = %v, %v; want <=%d", info, err, maxLog/2)
	}
	if body := logText(t, log); !strings.HasSuffix(body, "newest-output\n") {
		t.Fatalf("bounded log lost newest output; suffix = %q", body[max(0, len(body)-80):])
	}
}
