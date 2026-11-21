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

func TestAHeldDescriptorCannotWriteTheNextAdmission(t *testing.T) {
	log := independentLog(t)
	held, err := os.OpenFile(log.Name(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	resultHeld, err := os.OpenFile(log.Name()+".result", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer resultHeld.Close()
	fresh, err := replaceRegular(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	replaced, err := replaceRegular(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replaced.WriteString("{\"version\":1,\"attempted\":[\"ipv4:new_v4\"]}\n"); err != nil {
		t.Fatal(err)
	}
	replaced.Close()
	if _, err := held.WriteString("OLDPHP\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := resultHeld.WriteString("{\"version\":1,\"outcomes\":{\"ipv4:old_v4\":\"success\"}}\n"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "OLDPHP") || strings.Contains(string(result), "old_v4") {
		t.Fatalf("a descriptor opened before replacement wrote the next admission: log=%q result=%q", body, result)
	}
}

func TestACompleteResultIsSalvagedOnceWhenTheWorkerDidNotPublish(t *testing.T) {
	log := independentLog(t)
	body := validWorkerJSON(t)
	if err := os.WriteFile(log.Name()+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log.Name()+".result", []byte("{\"version\":1,\"outcomes\":{\"ipv4:old_v4\":\"success\"},\"attempted\":[\"ipv4:old_v4\"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := Recover(log.Name(), func(_ int64, _ map[string]int64, res Result, _ error) error {
		calls++
		if res.Outcomes["ipv4:old_v4"] != "success" {
			t.Fatalf("salvaged result = %+v", res)
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("Recover = %v, callbacks = %d; want one salvage", err, calls)
	}
	if err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("second Recover = %v, callbacks = %d; a salvaged receipt was applied again", err, calls)
	}
}

func TestSettledReceiptIsNotReapplied(t *testing.T) {
	log := independentLog(t)
	body := validWorkerJSON(t)
	body = body[:len(body)-1] + `,"finishedAt":101,"exitCode":0,"settled":true}`
	if err := os.WriteFile(log.Name()+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("settled receipt was applied %d times; receipt=%s", calls, strings.TrimSpace(body))
	}
}

func TestOwnedWorkerCrashDoesNotContaminateTheNextAdmission(t *testing.T) {
	p, dir := program(t, `echo ready > "$D/ready"; read _ < "$D/release"; echo OLDPHP; printf '%s\n' '{"version":1,"outcomes":{"ipv4:old_v4":"success"},"attempted":["ipv4:old_v4"]}' >&3; echo wrote > "$D/wrote"; read _ < "$D/release"; echo finished > "$D/finished"`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(filepath.Join(dir, "release"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = release.WriteString("write\nfinish\n"); _ = release.Close() })
	log := independentLog(t)
	cmd, err := startOwnedWorker(t, p.Path, log, false)
	if err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	awaitFile(t, dir+"/ready")
	oldLog, err := os.Open(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer oldLog.Close()
	oldResult, err := os.Open(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	defer oldResult.Close()
	oldLogInfo, err := oldLog.Stat()
	if err != nil {
		t.Fatal(err)
	}
	oldResultInfo, err := oldResult.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("the killed worker returned a nil error")
	}
	reaped = true
	calls := 0
	if err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	}); err != nil || calls != 0 {
		t.Fatalf("unfinished empty result was applied: %v calls=%d", err, calls)
	}
	next, nextDir := program(t, `echo NEW; printf '%s\n' '{"version":1,"attempted":["ipv4:new_v4"]}' >&3; echo ran > "$D/ran"`)
	g := New(log.Name(), nil, nil)
	g.Admit = next.Admit
	if err := g.Start(Request{Trigger: "apply"}, nil); !errors.Is(err, ErrRunning) {
		t.Fatalf("second admission while the native program lived = %v, want ErrRunning", err)
	}
	if _, err := os.Stat(filepath.Join(nextDir, "ran")); !os.IsNotExist(err) {
		t.Fatalf("a second native program started while the first lived: %v", err)
	}
	if _, err := release.WriteString("write\nfinish\n"); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, dir+"/wrote")
	awaitFile(t, dir+"/finished")
	awaitUnlocked(t, log.Name()).Close()
	if err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var nextErr error
	g = New(log.Name(), nil, func(_ Request, _ Result, err error) {
		nextErr = err
		close(done)
	})
	g.Admit = next.Admit
	g.Launch = func(ctx context.Context, lease *Admission, req Request, f *os.File) (Result, error) {
		return lease.Launch(ctx, next, req, f)
	}
	if err := g.Start(Request{Trigger: "apply"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)
	awaitFile(t, nextDir+"/ran")
	recv(t, done, "next worker did not complete")
	if nextErr != nil {
		t.Fatal(nextErr)
	}
	freshLogInfo, err := os.Stat(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	freshResultInfo, err := os.Stat(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldLogInfo, freshLogInfo) || os.SameFile(oldResultInfo, freshResultInfo) {
		t.Fatal("the next admission reused an inode still held by the old program")
	}
	body, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "OLDPHP") || strings.Contains(string(result), "old_v4") {
		t.Fatalf("the live program wrote the next admission: log=%q result=%q", body, result)
	}
	if !strings.Contains(string(result), "new_v4") {
		t.Fatalf("the next admission lost its result: %q", result)
	}
	if _, err := oldLog.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	retiredLog, err := io.ReadAll(oldLog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldResult.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	retiredResult, err := io.ReadAll(oldResult)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(retiredLog), "OLDPHP") || !strings.Contains(string(retiredResult), "old_v4") {
		t.Fatalf("the old program did not write its retired inodes: log=%q result=%q", retiredLog, retiredResult)
	}
}

func TestKilledWorkerSalvagesCompleteResultLinesWithoutClaimingSuccess(t *testing.T) {
	p, dir := program(t, `printf '%s\n' '{"version":1,"outcomes":{"ipv4:complete_v4":"success"}}' >&3; printf '%s' '{"version":1,"outcomes":{"ipv4:unfinished_v4":' >&3; echo ready > "$D/ready"; read _ < "$D/release"; echo finished > "$D/finished"`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(filepath.Join(dir, "release"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = release.WriteString("finish\n"); _ = release.Close() })
	log := independentLog(t)
	cmd, err := startOwnedWorker(t, p.Path, log, false)
	if err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	awaitFile(t, dir+"/ready")
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("the killed worker returned a nil error")
	}
	reaped = true

	calls := 0
	err = Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	})
	if err != nil || calls != 0 {
		t.Fatalf("salvage ran while the native program held the lock: %v calls=%d", err, calls)
	}
	if _, err := release.WriteString("finish\n"); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, dir+"/finished")
	awaitUnlocked(t, log.Name()).Close()
	err = Recover(log.Name(), func(_ int64, _ map[string]int64, res Result, runErr error) error {
		calls++
		if runErr == nil {
			t.Error("partial salvage reported whole Update success")
		}
		if len(res.Outcomes) != 1 || res.Outcomes["ipv4:complete_v4"] != "success" {
			t.Errorf("salvage lost the complete line or counted the unfinished line: %+v", res)
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("Recover = %v, callbacks = %d; want one partial salvage", err, calls)
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.outcome(); err == nil {
		t.Error("salvaged terminal claims whole success")
	}
	if state.ExitCode != nil || state.Signal != 0 {
		t.Fatalf("salvage invented program disposition: exit=%v signal=%d", state.ExitCode, state.Signal)
	}
}

func TestOwnedWorkerSetupFailureReapsDirectCommand(t *testing.T) {
	p, dir := program(t, `echo ran > "$D/ran"`)
	log := independentLog(t)
	cmd, err := startOwnedWorker(t, p.Path, log, true)
	if err == nil || cmd != nil {
		t.Fatalf("closed release setup = cmd %v, error %v; want a reaped failure", cmd, err)
	}
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("setup failure retained worker lifetime lock: %v", err)
	}
	lock.Close()
	if _, err := os.Stat(filepath.Join(dir, "ran")); !os.IsNotExist(err) {
		t.Fatalf("setup failure launched the program: %v", err)
	}
}

func TestWorkerDeathKeepsExclusionUntilTheNativeProgramExits(t *testing.T) {
	p, dir := program(t, `echo ready > "$D/ready"; echo once >> "$D/starts"; read _ < "$D/release"; echo finished > "$D/finished"`)
	if err := syscall.Mkfifo(filepath.Join(dir, "release"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := os.OpenFile(filepath.Join(dir, "release"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = release.WriteString("finish\n"); _ = release.Close() })
	log := independentLog(t)
	cmd, err := startOwnedWorker(t, p.Path, log, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	awaitFile(t, dir+"/ready")
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("the killed worker returned a nil error")
	}
	cmd.Process = nil
	if _, err := operationLock(log.Name()); !errors.Is(err, ErrRunning) {
		t.Fatalf("worker death released admission while the native program lived: %v", err)
	}
	second, secondDir := program(t, `echo second > "$D/second"`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, runErr := second.Run(ctx, Request{Trigger: "apply"}, log); !errors.Is(runErr, ErrRunning) {
		t.Fatalf("second admission = %v, want ErrRunning", runErr)
	}
	if _, err := os.Stat(filepath.Join(secondDir, "second")); !os.IsNotExist(err) {
		t.Fatalf("a second native program started after worker death: %v", err)
	}
}

// awaitUnlocked waits until the operation lock is free and returns it held. A native program writes its "finished"
// marker before the exit that drops the lock it inherited, so the marker alone does not mean the lock is free (#4040).
func awaitUnlocked(t *testing.T, logPath string) *os.File {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		lock, err := operationLock(logPath)
		if err == nil {
			return lock
		}
		if !errors.Is(err, ErrRunning) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: %s.lock was never released", logPath)
		}
	}
}

func startOwnedWorker(t *testing.T, programPath string, log *os.File, closeRelease bool) (*exec.Cmd, error) {
	t.Helper()
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validWorkerJSON(t), "/bin/true", programPath, 1)
	if err := os.WriteFile(log.Name()+".request", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log.Name()+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	request, err := os.Open(log.Name() + ".request")
	if err != nil {
		t.Fatal(err)
	}
	result, err := os.OpenFile(log.Name()+".result", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ready, readyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releasePipe, releaseW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, workerArg, log.Name())
	cmd.Stdout, cmd.Stderr = log, log
	cmd.ExtraFiles = []*os.File{request, lock, log, result, readyW, releasePipe}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	owned := true
	defer func() {
		if owned {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	defer ready.Close()
	defer releaseW.Close()
	defer lock.Close()
	request.Close()
	result.Close()
	readyW.Close()
	releasePipe.Close()
	if err := ready.SetReadDeadline(time.Now().Add(stuck)); err != nil {
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(ready, ack[:]); err != nil {
		return nil, fmt.Errorf("ownership ack = %v: %w", ack, err)
	}
	if ack[0] != 1 {
		return nil, fmt.Errorf("ownership ack = %v, want 1", ack)
	}
	if closeRelease {
		_ = releaseW.Close()
	}
	if _, err := releaseW.Write([]byte{1}); err != nil {
		return nil, err
	}
	owned = false
	return cmd, nil
}
