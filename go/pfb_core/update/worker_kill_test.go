package update

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestKilledWorkerDoesNotLetTheLiveProgramWriteTheNextAdmission(t *testing.T) {
	p, dir := program(t, `echo $$ > "$D/child"; echo ready > "$D/ready"; while [ ! -f "$D/go" ]; do sleep 0.05; done; echo OLDPHP; printf '%s\n' '{"version":1,"outcomes":{"ipv4:old_v4":"success"},"attempted":["ipv4:old_v4"]}' >&3; echo wrote > "$D/wrote"`)
	log := independentLog(t)
	go func() { _, _ = p.Run(context.Background(), Request{Trigger: "apply"}, log) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	php := recordedPid(t, dir)
	text, err := os.ReadFile("/proc/" + strconv.Itoa(php) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	worker := 0
	for _, line := range strings.Split(string(text), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			worker, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		}
	}
	if worker <= 1 {
		t.Fatalf("program parent = %d, want the worker", worker)
	}
	if err := syscall.Kill(worker, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(php, syscall.SIGKILL) })
	deadline := time.Now().Add(2 * time.Second)
	for {
		lock, err := operationLock(log.Name())
		if err == nil {
			lock.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	next, dir2 := program(t, `echo NEW; printf '%s\n' '{"version":1,"attempted":["ipv4:new_v4"]}' >&3; echo ran > "$D/ran"`)
	g := New(log.Name(), nil, nil)
	g.Admit = next.Admit
	g.Launch = func(ctx context.Context, lease *Admission, req Request, f *os.File) (Result, error) {
		return lease.Launch(ctx, next, req, f)
	}
	if err := g.Start(Request{Trigger: "apply"}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Stop)
	awaitFile(t, filepath.Join(dir2, "ran"))
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(dir, "wrote"))
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
}

func TestKilledWorkerSalvagesAFinishedResult(t *testing.T) {
	p, dir := program(t, `printf '%s\n' '{"version":1,"outcomes":{"ipv4:old_v4":"success"},"attempted":["ipv4:old_v4"]}' >&3; echo $$ > "$D/child"; echo ready > "$D/ready"; while [ ! -f "$D/go" ]; do sleep 0.05; done`)
	log := independentLog(t)
	go func() { _, _ = p.Run(context.Background(), Request{Trigger: "apply"}, log) }()
	awaitFile(t, filepath.Join(dir, "ready"))
	php := recordedPid(t, dir)
	text, err := os.ReadFile("/proc/" + strconv.Itoa(php) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	worker := 0
	for _, line := range strings.Split(string(text), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			worker, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		}
	}
	if err := syscall.Kill(worker, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(php, syscall.SIGKILL) })
	var got Result
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = Recover(log.Name(), func(_ int64, _ map[string]int64, res Result, _ error) error {
			got = res
			return nil
		})
		if err == nil && got.Outcomes["ipv4:old_v4"] == "success" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("finished result was not salvaged: %v %+v", err, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
