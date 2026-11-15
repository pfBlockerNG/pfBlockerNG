package update

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestGateStartAdmitsBeforeTruncatingTheLog(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := dir + "/update.log"
	if err := os.WriteFile(logPath, []byte("previous-update\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(logPath+".status", 0o700); err != nil {
		t.Fatal(err)
	}
	g := New(logPath, func(ctx context.Context, req Request, log *os.File) (Result, error) {
		t.Error("the program ran after admission failed")
		return Result{}, nil
	}, nil)
	g.Admit = (&Command{Path: "/bin/true"}).Admit
	t.Cleanup(g.Stop)
	if err := g.Start(Request{Trigger: "apply"}, nil); err == nil {
		t.Fatal("hostile worker state admitted a new Update")
	}
	body, err := os.ReadFile(logPath)
	if err != nil || string(body) != "previous-update\n" {
		t.Fatalf("log = %q, %v; want the previous Update untouched", body, err)
	}
}

func TestWorkerViewUsesLocalStatusOnlyBeforeFirstPublication(t *testing.T) {
	log := independentLog(t)
	command := &Command{Path: "/bin/true"}
	entered, release := make(chan struct{}), make(chan struct{})
	g := New(log.Name(), nil, nil)
	g.Admit = command.Admit
	g.Launch = func(context.Context, *Admission, Request, *os.File) (Result, error) {
		close(entered)
		<-release
		return Result{}, errors.New("fixture stopped before publication")
	}
	t.Cleanup(g.Stop)
	req := Request{Trigger: "manual", Scope: "ip", Force: "none"}
	if err := g.Start(req, nil); err != nil {
		t.Fatal(err)
	}
	recv(t, entered, "local launch did not enter its prepublication window")
	view, err := g.View(0, 0)
	if err != nil || !view.Running || view.Update == nil || view.Update.Trigger != req.Trigger || view.Update.Scope != req.Scope {
		t.Fatalf("local prepublication View = %+v, %v; want admitted in-memory status", view, err)
	}
	if _, err := os.Stat(log.Name() + ".status"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture published worker status before the guarded View: %v", err)
	}
	restarted := New(log.Name(), nil, nil)
	restarted.Admit = command.Admit
	if view, err := restarted.View(0, 0); err == nil {
		t.Fatalf("restarted Gate used another process's in-memory fallback: %+v", view)
	}
	close(release)
	settle(t, g)
	if err := os.WriteFile(log.Name()+".status", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := New(log.Name(), nil, nil)
	malformed.Admit = command.Admit
	if view, err := malformed.View(0, 0); err == nil {
		t.Fatalf("malformed worker status used in-memory fallback: %+v", view)
	}
}
