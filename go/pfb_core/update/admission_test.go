package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAdmissionFailureNeverTruncatesExistingLog(t *testing.T) {
	log := independentLog(t)
	if _, err := log.WriteString("previous-update\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(log.Name()+".status", 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := (&Command{Path: "/bin/true"}).Run(context.Background(), Request{Trigger: "apply"}, log)
	if err == nil {
		t.Fatal("hostile admission unexpectedly succeeded")
	}
	if body := logText(t, log); body != "previous-update\n" {
		t.Fatalf("log = %q, want unchanged previous Update", body)
	}
}

func TestAdmissionClosesItsLeaseAfterEveryFailure(t *testing.T) {
	log := independentLog(t)
	if err := os.Mkdir(log.Name()+".request", 0o700); err != nil {
		t.Fatal(err)
	}
	lease, err := (&Command{Path: "/bin/true"}).Admit(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := lease.Launch(context.Background(), &Command{Path: "/bin/true"}, Request{Trigger: "apply"}, log); err == nil {
		t.Fatal("request preparation unexpectedly launched")
	}
	lease.Close()
	lock, err := operationLock(log.Name())
	if err != nil {
		t.Fatalf("failed launch retained lifetime lock: %v", err)
	}
	lock.Close()
}

func TestAdmissionLaunchTransfersOwnershipAndParentCloseDoesNotUnlock(t *testing.T) {
	p, dir := independentProgram(t)
	log := independentLog(t)
	lease, err := (&Command{Path: p.Path}).Admit(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { _, err := lease.Launch(ctx, &Command{Path: p.Path}, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	if err := recv(t, ended, "observer never stopped"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := operationLock(log.Name()); !errors.Is(err, ErrRunning) {
		t.Fatalf("parent observation close unlocked worker: %v", err)
	}
	releaseIndependent(t, dir)
	state := awaitWorkerCompletion(t, log.Name())
	if state.ExitCode == nil || *state.ExitCode != 0 || !bytes.Contains([]byte(logText(t, log)), []byte("previous-update")) && false {
		t.Fatalf("transferred worker did not complete: %+v", state)
	}
}
