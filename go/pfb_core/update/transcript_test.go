package update

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func newTranscriptGate(t *testing.T, path string, command *Command) (*Gate, <-chan error) {
	t.Helper()
	done := make(chan error, 1)
	g := New(path, nil, func(Request, Result, error) {
		done <- Recover(path, func(int64, map[string]int64, Result, error) error { return nil })
	})
	g.Admit = command.Admit
	g.Launch = func(ctx context.Context, lease *Admission, req Request, log *os.File) (Result, error) {
		return lease.Launch(ctx, command, req, log)
	}
	t.Cleanup(g.Stop)
	return g, done
}

func TestUpdateTranscriptRetainsLargeOutputCursorsAndRunIdentity(t *testing.T) {
	command, dir := program(t, `exec 4<> "$D/hold"
printf 'EARLY\n'
echo ready > "$D/ready"
read release <&4
dd if=/dev/zero bs=1048576 count=4 2>/dev/null | tr '\000' A
printf '\nMIDDLE\n'
dd if=/dev/zero bs=1048576 count=4 2>/dev/null | tr '\000' B
printf '\nTAIL\n'
sleep 2
echo checked > "$D/checked"
read release <&4
printf '{"version":1}\n' >&3`)
	if err := syscall.Mkfifo(filepath.Join(dir, "hold"), 0o600); err != nil {
		t.Fatal(err)
	}
	hold, err := os.OpenFile(filepath.Join(dir, "hold"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = hold.WriteString("release\nrelease\n")
		_ = hold.Close()
	})

	log := independentLog(t)
	g, done := newTranscriptGate(t, log.Name(), command)
	if err := g.Start(Request{Trigger: "apply"}, nil); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(dir, "ready"))
	first := mustView(t, g, 0, 64<<10)
	second := mustView(t, g, 0, 64<<10)
	if first.Log != "EARLY\n" || second.Log != first.Log || second.Next != first.Next {
		t.Fatalf("independent initial Views = (%q, %d)/(%q, %d); want the same early bytes and cursor", first.Log, first.Next, second.Log, second.Next)
	}
	if err := g.Start(Request{Trigger: "retry"}, nil); !errors.Is(err, ErrRunning) {
		t.Fatalf("concurrent Start = %v; want ErrRunning", err)
	}
	if body, err := os.ReadFile(log.Name()); err != nil || string(body) != "EARLY\n" {
		t.Fatalf("rejected admission changed transcript = %q, %v", body, err)
	}
	if _, err := hold.WriteString("burst\n"); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(dir, "checked"))

	const block = 4 << 20
	expected := append([]byte("EARLY\n"), bytes.Repeat([]byte{'A'}, block)...)
	expected = append(expected, []byte("\nMIDDLE\n")...)
	expected = append(expected, bytes.Repeat([]byte{'B'}, block)...)
	expected = append(expected, []byte("\nTAIL\n")...)
	if len(expected) <= 8<<20 {
		t.Fatalf("fixture wrote %d bytes; want more than 8 MiB", len(expected))
	}
	if body, err := os.ReadFile(log.Name()); err != nil || !bytes.Equal(body, expected) {
		t.Fatalf("running transcript has %d bytes, %v; want all %d bytes including early, middle and tail markers", len(body), err, len(expected))
	}
	state, err := readWorkerState(log.Name() + ".status")
	if err != nil || state.FinishedAt != nil || state.LogGen != 0 {
		t.Fatalf("running receipt = %+v, %v; want unfinished generation 0", state, err)
	}

	third := mustView(t, g, 0, 64<<10)
	if len(third.Log) != 64<<10 || third.Next != 64<<10 {
		t.Fatalf("second reader advanced to %d with %d bytes; want stable offset 65536", third.Next, len(third.Log))
	}
	views := make([]View, 2)
	viewErrs := make(chan error, 2)
	for i, after := range []int64{first.Next, third.Next} {
		go func(i int, after int64) {
			view, err := g.View(after, len(expected))
			views[i] = view
			viewErrs <- err
		}(i, after)
	}
	for range views {
		if err := <-viewErrs; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal([]byte(views[0].Log), expected[len("EARLY\n"):]) || views[0].Next != int64(len(expected)) {
		t.Fatalf("first cursor read %d bytes through %d; want full transcript tail through %d", len(views[0].Log), views[0].Next, len(expected))
	}
	if !bytes.Equal([]byte(views[1].Log), expected[third.Next:]) || views[1].Next != int64(len(expected)) {
		t.Fatalf("independent cursor read %d bytes through %d; want its exact remaining bytes through %d", len(views[1].Log), views[1].Next, len(expected))
	}
	if _, err := hold.WriteString("finish\n"); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, done, "Update receipt was not settled"); err != nil {
		t.Fatal(err)
	}
	settle(t, g)
	state, err = readWorkerState(log.Name() + ".status")
	if err != nil || !state.Settled || state.FinishedAt == nil {
		t.Fatalf("completed receipt after transcript reads = %+v, %v; want settled terminal state", state, err)
	}

	restarted := New(log.Name(), nil, nil)
	restarted.Admit = command.Admit
	restartedView, err := restarted.View(0, math.MaxInt32)
	if err != nil || restartedView.Running || restartedView.Update == nil || restartedView.Update.FinishedAt == nil || restartedView.Update.Result != "success" || restartedView.Log != string(expected) {
		t.Fatalf("restarted View = %+v, %v; want settled completion and the complete transcript", restartedView, err)
	}

	oldFD, err := os.OpenFile(log.Name(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFD.Close()
	oldCursor := restartedView.Next
	secondCommand, secondDir := program(t, `printf 'NEW-RUN\n'
printf '{"version":1}\n' >&3
echo ready > "$D/ready"`)
	secondGate, secondDone := newTranscriptGate(t, log.Name(), secondCommand)
	if err := secondGate.Start(Request{Trigger: "retry"}, nil); err != nil {
		t.Fatal(err)
	}
	awaitFile(t, filepath.Join(secondDir, "ready"))
	if _, err := oldFD.WriteString("OLD-DESCRIPTOR\n"); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, secondDone, "second Update receipt was not settled"); err != nil {
		t.Fatal(err)
	}
	settle(t, secondGate)
	secondState, err := readWorkerState(log.Name() + ".status")
	if err != nil || !secondState.Settled || secondState.LogGen != 1 {
		t.Fatalf("second admission receipt = %+v, %v; want settled generation 1", secondState, err)
	}
	secondView := mustView(t, secondGate, oldCursor, math.MaxInt32)
	if secondView.Log != "NEW-RUN\n" || secondView.Next == oldCursor {
		t.Fatalf("old cursor after new admission = %+v; want new-run bytes under a fresh identity", secondView)
	}
	if body, err := os.ReadFile(log.Name()); err != nil || string(body) != "NEW-RUN\n" {
		t.Fatalf("old descriptor contaminated new transcript = %q, %v", body, err)
	}
}
