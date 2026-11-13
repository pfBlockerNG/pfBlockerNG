package update

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// writes is a RunFunc for a Gate that writes the text its request names in Trigger and ends.
func writes(_ context.Context, req Request, log *os.File) (Result, error) {
	_, err := log.WriteString(req.Trigger)
	return Result{}, err
}

// A cursor belongs to the Update that issued it: a longer new log must not be read from the old offset.
func TestACursorOfAnEarlierUpdateReadsTheNewLogFromZeroEvenWhenTheNewLogIsLonger(t *testing.T) {
	const first, second = "short\n", "a second log, longer than the first one's whole length\n"
	g := newGate(t, writes, nil)
	if err := g.Start(Request{Trigger: first}); err != nil {
		t.Fatal(err)
	}
	settle(t, g)
	old := g.View(0, 0)
	if old.Log != first {
		t.Fatalf("the first Update's View = %s, want its log %q", jsonOf(t, old), first)
	}
	if err := g.Start(Request{Trigger: second}); err != nil {
		t.Fatal(err)
	}
	settle(t, g)
	v := g.View(old.Next, 0)
	if v.Log != second {
		t.Errorf("View with the first Update's cursor = %q, want the second Update's whole log %q", v.Log, second)
	}
	if again := g.View(v.Next, 0); again.Log != "" || again.Next != v.Next {
		t.Errorf("View from the cursor the second Update's View returned = log %q next %d, want nothing new and the same cursor %d", again.Log, again.Next, v.Next)
	}
	if v.Next == old.Next {
		t.Errorf("the second Update's cursor %d equals the first's: it cannot tell the two logs apart", v.Next)
	}
}

// A chunk may end inside a rune only when the rune is whole in the log or the Update is over.
func TestAViewHoldsBackARuneStillBeingWrittenAtTheEndOfARunningLog(t *testing.T) {
	h := newHold()
	g := newGate(t, h.run, nil)
	if err := g.Start(Request{Trigger: "manual"}); err != nil {
		t.Fatal(err)
	}
	h.write(t, "ab\xe2\x82") // the first two bytes of the euro sign
	v := g.View(0, 0)
	if v.Log != "ab" {
		t.Fatalf("View(0) = %q, want %q: the half written rune waits", v.Log, "ab")
	}
	h.write(t, "\xac!")
	w := g.View(v.Next, 0)
	if w.Log != "\u20ac!" {
		t.Fatalf("View after the rune was finished = %q, want %q", w.Log, "\u20ac!")
	}
	h.write(t, "\xf0\x9d") // the first two bytes of a rune that is all there is left to read
	x := g.View(w.Next, 0)
	if x.Log != "" || x.Next != w.Next {
		t.Errorf("View of a lone half written rune = log %q next %d, want nothing and the cursor kept at %d", x.Log, x.Next, w.Next)
	}
	h.write(t, "\x84\x9e")
	if y := g.View(x.Next, 0); y.Log != "\U0001d11e" {
		t.Errorf("View after that rune was finished = %q, want %q", y.Log, "\U0001d11e")
	}
	h.finish(t, nil)
}

func TestAViewOfAFinishedLogDeliversATrailingHalfRuneAndReachesTheEnd(t *testing.T) {
	g := newGate(t, writes, nil)
	if err := g.Start(Request{Trigger: "x\xe2"}); err != nil {
		t.Fatal(err)
	}
	settle(t, g)
	v := g.View(0, 0)
	if v.Running || v.Log != "x\xe2" {
		t.Fatalf("View of a finished log ending inside a rune = running %v log %q, want the whole log %q", v.Running, v.Log, "x\xe2")
	}
	if again := g.View(v.Next, 0); again.Log != "" || again.Next != v.Next {
		t.Errorf("View from the end = log %q next %d, want nothing and the cursor kept at %d", again.Log, again.Next, v.Next)
	}
}

// A daemon an Update started keeps the Update's log descriptor after the Update ends. A new Update truncates the log; the
// stray write must then land at the new end (O_APPEND), not at the old offset past it, which would pad the log with NULs.
func TestAWriterHoldingAnEarlierUpdatesLogFdAppendsToTheNewLogWithoutAHole(t *testing.T) {
	var stray *os.File
	run := func(_ context.Context, req Request, log *os.File) (Result, error) {
		if req.Trigger == "first" {
			fd, err := syscall.Dup(int(log.Fd()))
			if err != nil {
				return Result{}, err
			}
			stray = os.NewFile(uintptr(fd), "stray")
			_, err = log.WriteString("the first Update's line\n")
			return Result{}, err
		}
		_, err := log.WriteString("second\n")
		return Result{}, err
	}
	path := filepath.Join(t.TempDir(), "update.log")
	g := New(path, run, nil)
	t.Cleanup(g.Stop)
	t.Cleanup(func() {
		if stray != nil {
			_ = stray.Close()
		}
	})
	for _, trigger := range []string{"first", "second"} {
		if err := g.Start(Request{Trigger: trigger}); err != nil {
			t.Fatal(err)
		}
		settle(t, g)
	}
	if stray == nil {
		t.Fatal("the first Update never kept its log descriptor")
	}
	if _, err := stray.WriteString("STRAY\n"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "second\nSTRAY\n"; string(raw) != want || bytes.IndexByte(raw, 0) >= 0 {
		t.Errorf("the log = %q, want %q with no NUL: the stray write must append after the truncation", raw, want)
	}
	if v := g.View(0, 0); v.Log != "second\nSTRAY\n" {
		t.Errorf("View(0) = %q, want %q", v.Log, "second\nSTRAY\n")
	}
}
