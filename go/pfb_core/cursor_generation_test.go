package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const cursorGenerationMask int64 = 1<<(63-40) - 1

func nextCursorGeneration(current int64) int64 { return (current + 1) & cursorGenerationMask }

func workerCursorGeneration(t *testing.T, c *runningCore, phase string, view updateView) int64 {
	t.Helper()
	if view.Update == nil {
		t.Fatalf("%s GetUpdate = %+v; want a retained Update", phase, view)
	}
	body, err := os.ReadFile(filepath.Join(c.state, "update.log.status"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		LogGen int64 `json:"logGen"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		t.Fatalf("%s worker receipt: %v", phase, err)
	}
	t.Logf("%s receipt LogGen=%d, returned cursor=%s, running=%t, logBytes=%d",
		phase, receipt.LogGen, view.Next, view.Running, len(view.Log))
	return receipt.LogGen
}

func waitCursorView(t *testing.T, c *runningCore, after, contains string) updateView {
	t.Helper()
	body := `{}`
	if after != "" {
		body = fmt.Sprintf(`{"after":%q}`, after)
	}
	deadline := time.Now().Add(watchdog)
	for {
		reply := c.post("GetUpdate", body)
		if reply.status == http.StatusServiceUnavailable {
			if time.Now().After(deadline) {
				t.Fatalf("GetUpdate stayed unavailable: %s", reply.body)
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		var view updateView
		if reply.status != http.StatusOK || json.Unmarshal(reply.body, &view) != nil {
			t.Fatalf("GetUpdate = %d %s", reply.status, reply.body)
		}
		if view.Update != nil && strings.Contains(view.Log, contains) {
			return view
		}
		if time.Now().After(deadline) {
			t.Fatalf("GetUpdate never showed %q: %+v", contains, view)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func generationFromCursor(t *testing.T, cursor string) int64 {
	t.Helper()
	value, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		t.Fatalf("cursor %q: %v", cursor, err)
	}
	return value >> 40
}

func TestWorkerLogGenerationAdvancesAcrossCoreRestart(t *testing.T) {
	holdQuarters(t)
	dir := scratchDir(t)
	f := newFakeUpdate(t)
	c1 := startCore(t, dir, "--update-cmd", f.path)
	t.Cleanup(f.release)
	wantJSON(t, c1.post("StartUpdate", `{"requestId":"gen-1","trigger":"manual"}`), http.StatusOK, `{}`)
	firstStart := waitCursorView(t, c1, "", "update program started")
	firstGen := workerCursorGeneration(t, c1, "first-live", firstStart)
	firstCursor := firstStart.Next
	f.release()
	firstEnd := c1.waitFinished("manual")
	firstEndGen := workerCursorGeneration(t, c1, "first-finished", firstEnd)
	if firstEndGen != firstGen {
		t.Fatalf("terminal publication changed LogGen %d to %d", firstGen, firstEndGen)
	}
	c1.stop()
	if err := os.Remove(filepath.Join(f.dir, "release")); err != nil {
		t.Fatal(err)
	}

	c2 := startCore(t, dir, "--update-cmd", f.path)
	t.Cleanup(f.release)
	wantJSON(t, c2.post("StartUpdate", `{"requestId":"gen-2","trigger":"manual"}`), http.StatusOK, `{}`)
	secondStart := waitCursorView(t, c2, "", "update program started")
	secondGen := workerCursorGeneration(t, c2, "second-live-after-restart", secondStart)
	if got := generationFromCursor(t, secondStart.Next); got != secondGen {
		t.Errorf("returned cursor generation=%d; want receipt generation %d", got, secondGen)
	}
	t.Logf("admission cursors: first partial=%s, second=%s", firstCursor, secondStart.Next)
	if want := nextCursorGeneration(firstEndGen); secondGen != want {
		t.Errorf("new admission after restart has LogGen=%d, want %d after prior receipt %d", secondGen, want, firstEndGen)
	}
	if secondStart.Next == firstCursor {
		t.Errorf("new Update reused prior cursor %s", firstCursor)
	}
	fromOldCursor := c2.getUpdate(firstCursor)
	if fromOldCursor.Log != secondStart.Log || fromOldCursor.Next != secondStart.Next {
		t.Errorf("old cursor %s read %+v; want the new Update from its start (%+v)", firstCursor, fromOldCursor, secondStart)
	}
	f.release()
	if end := c2.waitFinished("manual"); end.Update.Result != "success" {
		t.Errorf("second Update after recovery = %+v; want success", end.Update)
	}
	if n := f.runs(); n != 2 {
		t.Errorf("program runs = %d; want exactly two admissions", n)
	}
}
