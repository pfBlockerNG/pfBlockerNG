// The query channel's oracle rows (testdata/pfb_unbound_query_oracle.json): each scenario boots a module with the
// fixture's snapshot, stops its watcher and replays the steps through drainAndAnswer, comparing the reply file byte for
// byte, its mode and what the watcher wrote to stderr with what the shipped Python left.
package decider

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQueryChannelMatchesPythonOracle(t *testing.T) {
	oracle := loadQueryOracle(t)
	for _, sc := range oracle.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			dir := t.TempDir()
			m := modMust(t, dir)
			m.stopQueryWatcher() // the steps drive the watcher by hand
			m.snapshot.Store(oracle.Fixtures[sc.Fixture].snapshot(t))
			channel, reply := filepath.Join(dir, "pfb_py_query"), filepath.Join(dir, "pfb_py_query.reply")
			switch sc.ReplyMode {
			case "missing-dir":
				m.pfb.pfbPyQueryReply = filepath.Join(dir, "gone", "pfb_py_query.reply")
			case "is-dir":
				if err := os.Mkdir(reply, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			logs := modCaptureLog(t)
			w := m.newQueryWatcher()
			for i, step := range sc.Steps {
				label := fmt.Sprintf("step %d %s %.60q", i, step.Op, step.Text+step.B64)
				queryApply(t, channel, step)
				logs.Reset()
				takePyError()
				queryDrain(t, w)

				var got *string
				var mode string
				if data, err := os.ReadFile(reply); err == nil {
					text := string(data)
					got = &text
					info, err := os.Stat(reply)
					if err != nil {
						t.Fatal(err)
					}
					mode = fmt.Sprintf("0o%o", info.Mode().Perm())
					os.Remove(reply)
				}
				switch {
				case (got == nil) != (step.Reply == nil), got != nil && *got != *step.Reply:
					t.Errorf("%s: reply = %v, want %v", label, queryShow(got), queryShow(step.Reply))
				case step.Mode != nil && mode != *step.Mode:
					t.Errorf("%s: reply mode = %s, want %s", label, mode, *step.Mode)
				}
				// Python's sys.stderr is the py_error.log logger, which does not log a message equal to the one before it, so the
				// oracle recorded the rows that file got, and the suppression state runs on from step to step. The process
				// stderr stays empty.
				want := strings.ReplaceAll(step.PyError, "<dir>", dir)
				if got := takePyError(); got != want || logs.Len() != 0 {
					t.Errorf("%s: py_error.log rows = %q, want %q; process stderr = %q", label, got, want, logs.String())
				}
				for _, leftover := range []string{reply + ".tmp", m.pfb.pfbPyQueryReply + ".tmp"} {
					if _, err := os.Lstat(leftover); err == nil {
						t.Errorf("%s: %s is left behind", label, leftover)
					}
				}
			}
		})
	}
}

func queryShow(s *string) string {
	if s == nil {
		return "no reply"
	}
	return *s
}

// queryApply does the step to the channel: a file written next to it and renamed over it, a directory in its place, or
// nothing at all.
func queryApply(t *testing.T, channel string, step queryStep) {
	t.Helper()
	data := []byte(step.Text)
	switch step.Op {
	case "bytes":
		var err error
		if data, err = base64.StdEncoding.DecodeString(step.B64); err != nil {
			t.Fatal(err)
		}
	case "dir", "remove":
		data = nil
	case "text":
	default:
		t.Fatalf("unknown step op %q", step.Op)
	}
	if err := os.RemoveAll(channel); err != nil {
		t.Fatal(err)
	}
	switch step.Op {
	case "dir":
		if err := os.Mkdir(channel, 0o755); err != nil {
			t.Fatal(err)
		}
	case "remove":
	default:
		if err := os.WriteFile(channel, data, 0o660); err != nil {
			t.Fatal(err)
		}
	}
}

// A request whose evaluation fails is logged and skipped, and the next one is still answered: nothing restarts the
// watcher. A snapshot without settings makes the matcher panic.
func TestQueryWatcherSurvivesARequestThatPanics(t *testing.T) {
	oracle := loadQueryOracle(t)
	dir := t.TempDir()
	m := modMust(t, dir)
	m.stopQueryWatcher()
	broken := oracle.Fixtures["plain"].snapshot(t)
	broken.settings = nil
	m.snapshot.Store(broken)
	logs := modCaptureLog(t)
	w := m.newQueryWatcher()
	channel, reply := filepath.Join(dir, "pfb_py_query"), filepath.Join(dir, "pfb_py_query.reply")

	queryApply(t, channel, queryStep{Op: "text", Text: `{"id": "boom", "domain": "listed.example.com"}`})
	queryDrain(t, w)
	if want := "[pfBlockerNG]: query watcher failed to answer a request: "; !strings.HasPrefix(drainPyError(), want) || logs.Len() != 0 {
		t.Errorf("want py_error.log to start with %q and the process stderr empty, got stderr %q", want, logs.String())
	}
	if _, err := os.Stat(reply); err == nil {
		t.Errorf("a reply was written for the request that panicked")
	}

	m.snapshot.Store(oracle.Fixtures["plain"].snapshot(t))
	queryApply(t, channel, queryStep{Op: "text", Text: `{"id": "next", "domain": "clean.example.com"}`})
	queryDrain(t, w)
	got, err := os.ReadFile(reply)
	if err != nil || !strings.Contains(string(got), `"id": "next"`) {
		t.Errorf("reply after the panic = %q, %v; want the answer to the next request", got, err)
	}
}

// The one write a query makes is the decision memo, stamped with the snapshot's generation, the way operate() memoizes.
func TestQueryAnswerMemoizesTheDecisionOnTheLiveSnapshot(t *testing.T) {
	oracle := loadQueryOracle(t)
	m := modMust(t, t.TempDir())
	m.stopQueryWatcher()
	snap := oracle.Fixtures["plain"].snapshot(t)
	m.snapshot.Store(snap)
	m.dnsblQueryAnswer("Listed.Example.Com.")
	dec, ok := m.decisionDB.get("listed.example.com")
	if !ok || dec.snapGen != snap.gen {
		t.Fatalf("decisionDB entry = %v, %v; want one stamped with generation %d", dec, ok, snap.gen)
	}
	if got, _ := dec.getDnsbl().(*dnsblDecision); got == nil || !got.isFound {
		t.Errorf("the memoized decision = %+v, want the found verdict", dec.getDnsbl())
	}
}

// Python starts the watcher in init whatever the settings; stopping ends it, a second stop is harmless and it starts
// again; one that runs is not started twice.
func TestQueryWatcherLifecycle(t *testing.T) {
	m := modMust(t, t.TempDir())
	if m.queryStop == nil {
		t.Fatal("the watcher is not running after init")
	}
	started := 0
	m.queryTick = func() (<-chan time.Time, func()) {
		started++
		return make(chan time.Time), func() {}
	}
	m.startQueryWatcher() // already running
	if started != 0 {
		t.Errorf("a running watcher was started again")
	}
	m.stopQueryWatcher()
	if m.queryStop != nil {
		t.Errorf("the watcher is still marked running after stopQueryWatcher")
	}
	m.stopQueryWatcher()
	m.startQueryWatcher()
	if started != 1 || m.queryStop == nil {
		t.Errorf("after a stop, a start: started = %d, running = %v; want 1, true", started, m.queryStop != nil)
	}
}
