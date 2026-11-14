package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var _ RunFunc = (&Command{}).Run

// program writes a #!/bin/sh script running body into a directory of its own, which the script sees as $D.
func program(t *testing.T, body string) (*Command, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "update.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nD='"+dir+"'\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Command{Path: path}, dir
}

// withResult is a program that copies payload to fd 3 and exits with status.
func withResult(t *testing.T, payload string, status int) *Command {
	t.Helper()
	c, dir := program(t, `cat "$D/result" >&3; exit `+strconv.Itoa(status))
	if err := os.WriteFile(filepath.Join(dir, "result"), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// newLog opens a progress log the way the Gate does: a file for appending.
func newLog(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "update.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func logText(t *testing.T, log *os.File) string {
	t.Helper()
	b, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runCmd runs c under the watchdog, which kills a hung program.
func runCmd(t *testing.T, c *Command, req Request, log *os.File) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), stuck)
	defer cancel()
	return c.Run(ctx, req, log)
}

// recordedPid is the pid the program wrote to "child" in its directory; the process is killed when the test ends.
func recordedPid(t *testing.T, dir string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "child"))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program never recorded its child: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("ENVIRONMENT: the program's child file holds %q: %v", b, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	return pid
}

// exited reports whether pid is no longer a live process; a zombie counts as exited (a bare container may not reap it).
func exited(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	return err == nil && bytes.HasPrefix(stat[bytes.LastIndexByte(stat, ')')+2:], []byte("Z"))
}

// gone waits for pid to exit, within the watchdog.
func gone(pid int) bool {
	for deadline := time.Now().Add(stuck); ; time.Sleep(20 * time.Millisecond) {
		if exited(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// awaitFile returns once path exists.
func awaitFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(stuck); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("STUCK: %s never appeared", path)
		}
	}
}

func setKillGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := killGrace
	killGrace = d
	t.Cleanup(func() { killGrace = old })
}

func TestTheProgramReadsTheRequestOnStdinAsOneVersion1Object(t *testing.T) {
	var feeds []string
	var wantFeeds []any
	for i := range 5000 { // well over a pipe buffer
		id := fmt.Sprintf("ipv4:feed_%05d_v4", i)
		feeds = append(feeds, id)
		wantFeeds = append(wantFeeds, id)
	}
	for _, c := range []struct {
		name string
		req  Request
		want map[string]any
	}{
		{"a manual request",
			Request{Trigger: "manual", Scope: "ip", Force: "parse", Feeds: []string{"ipv4:a_v4", "dnsbl:b"}, Extras: []string{"extra:dcc"}},
			map[string]any{"version": 1.0, "trigger": "manual", "scope": "ip", "force": "parse", "feeds": []any{"ipv4:a_v4", "dnsbl:b"}, "extras": []any{"extra:dcc"}}},
		{"nothing but the trigger", Request{Trigger: "scheduled"}, map[string]any{"version": 1.0, "trigger": "scheduled"}},
		{"empty lists", Request{Trigger: "retry", Feeds: []string{}, Extras: []string{}}, map[string]any{"version": 1.0, "trigger": "retry"}},
		{"a request larger than a pipe buffer", Request{Trigger: "apply", Feeds: feeds}, map[string]any{"version": 1.0, "trigger": "apply", "feeds": wantFeeds}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _ := program(t, `cat`)
			log := newLog(t)
			if _, err := runCmd(t, p, c.req, log); err != nil {
				t.Fatalf("Run = %v, want the program to succeed", err)
			}
			dec := json.NewDecoder(strings.NewReader(logText(t, log)))
			var got map[string]any
			if err := dec.Decode(&got); err != nil {
				t.Fatalf("the program's stdin is not a JSON object: %v", err)
			}
			if _, err := dec.Token(); !errors.Is(err, io.EOF) {
				t.Errorf("the program's stdin has more than one JSON value (next token error: %v)", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("the program's stdin = %v, want %v", got, c.want)
			}
		})
	}
}

func TestStdoutAndStderrBothLandInTheLogAfterWhatIsThere(t *testing.T) {
	p, _ := program(t, `echo to-stdout; echo to-stderr >&2`)
	log := newLog(t)
	if _, err := log.WriteString("before\n"); err != nil {
		t.Fatal(err)
	}
	res, err := runCmd(t, p, Request{Trigger: "manual"}, log)
	if err != nil || !reflect.DeepEqual(res, Result{}) {
		t.Fatalf("Run = (%+v, %v), want an empty Result and no error: exit 0 and an empty result file", res, err)
	}
	if got := logText(t, log); got != "before\nto-stdout\nto-stderr\n" {
		t.Errorf("the log = %q, want what was there, then the program's stdout and stderr", got)
	}
}

func TestStdoutStderrAndTheResultFdAreRegularFilesNeverPipes(t *testing.T) {
	p, dir := program(t, `echo ran > "$D/ran"; for fd in 1 2 3; do [ -f /dev/fd/$fd ] || echo "fd $fd" >> "$D/notfile"; done`)
	if _, err := runCmd(t, p, Request{Trigger: "manual"}, newLog(t)); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err != nil {
		t.Fatalf("the program did not run to its checks: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "notfile")); err == nil {
		t.Errorf("not regular files in the program: %s", b)
	}
}

func TestAValidResultOnFd3IsReturned(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name, payload string
		want          Result
	}{
		{"every field", `{"version":1,"outcomes":{"ipv4:a_v4":"success","dnsbl:b":"retry-cap-reached"},"attempted":["ipv4:a_v4","dnsbl:b"],"geoipReady":true}`,
			Result{Outcomes: map[string]string{"ipv4:a_v4": "success", "dnsbl:b": "retry-cap-reached"}, Attempted: []string{"ipv4:a_v4", "dnsbl:b"}, GeoIPReady: &yes}},
		{"nothing but the version", `{"version":1}`, Result{}},
		{"geoipReady false is a report, not an absence", `{"version":1,"geoipReady":false}`, Result{GeoIPReady: &no}},
		{"empty outcomes and attempted", `{"version":1,"outcomes":{},"attempted":[]}`, Result{Outcomes: map[string]string{}, Attempted: []string{}}},
		{"a newline after the object", "{\"version\":1}\n", Result{}},
		{"an empty file", "", Result{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := runCmd(t, withResult(t, c.payload, 0), Request{Trigger: "manual"}, newLog(t))
			if err != nil || !reflect.DeepEqual(res, c.want) {
				t.Errorf("Run = (%s, %v), want (%s, nil)", jsonOf(t, res), err, jsonOf(t, c.want))
			}
		})
	}
}

func TestAHostileResultFailsTheRunWithNothingReturned(t *testing.T) {
	for _, c := range []struct {
		name, payload, want string
	}{
		{"not JSON", "hello", "not one JSON object"},
		{"an array", `[]`, "not one JSON object"},
		{"null", `null`, "version 0"},
		{"two objects", `{"version":1}{"version":1}`, "data after"},
		{"trailing garbage", `{"version":1} x`, "data after"},
		{"an unknown field", `{"version":1,"extra":true}`, "unknown field"},
		{"version 2", `{"version":2}`, "version 2"},
		{"no version", `{"outcomes":{}}`, "version 0"},
		{"an unknown outcome", `{"version":1,"outcomes":{"ipv4:a_v4":"maybe"}}`, "maybe"},
		{"outcomes that are not an object", `{"version":1,"outcomes":["success"]}`, "not one JSON object"},
		{"geoipReady that is not a boolean", `{"version":1,"geoipReady":"yes"}`, "not one JSON object"},
		{"a well-formed result over 1 MiB", `{"version":1,"attempted":["` + strings.Repeat("x", 1<<20) + `"]}`, "over 1 MiB"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := runCmd(t, withResult(t, c.payload, 0), Request{Trigger: "manual"}, newLog(t))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Run = %v, want an error saying %q", err, c.want)
			}
			if !reflect.DeepEqual(res, Result{}) {
				t.Errorf("Run returned %s with a hostile result, want nothing", jsonOf(t, res))
			}
		})
	}
}

func TestANonZeroExitIsAnErrorNamingTheStatusAndStillReturnsAValidResult(t *testing.T) {
	for _, c := range []struct {
		name, payload string
		want          Result
	}{
		{"with a valid result", `{"version":1,"outcomes":{"ipv4:a_v4":"success"},"attempted":["ipv4:a_v4","ipv4:b_v4"]}`,
			Result{Outcomes: map[string]string{"ipv4:a_v4": "success"}, Attempted: []string{"ipv4:a_v4", "ipv4:b_v4"}}},
		{"with no result", "", Result{}},
		{"with a hostile result", "not json", Result{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := runCmd(t, withResult(t, c.payload, 3), Request{Trigger: "manual"}, newLog(t))
			if err == nil || !strings.Contains(err.Error(), "exit status 3") {
				t.Errorf("Run = %v, want an error naming exit status 3", err)
			}
			if !reflect.DeepEqual(res, c.want) {
				t.Errorf("Run returned %s, want %s", jsonOf(t, res), jsonOf(t, c.want))
			}
		})
	}
}

// issue #4002: the program reports each outcome as a line of its own as it finishes, so a program that dies mid-pass still
// reports what it finished; a last line its death cut short is dropped, with an error.
func TestTheOutcomesOfAProgramKilledMidPassAreStillReturned(t *testing.T) {
	p, _ := program(t, `printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"}}\n' >&3
printf '{"version":1,"outcomes":{"dnsbl:b":"retry-cap-reached"}}\n' >&3
printf '{"version":1,"outc' >&3
kill -TERM $$
sleep 60`)
	res, err := runCmd(t, p, Request{Trigger: "scheduled"}, newLog(t))
	if err == nil || !strings.Contains(err.Error(), "signal: terminated") {
		t.Errorf("Run = %v, want an error naming the TERM that ended the program", err)
	}
	want := Result{Outcomes: map[string]string{"ipv4:a_v4": "success", "dnsbl:b": "retry-cap-reached"}}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("Run returned %s, want the two outcomes reported before the TERM, %s", jsonOf(t, res), jsonOf(t, want))
	}
}

// The lines of a result add up: every line's outcomes (the first for an id stands), and the attempted ids and GeoIP readiness
// of the last line that has them. A complete line that is not a result fails the whole result.
func TestResultLinesAddUp(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		name, payload string
		want          Result
		err           string
	}{
		{"outcomes, then the whole result", "{\"version\":1,\"outcomes\":{\"ipv4:a_v4\":\"success\"}}\n" +
			"{\"version\":1,\"geoipReady\":false}\n" +
			"{\"version\":1,\"outcomes\":{\"ipv4:a_v4\":\"retry-cap-reached\",\"extra:dcc\":\"success\"},\"attempted\":[\"extra:bl\"],\"geoipReady\":true}\n",
			Result{Outcomes: map[string]string{"ipv4:a_v4": "success", "extra:dcc": "success"}, Attempted: []string{"extra:bl"}, GeoIPReady: &yes}, ""},
		{"a readiness reported once stays", "{\"version\":1,\"geoipReady\":false}\n{\"version\":1,\"attempted\":[\"extra:bl\"]}\n",
			Result{Attempted: []string{"extra:bl"}, GeoIPReady: &no}, ""},
		{"the attempted ids of the last line that has them", "{\"version\":1,\"attempted\":[\"extra:dcc\"]}\n{\"version\":1,\"attempted\":[\"extra:bl\"]}\n{\"version\":1}\n",
			Result{Attempted: []string{"extra:bl"}}, ""},
		{"a bad line amid good ones", "{\"version\":1,\"outcomes\":{\"ipv4:a_v4\":\"success\"}}\nhello\n{\"version\":1}\n", Result{}, "not one JSON object"},
		{"a bad last line that is whole", "{\"version\":1,\"outcomes\":{\"ipv4:a_v4\":\"success\"}}\nhello\n", Result{}, "not one JSON object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, err := runCmd(t, withResult(t, c.payload, 0), Request{Trigger: "manual"}, newLog(t))
			if (c.err == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.err) {
				t.Errorf("Run = %v, want an error saying %q (none when empty)", err, c.err)
			}
			if !reflect.DeepEqual(res, c.want) {
				t.Errorf("Run returned %s, want %s", jsonOf(t, res), jsonOf(t, c.want))
			}
		})
	}
}

func TestTheCapKillsTheProgramAndItsWholeProcessGroup(t *testing.T) {
	p, dir := program(t, `sleep 60 & echo $! > "$D/child"; wait`)
	p.Cap = 500 * time.Millisecond
	_, err := runCmd(t, p, Request{Trigger: "scheduled"}, newLog(t))
	if err == nil || !strings.Contains(err.Error(), "killed") || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("Run = %v, want an error saying the program was killed at its cap", err)
	}
	if pid := recordedPid(t, dir); !gone(pid) {
		t.Errorf("the program's background child %d was still running after the cap killed it", pid)
	}
}

func TestCancelingTheContextKillsTheGroupAndEscalatesToKillWhenTermIsIgnored(t *testing.T) {
	setKillGrace(t, 100*time.Millisecond)
	p, dir := program(t, `trap '' TERM; sleep 60 & echo $! > "$D/child"; echo up > "$D/up"; wait`)
	log := newLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "manual"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "up"))
	pid := recordedPid(t, dir)
	cancel()
	err := recv(t, ended, "Run never returned after its context was canceled: a program ignoring TERM was not killed")
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "killed") {
		t.Errorf("Run = %v, want an error saying the program was killed, wrapping context.Canceled", err)
	}
	if !gone(pid) {
		t.Errorf("the program's background child %d was still running after the cancel", pid)
	}
}

func TestACanceledContextStartsNothing(t *testing.T) {
	p, dir := program(t, `echo ran > "$D/ran"`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Run(ctx, Request{Trigger: "manual"}, newLog(t)); !errors.Is(err, context.Canceled) {
		t.Errorf("Run with a canceled context = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Error("the program ran under a canceled context")
	}
}

func TestANormalExitLeavesAChildOfTheProgramRunning(t *testing.T) {
	p, dir := program(t, `sleep 60 >/dev/null 2>&1 </dev/null & echo $! > "$D/child"`)
	if _, err := runCmd(t, p, Request{Trigger: "manual"}, newLog(t)); err != nil {
		t.Fatalf("Run = %v", err)
	}
	if pid := recordedPid(t, dir); exited(pid) {
		t.Errorf("the program's background child %d was killed when the program exited normally, want it left running", pid)
	}
}

func TestAGrandchildHoldingTheLogAndTheResultFdDoesNotDelayRun(t *testing.T) {
	p, dir := program(t, `printf '{"version":1,"attempted":["ipv4:a_v4"]}' >&3; sleep 60 & echo $! > "$D/child"`)
	res, err := runCmd(t, p, Request{Trigger: "manual"}, newLog(t))
	if err != nil || !reflect.DeepEqual(res, Result{Attempted: []string{"ipv4:a_v4"}}) {
		t.Errorf("Run = (%s, %v), want the program's result and no error while a grandchild holds the log and fd 3", jsonOf(t, res), err)
	}
	if pid := recordedPid(t, dir); exited(pid) {
		t.Errorf("the grandchild %d is gone, so Run did not return while it was alive", pid)
	}
}

func TestTheResultFileIsRemovedAfterRun(t *testing.T) {
	missing := &Command{Path: filepath.Join(t.TempDir(), "absent")}
	ok, _ := program(t, `exit 0`)
	failing, _ := program(t, `exit 1`)
	capped, _ := program(t, `sleep 60`)
	capped.Cap = 200 * time.Millisecond
	for _, c := range []struct {
		name string
		cmd  *Command
	}{
		{"a program that succeeds", ok},
		{"a program that fails", failing},
		{"a program killed at the cap", capped},
		{"a program that cannot start", missing},
	} {
		t.Run(c.name, func(t *testing.T) {
			log := newLog(t)
			_, _ = runCmd(t, c.cmd, Request{Trigger: "manual"}, log)
			entries, err := os.ReadDir(filepath.Dir(log.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if !reflect.DeepEqual(names, []string{"update.log"}) {
				t.Errorf("the log's directory holds %v after Run, want only the log: the result file must be removed", names)
			}
		})
	}
}

func TestTheGateRunsTheCommandFromStartToTheRecordedResult(t *testing.T) {
	p, _ := program(t, `cat; echo working; printf '{"version":1,"outcomes":{"ipv4:a_v4":"success"},"attempted":["ipv4:a_v4"]}' >&3`)
	type ended struct {
		res Result
		err error
	}
	got := make(chan ended, 1)
	g := newGate(t, p.Run, func(_ Request, res Result, err error) { got <- ended{res, err} })
	if err := g.Start(Request{Trigger: "scheduled", Feeds: []string{"ipv4:a_v4"}}); err != nil {
		t.Fatal(err)
	}
	e := recv(t, got, "done was never called")
	settle(t, g)
	want := Result{Outcomes: map[string]string{"ipv4:a_v4": "success"}, Attempted: []string{"ipv4:a_v4"}}
	if e.err != nil || !reflect.DeepEqual(e.res, want) {
		t.Errorf("done got (%s, %v), want (%s, nil)", jsonOf(t, e.res), e.err, jsonOf(t, want))
	}
	v := g.View(0, 0)
	if v.Running || v.Update.Result != "success" || !strings.Contains(v.Log, `"trigger":"scheduled"`) || !strings.HasSuffix(v.Log, "working\n") {
		t.Errorf("View = %s, want a successful Update whose log holds the program's stdin and output", jsonOf(t, v))
	}
}
