package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// statusMembers is the worker status Core's last Update left in its state directory, member by member.
func statusMembers(t *testing.T, c *runningCore) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.state, "update.log.status"))
	var members map[string]json.RawMessage
	if err != nil || json.Unmarshal(b, &members) != nil {
		t.Fatalf("update.log.status = %q, %v", b, err)
	}
	return members
}

// loopFlags are the path flags the loop takes, each naming a folder of the test's own.
func loopFlags(t *testing.T) (flags []string, paths map[string]any) {
	t.Helper()
	dir := scratchDir(t)
	p := func(name string) string { return filepath.Join(dir, name) }
	flags = []string{"--resource-dir", p("store"), "--feed-local-dir", p("feeds1"), "--feed-local-dir", p("feeds2"),
		"--script-dir", p("scripts"), "--rsync-bin", p("rsync"), "--hook-dir", p("hooks"), "--python-wrapper", p("python.sh"),
		"--main-log", p("main.log")}
	paths = map[string]any{"resourceDir": p("store"), "feedLocalDirs": []any{p("feeds1"), p("feeds2")}, "scriptDirs": []any{p("scripts")},
		"rsyncBin": p("rsync"), "hookDir": p("hooks"), "pythonWrapper": p("python.sh"), "mainLog": p("main.log")}
	return flags, paths
}

// WHEN Core runs with --update-loop THEN an admitted Update runs the Core Updater loop, which reads the settings itself,
// instead of the --update-cmd program, and the worker's state carries the paths the flags gave Core.
func TestWithTheUpdateLoopSwitchOnAnUpdateRunsTheLoopNotTheProgram(t *testing.T) {
	holdQuarters(t)
	f := newFakeUpdate(t)
	adapter := newFakeAdapter(t, readReply(t, 5, nil))
	flags, paths := loopFlags(t)
	c := startCore(t, scratchDir(t), append([]string{"--update-cmd", f.path, "--update-loop", "--settings-backend-cmd", adapter.path}, flags...)...)
	before := adapter.runs()
	wantJSON(t, c.post("StartUpdate", `{"requestId":"l1","trigger":"manual"}`), http.StatusOK, `{}`)
	end := c.waitFinished("manual")
	if end.Update.Result != "success" || !strings.Contains(end.Log, "settings revision 5") {
		t.Errorf("GetUpdate = %+v, want a success whose transcript has the loop's snapshot line", end)
	}
	if n := f.runs(); n != 0 {
		t.Errorf("the --update-cmd program ran %d times, want none", n)
	}
	if n := adapter.runs() - before; n != 2 {
		t.Errorf("the adapter ran %d times for the Update, want 2: the Core API's read before launch and the loop's own", n)
	}
	paths["settingsCmd"] = adapter.path
	var loop map[string]any
	if err := json.Unmarshal(statusMembers(t, c)["loop"], &loop); err != nil {
		t.Fatalf("the worker status has no loop: %v", err)
	}
	sameJSON(t, jsonString(t, loop), jsonString(t, paths))
	if main, err := os.ReadFile(paths["mainLog"].(string)); err != nil || !strings.Contains(string(main), "settings revision 5") {
		t.Errorf("main log = %q, %v; want the loop's snapshot line", main, err)
	}
}

// WHEN Core runs without --update-loop, whatever path flags it has THEN the Update runs the program as before and the
// worker's state has no loop member.
func TestWithTheUpdateLoopSwitchOffAnUpdateRunsTheProgramAsBefore(t *testing.T) {
	holdQuarters(t)
	f := newFakeUpdate(t)
	f.release()
	flags, _ := loopFlags(t)
	c := startCore(t, scratchDir(t), append([]string{"--update-cmd", f.path}, flags...)...)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"o1","trigger":"manual"}`), http.StatusOK, `{}`)
	end := c.waitFinished("manual")
	if end.Update.Result != "success" || end.Log != "update program started\nupdate program done\n" {
		t.Errorf("GetUpdate = %+v, want a success with the program's whole output and nothing else", end)
	}
	if n := f.runs(); n != 1 {
		t.Errorf("the program ran %d times, want once", n)
	}
	if loop, ok := statusMembers(t, c)["loop"]; ok {
		t.Errorf("the worker status carries a loop %s, want none", loop)
	}
}

// --update-loop selects how an Update runs, so it needs --update-cmd; --main-log, like every path, must be absolute.
func TestTheUpdateLoopFlagsAreRefusedAsUsageErrorsWhenTheyCannotWork(t *testing.T) {
	dir := scratchDir(t)
	base := []string{"--socket", filepath.Join(dir, "run", "api.sock"), "--state-dir", filepath.Join(dir, "state")}
	for name, extra := range map[string][]string{
		"loop without update-cmd": {"--update-loop"},
		"relative main log":       {"--update-cmd", "/bin/true", "--update-loop", "--main-log", "pfblockerng.log"},
	} {
		t.Run(name, func(t *testing.T) {
			stopped, cancel := context.WithCancel(context.Background())
			cancel()
			var stderr bytes.Buffer
			if code := run(stopped, append(append([]string{}, base...), extra...), &stderr); code != 2 {
				t.Errorf("run = %d, want 2; stderr %q", code, stderr.String())
			}
		})
	}
}

func TestUsageNamesTheUpdateLoopFlags(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), nil, &stderr); code != 2 {
		t.Fatalf("run without flags = %d, want 2", code)
	}
	for _, flag := range []string{"--update-loop", "--main-log PATH"} {
		if !strings.Contains(stderr.String(), flag) {
			t.Errorf("the usage text does not name %s: %q", flag, stderr.String())
		}
	}
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
