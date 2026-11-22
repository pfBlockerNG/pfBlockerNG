package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// workerMembers is the worker file name (update.log.status, update.log.request) Core's last Update left in its state
// directory, member by member.
func workerMembers(t *testing.T, c *runningCore, name string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.state, name))
	var members map[string]json.RawMessage
	if err != nil || json.Unmarshal(b, &members) != nil {
		t.Fatalf("%s = %q, %v", name, b, err)
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
// instead of the --update-cmd program; the worker's request carries the paths the flags gave Core, and the status it
// publishes does not.
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
	if err := json.Unmarshal(workerMembers(t, c, "update.log.request")["loop"], &loop); err != nil {
		t.Fatalf("the worker request has no loop: %v", err)
	}
	sameJSON(t, jsonString(t, loop), jsonString(t, paths))
	if loop, ok := workerMembers(t, c, "update.log.status")["loop"]; ok {
		t.Errorf("the worker status carries the loop %s, want none", loop)
	}
	if main, err := os.ReadFile(paths["mainLog"].(string)); err != nil || !strings.Contains(string(main), "settings revision 5") {
		t.Errorf("main log = %q, %v; want the loop's snapshot line", main, err)
	}
}

// WHEN Core runs without --update-loop, whatever other path flags it has THEN the Update runs the program as before and
// the worker's state has no loop member.
func TestWithTheUpdateLoopSwitchOffAnUpdateRunsTheProgramAsBefore(t *testing.T) {
	holdQuarters(t)
	f := newFakeUpdate(t)
	f.release()
	flags, _ := loopFlags(t)
	flags = flags[:len(flags)-2] // --main-log comes last: it needs the switch
	c := startCore(t, scratchDir(t), append([]string{"--update-cmd", f.path}, flags...)...)
	wantJSON(t, c.post("StartUpdate", `{"requestId":"o1","trigger":"manual"}`), http.StatusOK, `{}`)
	end := c.waitFinished("manual")
	if end.Update.Result != "success" || end.Log != "update program started\nupdate program done\n" {
		t.Errorf("GetUpdate = %+v, want a success with the program's whole output and nothing else", end)
	}
	if n := f.runs(); n != 1 {
		t.Errorf("the program ran %d times, want once", n)
	}
	if loop, ok := workerMembers(t, c, "update.log.status")["loop"]; ok {
		t.Errorf("the worker status carries a loop %s, want none", loop)
	}
}

// --update-loop selects how an Update runs, so it needs --update-cmd, and --main-log serves only the loop; with the switch
// on, every path the loop is given, --settings-backend-cmd among them, must be absolute and clean and hold no control
// character. Each refusal is a usage error with a line that names the flag at fault.
func TestTheUpdateLoopFlagsAreRefusedAsUsageErrorsWhenTheyCannotWork(t *testing.T) {
	dir := scratchDir(t)
	base := []string{"--socket", filepath.Join(dir, "run", "api.sock"), "--state-dir", filepath.Join(dir, "state")}
	loop := []string{"--update-cmd", "/bin/true", "--update-loop"}
	for _, tc := range []struct {
		name, flag string
		extra      []string
	}{
		{"loop without update-cmd", "--update-cmd", []string{"--update-loop"}},
		{"main log without the loop", "--update-loop", []string{"--update-cmd", "/bin/true", "--main-log", filepath.Join(dir, "main.log")}},
		{"relative main log", `invalid value "pfblockerng.log" for flag -main-log`, append(slices.Clone(loop), "--main-log", "pfblockerng.log")},
		{"relative settings program", "--settings-backend-cmd", append(slices.Clone(loop), "--settings-backend-cmd", "adapter.sh")},
		{"unclean settings program", "--settings-backend-cmd", append(slices.Clone(loop), "--settings-backend-cmd", dir+"/bin/../adapter.sh")},
		{"main log that is not UTF-8", "--main-log", append(slices.Clone(loop), "--main-log", dir+"/\xe9.log")},
		{"control character in the update program", "for flag -update-cmd", []string{"--update-cmd", dir + "/update\x01.sh"}},
		{"update program that is not UTF-8", "for flag -update-cmd", []string{"--update-cmd", dir + "/update\xe9.sh"}},
		{"control character in the update program with the loop", "for flag -update-cmd", []string{"--update-cmd", dir + "/update\n.sh", "--update-loop"}},
		{"update program that is not UTF-8 with the loop", "for flag -update-cmd", []string{"--update-cmd", dir + "/update\xe9.sh", "--update-loop"}},
		{"control character in the resource folder", "--resource-dir", append(slices.Clone(loop), "--resource-dir", dir+"/store\x01")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stopped, cancel := context.WithCancel(context.Background())
			cancel()
			var stderr bytes.Buffer
			if code := run(stopped, append(slices.Clone(base), tc.extra...), &stderr); code != 2 {
				t.Errorf("run = %d, want 2; stderr %q", code, stderr.String())
			}
			named := false
			for _, line := range strings.Split(stderr.String(), "\n") {
				named = named || !strings.HasPrefix(line, "pfb-core: usage:") && strings.Contains(line, tc.flag)
			}
			if !named {
				t.Errorf("stderr = %q, want a line besides the usage text that names %s", stderr.String(), tc.flag)
			}
		})
	}
}

// WHEN an invalid loop reaches the admission of an Update THEN the Update is refused before any side effect: the previous
// transcript, the schedule state and the gate's status stay as they were, and no program runs.
func TestAnInvalidLoopIsRefusedBeforeAnySideEffectOfAnUpdate(t *testing.T) {
	stateDir := scratchDir(t)
	st, err := settings.Open(stateDir, settings.Production())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Initialize(t.Context(), map[string]map[string]json.RawMessage{}); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(stateDir, "update.log")
	if err := os.WriteFile(logPath, []byte("the previous Update\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFakeUpdate(t)
	f.release()
	sched, gate := newUpdates(f.path, "", "", stateDir, &update.Loop{ResourceDir: "relative/store"}, st, newLaneSettings(st, t.Logf), t.Logf)
	t.Cleanup(gate.Stop)
	files := func() map[string]string {
		got := map[string]string{}
		for _, name := range []string{"update.log", "schedule_state.json", "update.log.request", "update.log.status"} {
			b, err := os.ReadFile(filepath.Join(stateDir, name))
			got[name] = fmt.Sprintf("%q %v", b, err)
		}
		return got
	}
	beforeFiles := files()
	beforeView, err := gate.View(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.Start("manual", "both", "none"); err == nil {
		t.Error("Start = nil, want the invalid loop refused")
	}
	if after := files(); !reflect.DeepEqual(after, beforeFiles) {
		t.Errorf("state files:\n have %v\n want %v", after, beforeFiles)
	}
	if afterView, err := gate.View(0, 0); err != nil || !reflect.DeepEqual(afterView, beforeView) {
		t.Errorf("gate view = %+v, %v; want %+v", afterView, err, beforeView)
	}
	if n := f.runs(); n != 0 {
		t.Errorf("the program ran %d times, want none", n)
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
