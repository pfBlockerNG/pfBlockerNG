package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func validWorkerJSON(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(workerState{Version: 1, Nonce: strings.Repeat("a", 64), Path: "/bin/true", Request: Request{Trigger: "apply"}, StartedAt: 100})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWorkerStateRejectsMalformedPrivateRecords(t *testing.T) {
	valid := validWorkerJSON(t)
	if _, err := decodeWorkerState(strings.NewReader(valid)); err != nil {
		t.Fatalf("valid active record rejected: %v", err)
	}
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"null", "null"},
		{"truncated", valid[:len(valid)-1]},
		{"unknown field", valid[:len(valid)-1] + `,"pid":1}`},
		{"trailing object", valid + `{}`},
		{"wrong version", strings.Replace(valid, `"version":1`, `"version":2`, 1)},
		{"invalid nonce", strings.Replace(valid, strings.Repeat("a", 64), "not-an-identity", 1)},
		{"upper case nonce", strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1)},
		{"zero start", strings.Replace(valid, `"startedAt":100`, `"startedAt":0`, 1)},
		{"missing terminal status", valid[:len(valid)-1] + `,"finishedAt":101}`},
		{"end before start", valid[:len(valid)-1] + `,"finishedAt":99,"exitCode":0}`},
		{"negative exit", valid[:len(valid)-1] + `,"finishedAt":101,"exitCode":-1}`},
		{"oversized exit", valid[:len(valid)-1] + `,"finishedAt":101,"exitCode":256}`},
		{"negative signal", valid[:len(valid)-1] + `,"finishedAt":101,"signal":-1}`},
		{"signal and exit", valid[:len(valid)-1] + `,"finishedAt":101,"signal":15,"exitCode":0}`},
		{"NUL program", strings.Replace(valid, "/bin/true", `/bin/true\u0000`, 1)},
		{"bad outcome", strings.Replace(valid, `"outcomes":null`, `"outcomes":{"ipv4:a_v4":"invented"}`, 1)},
		{"result before completion", strings.Replace(valid, `"outcomes":null`, `"outcomes":{"ipv4:a_v4":"success"}`, 1)},
		{"oversized whitespace", valid + strings.Repeat(" ", 4<<20)},
		{"invalid UTF8", strings.Replace(valid, "/bin/true", "/bin/"+string([]byte{0xff}), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeWorkerState(strings.NewReader(tc.body)); err == nil {
				t.Fatalf("accepted malformed private state %q", tc.name)
			}
		})
	}
}

func TestWorkerFilesRejectHostilePathsWithoutTouchingTargets(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "shared file"} {
		t.Run(kind, func(t *testing.T) {
			log := independentLog(t)
			path := log.Name() + ".status"
			target := filepath.Join(t.TempDir(), "unrelated")
			if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			case "shared file":
				err = os.WriteFile(path, []byte("bad"), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (&Command{Path: "/bin/true"}).Run(context.Background(), Request{Trigger: "apply"}, log); err == nil {
				t.Fatalf("accepted hostile %s state path", kind)
			}
			if body, err := os.ReadFile(target); err != nil || string(body) != "untouched" {
				t.Fatalf("unrelated target = %q, %v; want untouched", body, err)
			}
		})
	}
}

func awaitWorkerCompletion(t *testing.T, logPath string) workerState {
	t.Helper()
	lock := awaitUnlocked(t, logPath)
	state, err := readWorkerState(logPath + ".status")
	lock.Close()
	if err != nil || state.FinishedAt == nil {
		t.Fatalf("worker released ownership without terminal publication: %+v, %v", state, err)
	}
	return state
}

func TestWorkerPublishesActualResultBeforeReleasingOwnershipAfterObserverLeaves(t *testing.T) {
	p, dir := independentProgram(t)
	log := independentLog(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ended := make(chan error, 1)
	go func() { _, err := p.Run(ctx, Request{Trigger: "apply"}, log); ended <- err }()
	awaitFile(t, filepath.Join(dir, "ready"))
	cancel()
	if err := recv(t, ended, "observer never returned"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	releaseIndependent(t, dir)
	state := awaitWorkerCompletion(t, log.Name())
	result, err := state.outcome()
	if err != nil || !reflect.DeepEqual(result.Outcomes, map[string]string{"ipv4:a_v4": "success"}) {
		t.Fatalf("durable terminal result = %+v, %v; want completed feed success", state, err)
	}
	if state.ExitCode == nil || *state.ExitCode != 0 || state.Signal != 0 || *state.FinishedAt < state.StartedAt {
		t.Fatalf("actual terminal status = %+v, want exit0 and ordered timestamps", state)
	}
}
