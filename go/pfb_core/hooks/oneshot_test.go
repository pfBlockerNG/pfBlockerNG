//go:build linux || freebsd

package hooks_test

// `pfb-core --run-hooks <pre|post>` (#4035 slice 6c), run as a process of the built binary: the corpus in
// tests/hooks/fixtures/oneshot (tests/php/HookOneShotCorpusTest.php documents the keys and drives today's PHP callers
// on it), then the one-shot's refusals, its settings backend, its usage and the locks it leaves alone. The settings
// backend is an adapter program answering the scenario's rows as the hooks projection holds them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var coreBinary struct {
	once      sync.Once
	dir, path string
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if coreBinary.dir != "" {
		os.RemoveAll(coreBinary.dir)
	}
	os.Exit(code)
}

// pfbCore builds the pfb-core binary once per test run.
func pfbCore(t *testing.T) string {
	t.Helper()
	coreBinary.once.Do(func() {
		if coreBinary.dir, coreBinary.err = os.MkdirTemp("", "pfb-core-oneshot-"); coreBinary.err != nil {
			return
		}
		coreBinary.path = filepath.Join(coreBinary.dir, "pfb-core")
		out, err := exec.Command("go", "build", "-o", coreBinary.path, "..").CombinedOutput()
		if err != nil {
			coreBinary.err = errors.New(err.Error() + ": " + string(out))
		}
	})
	if coreBinary.err != nil {
		t.Fatalf("building pfb-core: %v", coreBinary.err)
	}
	return coreBinary.path
}

type oneShotResult struct {
	status         int
	stdout, stderr string
}

// oneShot runs pfb-core with args and stdin, its environment without any PFB_* entry, and returns how it ended. A run
// still going after two minutes is killed and fails the test as stuck.
func oneShot(t *testing.T, stdin string, args ...string) oneShotResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	cmd := exec.CommandContext(ctx, pfbCore(t), args...)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "PFB_") })
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(stdin), &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("STUCK: pfb-core %v did not return", args)
	}
	var exit *exec.ExitError
	status := 0
	switch {
	case errors.As(err, &exit):
		status = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return oneShotResult{status, stdout.String(), stderr.String()}
}

// projected is a stored row as the hooks projection lists it (docs/misc/core-api-protocol.md "Projection hooks").
func projected(rows []map[string]any, expand func(string) string) []map[string]any {
	out := []map[string]any{}
	for i, r := range rows {
		str := func(key string) string { s, _ := r[key].(string); return expand(s) }
		timeout := phpInt(r["timeout"])
		if timeout < 1 {
			timeout = 60
		}
		out = append(out, map[string]any{"id": strconv.Itoa(i), "when": str("when"), "script": str("script"),
			"description": strings.TrimSpace(str("description")), "timeout": timeout, "enabled": r["enabled"] == "on"})
	}
	return out
}

// adapter writes a settings backend program under root that answers a read with rows as the hooks projection, and
// returns its path.
func adapter(t *testing.T, root string, rows []map[string]any) string {
	t.Helper()
	stored := map[string]any{"hooks": map[string]any{"rows": rows}}
	reply, err := json.Marshal(map[string]any{"version": 1, "revision": 1, "settings": stored})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), reply, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adapter.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat > /dev/null\ncat '"+root+"/settings.json'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type oneShotCase struct {
	Description string                     `json:"description"`
	Departure   string                     `json:"departure"`
	Caller      string                     `json:"caller"`
	Argv        []string                   `json:"argv"`
	Vars        map[string]content         `json:"vars"`
	PkgOp       string                     `json:"pkgOp"`
	When        string                     `json:"when"`
	Stdin       content                    `json:"stdin"`
	Python      string                     `json:"python"`
	Rows        []map[string]any           `json:"rows"`
	Files       map[string]corpusFile      `json:"files"`
	OldExpect   map[string]json.RawMessage `json:"old_expect"`
	Expect      struct {
		Runs    []corpusRun `json:"runs"`
		Log     content     `json:"log"`
		Console content     `json:"console"`
		Absent  []string    `json:"absent"`
	} `json:"expect"`
}

func TestOneShotCorpus(t *testing.T) {
	files, _ := filepath.Glob("../../../tests/hooks/fixtures/oneshot/*.json")
	if len(files) == 0 {
		t.Fatal("no one-shot corpus scenarios")
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var sc oneShotCase
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&sc); err != nil {
				t.Fatal(err)
			}
			if (sc.OldExpect != nil) != (sc.Departure != "") {
				t.Fatal("a scenario has old_expect exactly when it names its departure")
			}
			root := t.TempDir()
			expand := func(s string) string {
				return strings.NewReplacer("{record}", ". '"+root+"/record.sh'", "{root}", root).Replace(s)
			}
			stage(t, root, corpusCase{Python: sc.Python, Files: sc.Files}, expand)
			got := oneShot(t, sc.Stdin.bytes(expand), "--run-hooks", sc.When,
				"--settings-backend-cmd", adapter(t, root, projected(sc.Rows, expand)),
				"--hook-dir", filepath.Join(root, "hooks"), "--python-wrapper", filepath.Join(root, "wrapper.sh"))
			if got.status != 0 {
				t.Fatalf("exit status %d, want 0; stderr %s", got.status, clip(got.stderr))
			}
			want := []corpusRun{}
			for _, run := range sc.Expect.Runs {
				env := map[string]string{}
				for k, v := range run.Env {
					env[k] = expand(v)
				}
				want = append(want, corpusRun{Script: run.Script, Wrapped: run.Wrapped, Args: run.Args, Env: env})
			}
			runs := recordedRuns(t, root)
			if runs == nil {
				runs = []corpusRun{}
			}
			wantJSON, _ := json.MarshalIndent(want, "", " ")
			gotJSON, _ := json.MarshalIndent(runs, "", " ")
			if !bytes.Equal(wantJSON, gotJSON) {
				t.Errorf("recorded invocations (order, launcher, arguments, PFB_* environment):\n got %s\nwant %s", gotJSON,
					wantJSON)
			}
			if want := sc.Expect.Log.bytes(expand); got.stderr != want {
				t.Errorf("main log (stderr):\n got %s\nwant %s", clip(got.stderr), clip(want))
			}
			if want := sc.Expect.Console.bytes(expand); got.stdout != want {
				t.Errorf("console (stdout):\n got %s\nwant %s", clip(got.stdout), clip(want))
			}
			for _, canary := range sc.Expect.Absent {
				if _, err := os.Stat(filepath.Join(root, canary)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("canary %s exists: a context value was evaluated", canary)
				}
			}
		})
	}
}

// oneShotRoot stages a hook directory whose hooks record their runs, one pre and one post, and a settings backend
// listing both enabled.
func oneShotRoot(t *testing.T) (root string, flags []string) {
	t.Helper()
	root = t.TempDir()
	expand := func(s string) string { return strings.ReplaceAll(s, "{record}", ". '"+root+"/record.sh'") }
	body := &content{text: "#!/bin/sh\n{record}\n"}
	stage(t, root, corpusCase{Files: map[string]corpusFile{"hooks/hook_pre_a.sh": {Body: body},
		"hooks/hook_post_a.sh": {Body: body}}}, expand)
	rows := projected([]map[string]any{{"script": "hook_pre_a.sh", "when": "pre", "enabled": "on"},
		{"script": "hook_post_a.sh", "when": "post", "enabled": "on"}}, expand)
	return root, []string{"--settings-backend-cmd", adapter(t, root, rows), "--hook-dir", filepath.Join(root, "hooks"),
		"--python-wrapper", filepath.Join(root, "wrapper.sh")}
}

// WHEN pfb-core --run-hooks pre runs with no Core running THEN the configured pre hooks run once, in list order, with
// the context from stdin, and the exit status is 0 although one of them failed.
func TestOneShotPreRunsTheConfiguredHooksOnceInOrderAndExitsZeroWhenOneFails(t *testing.T) {
	root := t.TempDir()
	expand := func(s string) string { return strings.ReplaceAll(s, "{record}", ". '"+root+"/record.sh'") }
	stage(t, root, corpusCase{Files: map[string]corpusFile{
		"hooks/hook_pre_a.sh":  {Body: &content{text: "#!/bin/sh\n{record}\nexit 1\n"}},
		"hooks/hook_pre_b.sh":  {Body: &content{text: "#!/bin/sh\n{record}\n"}},
		"hooks/hook_post_c.sh": {Body: &content{text: "#!/bin/sh\n{record}\n"}}}}, expand)
	rows := projected([]map[string]any{{"script": "hook_pre_a.sh", "when": "pre", "enabled": "on"},
		{"script": "hook_post_c.sh", "when": "post", "enabled": "on"},
		{"script": "hook_pre_b.sh", "when": "pre", "enabled": "on"}}, expand)
	got := oneShot(t, `{"trigger":"cron"}`, "--run-hooks", "pre", "--settings-backend-cmd", adapter(t, root, rows),
		"--hook-dir", filepath.Join(root, "hooks"))
	if got.status != 0 {
		t.Errorf("exit status %d, want 0 although a hook failed; stderr %s", got.status, clip(got.stderr))
	}
	env := map[string]string{"PFB_WHEN": "pre", "PFB_TRIGGER": "cron", "PFB_POST_INSTALL": "0", "PFB_PRE_UNINSTALL": "0",
		"PFB_PKG_OP": ""}
	want := []corpusRun{{Script: "hook_pre_a.sh", Args: []string{}, Env: env},
		{Script: "hook_pre_b.sh", Args: []string{}, Env: env}}
	if runs := recordedRuns(t, root); !slices.EqualFunc(runs, want, func(a, b corpusRun) bool {
		return a.Script == b.Script && maps.Equal(a.Env, b.Env) && len(a.Args) == 0
	}) {
		t.Errorf("runs = %+v, want %+v", runs, want)
	}
	if !strings.Contains(got.stderr, "[ pfB Hook ] pre #0 exited non-zero [ 1 ]; continuing\n") {
		t.Errorf("stderr %s does not log the failed hook", clip(got.stderr))
	}
	if got.stdout != "" {
		t.Errorf("stdout = %s, want nothing: no package lifecycle, no console copy", clip(got.stdout))
	}
}

// runsOnce is the control of a refusal test: the same staging and a valid context run hook_pre_a.sh once and exit 0, so
// that "nothing ran" below is the refusal's doing.
func runsOnce(t *testing.T, args ...string) {
	t.Helper()
	root, flags := oneShotRoot(t)
	got := oneShot(t, `{"trigger":"cron"}`, append(append([]string{"--run-hooks", "pre"}, flags...), args...)...)
	if runs := recordedRuns(t, root); got.status != 0 || len(runs) != 1 || runs[0].Script != "hook_pre_a.sh" {
		t.Fatalf("control: exit status %d and runs %+v, want 0 and hook_pre_a.sh once; stderr %s", got.status, runs,
			clip(got.stderr))
	}
}

// WHEN the context is not one JSON object of the fixed vocabulary THEN nothing runs and the exit status is 2. A context
// name that is not [A-Z0-9_]+ cannot be given: every name outside the vocabulary is refused.
func TestOneShotRefusesAContextOutsideItsVocabulary(t *testing.T) {
	runsOnce(t)
	for _, tc := range []struct{ name, when, stdin string }{
		{"unknown field", "pre", `{"trigger":"cron","status":"ok"}`},
		{"a name that is not a context name", "pre", `{"BAD-NAME":"x"}`},
		{"a name in another case", "pre", `{"Trigger":"cron"}`},
		{"lifecycle install", "pre", `{"lifecycle":"install"}`},
		{"lifecycle empty", "post", `{"lifecycle":""}`},
		{"lifecycle null", "pre", `{"lifecycle":null}`},
		{"pkgOp outside the vocabulary", "pre", `{"pkgOp":"remove"}`},
		{"trigger of a wrong type", "pre", `{"trigger":5}`},
		{"trigger null", "pre", `{"trigger":null}`},
		{"a flag of a wrong type", "post", `{"ipChanged":"1"}`},
		{"a list of a wrong type", "post", `{"changedIpAliases":["a"]}`},
		{"a post field for pre", "pre", `{"trigger":"cron","ipChanged":false}`},
		{"a value with a NUL", "pre", `{"trigger":"a\u0000b"}`},
		{"two objects", "pre", `{"trigger":"cron"}{"trigger":"cron"}`},
		{"trailing data", "pre", `{"trigger":"cron"} x`},
		{"empty input", "pre", ``},
		{"only white space", "pre", " \n"},
		{"null", "pre", `null`},
		{"an array", "pre", `[{"trigger":"cron"}]`},
		{"a string", "post", `"cron"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			got := oneShot(t, tc.stdin, append([]string{"--run-hooks", tc.when}, flags...)...)
			if got.status != 2 {
				t.Errorf("exit status %d, want 2", got.status)
			}
			if runs := recordedRuns(t, root); runs != nil {
				t.Errorf("hooks ran for a refused context: %+v", runs)
			}
			if got.stdout != "" || got.stderr == "" {
				t.Errorf("stdout %s, stderr %s: want only a refusal on stderr", clip(got.stdout), clip(got.stderr))
			}
		})
	}
}

// WHEN the settings backend is missing, fails or answers what Core refuses THEN nothing runs and the exit status is 1,
// as for a Core that cannot read its settings at start.
func TestOneShotWithoutUsableSettingsRunsNothing(t *testing.T) {
	runsOnce(t)
	for _, tc := range []struct{ name, program string }{
		{"missing", ""},
		{"failing", "#!/bin/sh\necho broken >&2\nexit 1\n"},
		{"not a reply", "#!/bin/sh\necho no\n"},
		{"refused rows", "#!/bin/sh\necho '" + `{"version":1,"revision":1,"settings":{"hooks":{"rows":[` +
			`{"id":"0","when":"pre","script":"../hook_pre_a.sh","enabled":true}]}}}` + "'\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			backend := filepath.Join(root, "backend.sh")
			if tc.program != "" {
				if err := os.WriteFile(backend, []byte(tc.program), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			flags[1] = backend
			got := oneShot(t, `{"trigger":"cron"}`, append([]string{"--run-hooks", "pre"}, flags...)...)
			if got.status != 1 {
				t.Errorf("exit status %d, want 1; stderr %s", got.status, clip(got.stderr))
			}
			if runs := recordedRuns(t, root); runs != nil {
				t.Errorf("hooks ran without usable settings: %+v", runs)
			}
		})
	}
}

// WHEN --run-hooks has a value other than pre or post, an argument after it, or lacks the hook folder or a settings
// backend THEN it is a usage error (exit status 2) and nothing runs.
func TestOneShotUsageErrors(t *testing.T) {
	runsOnce(t)
	for _, tc := range []struct {
		name string
		args func(flags []string) []string
	}{
		{"another fire point", func(f []string) []string { return append([]string{"--run-hooks", "start"}, f...) }},
		{"no fire point", func(f []string) []string { return append(f, "--run-hooks") }},
		{"an argument after it", func(f []string) []string {
			return append(append([]string{"--run-hooks", "pre"}, f...), "post")
		}},
		{"no hook folder", func(f []string) []string { return append([]string{"--run-hooks", "pre"}, f[:2]...) }},
		{"a relative hook folder", func(f []string) []string {
			return append([]string{"--run-hooks", "pre", "--hook-dir", "hooks"}, f[:2]...)
		}},
		{"a relative Python wrapper", func(f []string) []string {
			return append(append([]string{"--run-hooks", "pre"}, f[:4]...), "--python-wrapper", "wrapper.sh")
		}},
		{"no settings backend", func(f []string) []string { return append([]string{"--run-hooks", "pre"}, f[2:]...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			got := oneShot(t, `{"trigger":"cron"}`, tc.args(flags)...)
			if got.status != 2 {
				t.Errorf("exit status %d, want 2; stderr %s", got.status, clip(got.stderr))
			}
			if runs := recordedRuns(t, root); runs != nil {
				t.Errorf("hooks ran on a usage error: %+v", runs)
			}
		})
	}
}

// WHEN --run-hooks runs while another process holds the Update lock and Core's own lock in the state directory THEN it
// neither waits for them nor fails, runs its hooks, and leaves both locks held and the directory as it was. A wait
// would hang the run until the watchdog kills it.
func TestOneShotTakesNoUpdateLock(t *testing.T) {
	root, flags := oneShotRoot(t)
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	var held []*os.File
	for _, name := range []string{"update.log.lock", "core.lock"} {
		f, err := os.OpenFile(filepath.Join(state, name), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		held = append(held, f)
	}
	before, _ := os.ReadDir(state)
	got := oneShot(t, `{"trigger":"cron"}`, append([]string{"--run-hooks", "pre", "--state-dir", state}, flags...)...)
	if got.status != 0 {
		t.Errorf("exit status %d, want 0; stderr %s", got.status, clip(got.stderr))
	}
	if runs := recordedRuns(t, root); len(runs) != 1 || runs[0].Script != "hook_pre_a.sh" {
		t.Errorf("runs = %+v, want hook_pre_a.sh once", runs)
	}
	for _, f := range held {
		probe, err := os.Open(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Errorf("%s: flock by another descriptor = %v, want EWOULDBLOCK: the lock is no longer held", f.Name(), err)
		}
		probe.Close()
	}
	after, _ := os.ReadDir(state)
	names := func(es []os.DirEntry) []string {
		var n []string
		for _, e := range es {
			n = append(n, e.Name())
		}
		return n
	}
	if !slices.Equal(names(before), names(after)) {
		t.Errorf("the state directory changed: %v, then %v", names(before), names(after))
	}
}
