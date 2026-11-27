//go:build linux || freebsd

package hooks_test

// `pfb-core --run-hooks <pre|post>` (#4035 slice 6c), run as a process of the built binary: the corpus in
// tests/hooks/fixtures/oneshot (a scenario's keys: description, caller, when, stdin, python, rows, files, expect, and
// old_expect, the retired PHP runner's answer, which #3977 left unread: its callers run this binary now), then the
// one-shot's refusals, its settings backend, its usage and the locks it leaves alone. The settings
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

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // only salvages a hung build
		defer cancel()
		out, err := exec.CommandContext(ctx, "go", "build", "-o", coreBinary.path, "..").CombinedOutput()
		switch {
		case ctx.Err() != nil:
			coreBinary.err = errors.New("STUCK: go build did not finish within 5 minutes")
		case err != nil:
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

// oneShotCmd is pfb-core with args and stdin, its environment without any PFB_* entry but env.
func oneShotCmd(t *testing.T, ctx context.Context, stdin string, env []string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, pfbCore(t), args...)
	inherited := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "PFB_") })
	cmd.Env = append(inherited, env...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

// exitStatus is the exit status of a pfb-core run that ended with err: -1 when a signal ended it.
func exitStatus(t *testing.T, err error) int {
	t.Helper()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		return exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return 0
}

// oneShot runs pfb-core with args and stdin, its environment without any PFB_* entry, and returns how it ended.
func oneShot(t *testing.T, stdin string, args ...string) oneShotResult {
	t.Helper()
	return oneShotEnv(t, nil, stdin, args...)
}

// oneShotEnv is oneShot with env added to the environment. A run still going after two minutes is killed and fails the
// test as stuck.
func oneShotEnv(t *testing.T, env []string, stdin string, args ...string) oneShotResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	cmd := oneShotCmd(t, ctx, stdin, env, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("STUCK: pfb-core %v did not return", args)
	}
	return oneShotResult{exitStatus(t, err), stdout.String(), stderr.String()}
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
	return adapterOf(t, root, map[string]any{"hooks": map[string]any{"rows": rows}})
}

// adapterOf writes a settings backend program under root that answers a read with stored (projection id: values) and
// leaves root/backend-called behind, and returns its path.
func adapterOf(t *testing.T, root string, stored map[string]any) string {
	t.Helper()
	reply, err := json.Marshal(map[string]any{"version": 1, "revision": 1, "settings": stored})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "settings.json"), reply, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adapter.sh")
	program := "#!/bin/sh\ncat > /dev/null\n: > '" + root + "/backend-called'\ncat '" + root + "/settings.json'\n"
	if err := os.WriteFile(path, []byte(program), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// fileStore writes dir/settings.json, the file backend's store (--state-dir), holding rows as the hooks projection.
func fileStore(t *testing.T, dir string, rows []map[string]any) {
	t.Helper()
	doc, err := json.Marshal(map[string]any{"format": 1, "revision": 1,
		"projections": map[string]any{"hooks": map[string]any{"values": map[string]any{"rows": rows}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
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
			var sc oneShotCase
			root, expand := scenario(t, file, &sc)
			stage(t, root, corpusCase{Python: sc.Python, Files: sc.Files}, expand)
			got := oneShot(t, sc.Stdin.bytes(expand), "--run-hooks", sc.When,
				"--settings-backend-cmd", adapter(t, root, projected(sc.Rows, expand)),
				"--hook-dir", filepath.Join(root, "hooks"), "--python-wrapper", filepath.Join(root, "wrapper.sh"))
			if got.status != 0 {
				t.Fatalf("exit status %d, want 0; stderr %s", got.status, clip(got.stderr))
			}
			checkRuns(t, root, sc.Expect.Runs, expand)
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

// hookRoot stages each hook file of scripts (file name, body with {record} and {root} expanded) and lists them enabled,
// in that order, both through a settings backend program and in root/state/settings.json. It returns root and the flags
// of a one-shot run through the program; flags[2:] are the hook folder and the Python wrapper.
func hookRoot(t *testing.T, scripts ...[2]string) (root string, flags []string) {
	t.Helper()
	root = t.TempDir()
	expand := strings.NewReplacer("{record}", ". '"+root+"/record.sh'", "{root}", root).Replace
	files, rows := map[string]corpusFile{}, []map[string]any{}
	for _, s := range scripts {
		files["hooks/"+s[0]] = corpusFile{Body: &content{text: s[1]}}
		rows = append(rows, map[string]any{"script": s[0], "when": strings.Split(s[0], "_")[1], "enabled": "on"})
	}
	stage(t, root, corpusCase{Files: files}, expand)
	fileStore(t, filepath.Join(root, "state"), projected(rows, expand))
	return root, []string{"--settings-backend-cmd", adapter(t, root, projected(rows, expand)), "--hook-dir",
		filepath.Join(root, "hooks"), "--python-wrapper", filepath.Join(root, "wrapper.sh")}
}

// oneShotRoot stages one recording pre hook and one recording post hook, both enabled (hookRoot).
func oneShotRoot(t *testing.T) (root string, flags []string) {
	t.Helper()
	return hookRoot(t, [2]string{"hook_pre_a.sh", "#!/bin/sh\n{record}\n"},
		[2]string{"hook_post_a.sh", "#!/bin/sh\n{record}\n"})
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
	if !exists(filepath.Join(root, "backend-called")) {
		t.Fatal("control: the settings backend was not called")
	}
}

// WHEN the context is not one JSON object of the fixed vocabulary THEN nothing runs, the settings backend is not called
// and the exit status is 2. A context name that is not [A-Z0-9_]+ cannot be given: every name outside the vocabulary is
// refused. A member given twice is refused whichever value is valid, and so is input that is not UTF-8 or a lone
// surrogate escape, which decoding would otherwise turn into U+FFFD.
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
		{"a member twice, the valid value last", "pre", `{"lifecycle":"bogus","lifecycle":"uninstall"}`},
		{"a member twice, the valid value first", "pre", `{"lifecycle":"uninstall","lifecycle":"bogus"}`},
		{"a trigger twice", "pre", `{"trigger":"a","trigger":"b"}`},
		{"a trigger twice, once escaped", "post", `{"trigger":"a","tr\u0069gger":"a"}`},
		{"input that is not UTF-8", "pre", "{\"trigger\":\"a\xffb\"}"},
		{"a lone high surrogate", "pre", `{"trigger":"\ud800x"}`},
		{"a lone low surrogate", "post", `{"trigger":"x\uDC00"}`},
		{"a NUL under a member name with a line break", "pre", `{"a\nFAKE LINE":"\u0000"}`},
		{"U+FFFD under a member name with a line break", "pre", `{"a\nFAKE LINE":"\ufffd"}`},
		{"an unknown member name with a line break", "pre", `{"a\nFAKE LINE":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) { refused(t, tc.when, tc.stdin) })
	}
}

// refused runs the one-shot on stdin and wants the context refused: exit status 2, nothing run, the settings backend
// not called, and one line on stderr, so that a caller-chosen name cannot forge a log line.
func refused(t *testing.T, when, stdin string) {
	t.Helper()
	root, flags := oneShotRoot(t)
	got := oneShot(t, stdin, append([]string{"--run-hooks", when}, flags...)...)
	if got.status != 2 {
		t.Errorf("exit status %d, want 2", got.status)
	}
	if runs := recordedRuns(t, root); runs != nil {
		t.Errorf("hooks ran for a refused context: %+v", runs)
	}
	if got.stdout != "" || strings.Count(got.stderr, "\n") != 1 || !strings.HasSuffix(got.stderr, "\n") {
		t.Errorf("stdout %s, stderr %s: want only a one-line refusal on stderr", clip(got.stdout), clip(got.stderr))
	}
	if exists(filepath.Join(root, "backend-called")) {
		t.Error("the settings backend was called for a refused context")
	}
}

// WHEN the context is 16 MiB long THEN it is read and the hooks run; one byte more is refused before the settings
// backend is called, with exit status 2.
func TestOneShotReadsAContextOfAtMost16MiB(t *testing.T) {
	const valid = `{"trigger":"cron"}`
	for _, tc := range []struct {
		name         string
		size, status int
		ran          bool
	}{{"16 MiB", 16 << 20, 0, true}, {"one byte more", 16<<20 + 1, 2, false}} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			got := oneShot(t, valid+strings.Repeat(" ", tc.size-len(valid)), append([]string{"--run-hooks", "pre"}, flags...)...)
			if got.status != tc.status {
				t.Errorf("exit status %d, want %d; stderr %s", got.status, tc.status, clip(got.stderr))
			}
			called := exists(filepath.Join(root, "backend-called"))
			if runs := recordedRuns(t, root); (len(runs) == 1) != tc.ran || called != tc.ran {
				t.Errorf("runs %+v, backend called %v: want the hook run and the backend called = %v", runs, called, tc.ran)
			}
		})
	}
}

// WHEN a string value holds U+FFFD once decoded THEN the run is refused, whichever member holds it and however the
// input spells it: the character itself, an escape in either case, or what invalid UTF-8 and a lone surrogate escape
// decode to.
func TestOneShotRefusesAReplacementCharacter(t *testing.T) {
	runsOnce(t)
	for _, tc := range []struct{ when, stdin string }{
		{"pre", "{\"trigger\":\"a\uFFFDb\"}"},
		{"pre", `{"trigger":"a\ufffdb"}`},
		{"pre", `{"trigger":"a\uFFFDb"}`},
		{"pre", `{"trigger":"\ud800 \\ufffd"}`},
		{"post", "{\"trigger\":\"\\ud800\",\"changedIpAliases\":\"\uFFFD\"}"},
		{"pre", "{\"trigger\":\"\uFFFD\"}"},
		{"pre", "{\"trigger\":\"\xff \uFFFD\"}"},
	} {
		t.Run(tc.stdin, func(t *testing.T) { refused(t, tc.when, tc.stdin) })
	}
}

// WHEN a string holds a valid surrogate pair escape THEN the hook gets the character it encodes.
func TestOneShotPassesASurrogatePairThrough(t *testing.T) {
	root, flags := oneShotRoot(t)
	got := oneShot(t, `{"trigger":"a\ud83d\ude00b"}`, append([]string{"--run-hooks", "pre"}, flags...)...)
	if runs := recordedRuns(t, root); got.status != 0 || len(runs) != 1 || runs[0].Env["PFB_TRIGGER"] != "a\U0001F600b" {
		t.Errorf("exit status %d and runs %+v, want 0 and PFB_TRIGGER=a\U0001F600b; stderr %s", got.status, runs,
			clip(got.stderr))
	}
}

// WHEN the context's pkgOp is "" THEN it is accepted and the hooks get PFB_PKG_OP set and empty.
func TestOneShotAcceptsAnEmptyPkgOp(t *testing.T) {
	root, flags := oneShotRoot(t)
	got := oneShot(t, `{"pkgOp":""}`, append([]string{"--run-hooks", "pre"}, flags...)...)
	runs := recordedRuns(t, root)
	if got.status != 0 || len(runs) != 1 {
		t.Fatalf("exit status %d and runs %+v, want 0 and one run; stderr %s", got.status, runs, clip(got.stderr))
	}
	if op, set := runs[0].Env["PFB_PKG_OP"]; !set || op != "" {
		t.Errorf("PFB_PKG_OP = %q (set %v), want it set and empty", op, set)
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

// WHEN --run-hooks reads its settings from the state directory while another process holds the Update lock and Core's
// own lock there THEN it neither waits for them nor fails, runs its hooks, and leaves both locks held and the directory
// as it was. A wait would hang the run until the watchdog kills it.
func TestOneShotTakesNoUpdateLock(t *testing.T) {
	root, flags := oneShotRoot(t)
	state := filepath.Join(root, "state")
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
	got := oneShot(t, `{"trigger":"cron"}`, append([]string{"--run-hooks", "pre", "--state-dir", state}, flags[2:]...)...)
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

// WHEN --state-dir alone names the settings and holds no settings.json (an uninitialized Core, which the daemon serves)
// THEN the one-shot logs one line, runs nothing, leaves the directory empty and exits 0.
func TestOneShotOnAnUninitializedCoreRunsNothingAndExitsZero(t *testing.T) {
	root, flags := oneShotRoot(t)
	state := t.TempDir()
	got := oneShot(t, `{"trigger":"cron"}`, append([]string{"--run-hooks", "pre", "--state-dir", state}, flags[2:]...)...)
	if got.status != 0 || strings.Count(got.stderr, "\n") != 1 {
		t.Errorf("exit status %d and stderr %s, want 0 and one line", got.status, clip(got.stderr))
	}
	if runs := recordedRuns(t, root); runs != nil {
		t.Errorf("hooks ran without settings: %+v", runs)
	}
	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Errorf("the state directory holds %v, want nothing", entries)
	}
}

// WHEN another projection of the stored settings holds a value Core refuses, or one Core does not know THEN the hooks
// still run: the one-shot reads the hooks projection alone, as pfb_run_hooks() reads only the hook rows. A refused hook
// row still runs nothing (TestOneShotWithoutUsableSettingsRunsNothing).
func TestOneShotReadsTheHooksProjectionAlone(t *testing.T) {
	for name, other := range map[string]map[string]any{
		"a refused dns value":   {"dns": map[string]any{"decisionCacheMax": -1}},
		"an unknown projection": {"future": map[string]any{"x": 1}},
	} {
		t.Run(name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			rows := projected([]map[string]any{{"script": "hook_pre_a.sh", "when": "pre", "enabled": "on"}},
				func(s string) string { return s })
			other["hooks"] = map[string]any{"rows": rows}
			flags[1] = adapterOf(t, root, other)
			if _, err := settings.Load(&settings.AdapterBackend{Path: flags[1]}, settings.Production()); err == nil {
				t.Fatal("control: the daemon's schema reads these settings, want it to refuse them")
			}
			got := oneShot(t, `{"trigger":"cron"}`, append([]string{"--run-hooks", "pre"}, flags...)...)
			if runs := recordedRuns(t, root); got.status != 0 || len(runs) != 1 || runs[0].Script != "hook_pre_a.sh" {
				t.Errorf("exit status %d and runs %+v, want 0 and hook_pre_a.sh once; stderr %s", got.status, runs,
					clip(got.stderr))
			}
		})
	}
}

// WHEN the caller's environment holds PFB_* entries THEN no hook sees them: a member the context leaves out sets no
// variable, never an inherited one. Departure: today's pfb_run_hooks() passes them through.
func TestOneShotHookNeverInheritsACallersPFBEntry(t *testing.T) {
	root, flags := oneShotRoot(t)
	got := oneShotEnv(t, []string{"PFB_TRIGGER=evil", "PFB_STATUS=evil", "PFB_CHANGED_IP_ALIASES=evil"}, `{}`,
		append([]string{"--run-hooks", "pre"}, flags...)...)
	want := map[string]string{"PFB_WHEN": "pre", "PFB_POST_INSTALL": "0", "PFB_PRE_UNINSTALL": "0", "PFB_PKG_OP": ""}
	if runs := recordedRuns(t, root); got.status != 0 || len(runs) != 1 || !maps.Equal(runs[0].Env, want) {
		t.Errorf("exit status %d and runs %+v, want 0 and one run with %v; stderr %s", got.status, runs, want,
			clip(got.stderr))
	}
}

// WHEN the uninstall's console is a pipe whose reader has gone THEN the one-shot is not killed by SIGPIPE at its first
// console write: every hook runs, the exit status is 0 and stderr holds the whole main log.
func TestOneShotOutlivesAClosedConsole(t *testing.T) {
	root, flags := hookRoot(t, [2]string{"hook_pre_a.sh", "#!/bin/sh\n{record}\necho a\n"},
		[2]string{"hook_pre_b.sh", "#!/bin/sh\n{record}\necho b\n"})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	cmd := oneShotCmd(t, ctx, `{"lifecycle":"uninstall"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = w, &stderr
	status := exitStatus(t, cmd.Run())
	if ctx.Err() != nil {
		t.Fatal("STUCK: pfb-core did not return")
	}
	if status != 0 {
		t.Errorf("exit status %d, want 0; stderr %s", status, clip(stderr.String()))
	}
	runs := recordedRuns(t, root)
	if len(runs) != 2 || runs[0].Script != "hook_pre_a.sh" || runs[1].Script != "hook_pre_b.sh" {
		t.Errorf("runs = %+v, want hook_pre_a.sh, then hook_pre_b.sh", runs)
	}
	if stderr.String() != echoedAB {
		t.Errorf("main log (stderr):\n got %s\nwant %s", clip(stderr.String()), clip(echoedAB))
	}
}

// echoedAB is the main log of hook_pre_a.sh echoing a, then hook_pre_b.sh echoing b.
const echoedAB = "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\na\n[ pfB Hook ] pre #0 completed\n" +
	"\n[ pfB Hook ] pre #1 (hook_pre_b.sh, timeout 60s)\nb\n[ pfB Hook ] pre #1 completed\n"

// WHEN stderr, the main log, is a pipe whose reader has gone, under the uninstall lifecycle THEN the console (stdout)
// still gets the whole text, every hook runs and the exit status is 0: a failed main log write never stops the console.
func TestOneShotConsoleOutlivesAClosedMainLog(t *testing.T) {
	root, flags := hookRoot(t, [2]string{"hook_pre_a.sh", "#!/bin/sh\n{record}\necho a\n"},
		[2]string{"hook_pre_b.sh", "#!/bin/sh\n{record}\necho b\n"})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	cmd := oneShotCmd(t, ctx, `{"lifecycle":"uninstall"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, w
	status := exitStatus(t, cmd.Run())
	if ctx.Err() != nil {
		t.Fatal("STUCK: pfb-core did not return")
	}
	if status != 0 {
		t.Errorf("exit status %d, want 0", status)
	}
	if runs := recordedRuns(t, root); len(runs) != 2 {
		t.Errorf("runs = %+v, want hook_pre_a.sh, then hook_pre_b.sh", runs)
	}
	if stdout.String() != echoedAB {
		t.Errorf("console (stdout):\n got %s\nwant %s", clip(stdout.String()), clip(echoedAB))
	}
}

// WHEN the uninstall's console is a closed pipe and a hook writes in pieces, each drained into the main log before it
// writes the next THEN the main log holds every piece: a failed console write never stops a later drain.
func TestOneShotMainLogKeepsEveryDrainUnderAClosedConsole(t *testing.T) {
	root, flags := hookRoot(t, [2]string{"hook_pre_a.sh",
		"#!/bin/sh\necho one\nread _ < '{root}/go'\necho two\nread _ < '{root}/go'\necho three\n"})
	gate := fifo(t, filepath.Join(root, "go"))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	cmd := oneShotCmd(t, ctx, `{"lifecycle":"uninstall"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
	stderr := newWatchedLog("", closed())
	cmd.Stdout, cmd.Stderr = w, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, piece := range []string{"one\n", "two\n"} {
		await(t, "the main log to hold "+piece, func() bool { return strings.Contains(stderr.String(), piece) })
		release(t, gate)
	}
	status := exitStatus(t, cmd.Wait())
	if ctx.Err() != nil {
		t.Fatal("STUCK: pfb-core did not return")
	}
	want := "\n[ pfB Hook ] pre #0 (hook_pre_a.sh, timeout 60s)\none\ntwo\nthree\n[ pfB Hook ] pre #0 completed\n"
	if status != 0 || stderr.String() != want {
		t.Errorf("exit status %d and main log (stderr):\n got %s\nwant 0 and %s", status, clip(stderr.String()), clip(want))
	}
}

// WHEN the one-shot runs a hook THEN the hook has SIGPIPE's default action, not an ignore inherited from pfb-core: a
// hook that sends itself SIGPIPE dies of it (128+13) before it writes its marker.
func TestOneShotHookKeepsTheDefaultSIGPIPE(t *testing.T) {
	root, flags := hookRoot(t, [2]string{"hook_pre_a.sh", "#!/bin/sh\nkill -PIPE $$\n: > '{root}/survived'\n"})
	got := oneShot(t, `{"lifecycle":"uninstall"}`, append([]string{"--run-hooks", "pre"}, flags...)...)
	if got.status != 0 || !strings.Contains(got.stderr, "[ pfB Hook ] pre #0 exited non-zero [ 141 ]; continuing\n") {
		t.Errorf("exit status %d and stderr %s, want 0 and the hook killed by SIGPIPE", got.status, clip(got.stderr))
	}
	if exists(filepath.Join(root, "survived")) {
		t.Error("the hook survived SIGPIPE: it was started with SIGPIPE ignored")
	}
}

// WHEN TERM, INT or HUP reaches the one-shot while a hook runs THEN that hook is ended, the next one never starts, the
// log says the run was cancelled, and the exit status is 1: the hooks did not all run.
func TestOneShotCancelledBySignalEndsTheHookAndExitsOne(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			root, flags := hookRoot(t,
				[2]string{"hook_pre_a.sh", sleeper},
				[2]string{"hook_pre_b.sh", "#!/bin/sh\n{record}\n"})
			pidfile := killLeftover(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
			defer cancel()
			cmd := oneShotCmd(t, ctx, `{"trigger":"cron"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			await(t, "the first hook to start", func() bool { return exists(pidfile) })
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			status := exitStatus(t, cmd.Wait())
			if ctx.Err() != nil {
				t.Fatal("STUCK: pfb-core did not return")
			}
			if status != 1 {
				t.Errorf("exit status %d, want 1; stderr %s", status, clip(stderr.String()))
			}
			if !strings.Contains(stderr.String(), "[ pfB Hook ] pre run cancelled; 1 enabled hook did not run\n") {
				t.Errorf("stderr %s does not say the run was cancelled", clip(stderr.String()))
			}
			if alive(t, pidfile) {
				t.Error("the hook outlived the run")
			}
			if runs := recordedRuns(t, root); runs != nil {
				t.Errorf("a hook started after the signal: %+v", runs)
			}
		})
	}
}

// WHEN TERM or INT reaches the one-shot's whole process group (a terminal's Ctrl-C, a hangup, kill -TERM -<pgid>) while
// its only hook runs THEN that hook, which the signal ends itself, counts as cut short: the log says the run was
// cancelled and the exit status is 1. A hook that exits 130 on its own, with no signal, is a failed hook: the status is 0.
func TestOneShotGroupSignalDuringTheLastHookExitsOne(t *testing.T) {
	cancelled := "[ pfB Hook ] pre run cancelled; 0 enabled hooks did not run\n"
	for _, tc := range []struct {
		name   string
		sig    syscall.Signal // 0: none; the hook exits by itself
		body   string
		status int
		want   string
	}{
		{"SIGINT", syscall.SIGINT, sleeper, 1, cancelled},
		{"SIGTERM", syscall.SIGTERM, sleeper, 1, cancelled},
		{"exit 130 without a signal", 0, "#!/bin/sh\nexit 130\n", 0,
			"[ pfB Hook ] pre #0 exited non-zero [ 130 ]; continuing\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := hookRoot(t, [2]string{"hook_pre_a.sh", tc.body})
			pidfile := killLeftover(t, root)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
			defer cancel()
			cmd := oneShotCmd(t, ctx, `{"trigger":"cron"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // its own group, as a terminal's foreground job
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if tc.sig != 0 {
				await(t, "the hook to start", func() bool { return exists(pidfile) })
				if err := syscall.Kill(-cmd.Process.Pid, tc.sig); err != nil {
					t.Fatal(err)
				}
			}
			status := exitStatus(t, cmd.Wait())
			if ctx.Err() != nil {
				t.Fatal("STUCK: pfb-core did not return")
			}
			logged := strings.Contains(stderr.String(), "run cancelled")
			if status != tc.status || !strings.Contains(stderr.String(), tc.want) || logged != (tc.sig != 0) {
				t.Errorf("exit status %d and stderr %s, want %d and %q only", status, clip(stderr.String()), tc.status,
					tc.want)
			}
		})
	}
}

// sleeper is a hook that leaves its pid in {root}/a.pid and sleeps until it is ended.
const sleeper = "#!/bin/sh\necho $$ > '{root}/a.tmp'\nmv '{root}/a.tmp' '{root}/a.pid'\nexec sleep 600\n"

// killLeftover kills a sleeper the run left behind once the test ends, and returns its pid file.
func killLeftover(t *testing.T, root string) string {
	t.Helper()
	pidfile := filepath.Join(root, "a.pid")
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidfile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	return pidfile
}

// procStatus skips the test where there is no /proc, and returns a reader of the hex mask field (SigIgn, ...) of a
// process's status: whether it holds sig. A process that is gone holds nothing.
func procStatus(t *testing.T) func(pid int, field string, sig syscall.Signal) bool {
	t.Helper()
	if !exists("/proc/self/status") {
		t.Skip("no /proc to read a process's state from")
	}
	return func(pid int, field string, sig syscall.Signal) bool {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
		for _, line := range strings.Split(string(b), "\n") {
			if hex, ok := strings.CutPrefix(line, field+":"); ok {
				mask, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
				return err == nil && mask&(1<<(sig-1)) != 0
			}
		}
		return false
	}
}

// WHEN TERM reaches the one-shot while it waits for its context on a stdin that stays open THEN it stops waiting, logs
// one line, runs nothing, calls no settings backend and exits 1.
func TestOneShotSignalledWhileReadingTheContextExitsOne(t *testing.T) {
	root, flags := oneShotRoot(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// the writer stays open: the context never ends
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), hang) // only salvages a hung run
	defer cancel()
	cmd := oneShotCmd(t, ctx, "", nil, append([]string{"--run-hooks", "pre"}, flags...)...)
	var stderr bytes.Buffer
	cmd.Stdin, cmd.Stderr = r, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	// more white space than a pipe holds: the write returns only once pfb-core is reading its context
	if _, err := w.Write(bytes.Repeat([]byte(" "), 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	status := exitStatus(t, cmd.Wait())
	if ctx.Err() != nil {
		t.Fatal("STUCK: pfb-core kept waiting for its context after TERM")
	}
	if status != 1 || strings.Count(stderr.String(), "\n") != 1 {
		t.Errorf("exit status %d and stderr %s, want 1 and one line", status, clip(stderr.String()))
	}
	if runs := recordedRuns(t, root); runs != nil || exists(filepath.Join(root, "backend-called")) {
		t.Errorf("runs %+v and backend called %v, want neither", runs, exists(filepath.Join(root, "backend-called")))
	}
}

// WHEN TERM reaches the one-shot while it reads its settings THEN a fire point with no enabled hook runs to the end
// with exit status 0, as no hook was left unrun; one with an enabled hook logs that the run was cancelled and exits 1.
func TestOneShotSignalledDuringTheSettingsReadExitsOneOnlyWithAHookLeft(t *testing.T) {
	for _, tc := range []struct {
		when      string
		status    int
		cancelled bool
	}{{"post", 0, false}, {"pre", 1, true}} {
		t.Run(tc.when, func(t *testing.T) {
			root, flags := hookRoot(t, [2]string{"hook_pre_a.sh", sleeper}) // no post hook
			killLeftover(t, root)
			gate := fifo(t, filepath.Join(root, "go"))
			flags[1] = filepath.Join(root, "slow.sh")
			writeFile(t, flags[1], "#!/bin/sh\ncat > /dev/null\n: > '"+root+"/reading'\nread _ < '"+root+"/go'\n"+
				"cat '"+root+"/settings.json'\n", 0o755)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
			defer cancel()
			cmd := oneShotCmd(t, ctx, `{"trigger":"cron"}`, nil, append([]string{"--run-hooks", tc.when}, flags...)...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			await(t, "the settings read", func() bool { return exists(filepath.Join(root, "reading")) })
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			release(t, gate)
			status := exitStatus(t, cmd.Wait())
			if ctx.Err() != nil {
				t.Fatal("STUCK: pfb-core did not return")
			}
			logged := strings.Contains(stderr.String(), "[ pfB Hook ] "+tc.when+" run cancelled; ")
			if status != tc.status || logged != tc.cancelled {
				t.Errorf("exit status %d and cancelled line %v, want %d and %v; stderr %s", status, logged, tc.status,
					tc.cancelled, clip(stderr.String()))
			}
		})
	}
}

// WHEN the one-shot starts with SIGHUP ignored (nohup), or SIGINT ignored (a job started in the background by a shell
// without job control) THEN it leaves that signal ignored: the signal while a hook runs changes nothing, the hook runs to
// its end and the exit status is 0.
func TestOneShotLeavesAnIgnoredHangupOrInterruptIgnored(t *testing.T) {
	masked := procStatus(t)
	for _, tc := range []struct {
		sig  syscall.Signal
		name string // the signal's name for trap(1)
	}{{syscall.SIGHUP, "HUP"}, {syscall.SIGINT, "INT"}} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := hookRoot(t,
				[2]string{"hook_pre_a.sh", "#!/bin/sh\n: > '{root}/started'\nread _ < '{root}/go'\n{record}\n"})
			gate := fifo(t, filepath.Join(root, "go"))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
			defer cancel()
			cmd := oneShotCmd(t, ctx, `{"trigger":"cron"}`, nil, append([]string{"--run-hooks", "pre"}, flags...)...)
			cmd.Path = "/bin/sh"
			cmd.Args = append([]string{"/bin/sh", "-c", `trap "" ` + tc.name + `; exec "$0" "$@"`}, cmd.Args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			await(t, "the hook to start", func() bool { return exists(filepath.Join(root, "started")) })
			if !masked(cmd.Process.Pid, "SigIgn", tc.sig) {
				t.Errorf("pfb-core no longer ignores %s", tc.name)
			}
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatal(err)
			}
			release(t, gate)
			status := exitStatus(t, cmd.Wait())
			if ctx.Err() != nil {
				t.Fatal("STUCK: pfb-core did not return")
			}
			if runs := recordedRuns(t, root); status != 0 || len(runs) != 1 {
				t.Errorf("exit status %d and runs %+v, want 0 and the hook run to its end; stderr %s", status, runs,
					clip(stderr.String()))
			}
		})
	}
}

// WHEN --state-dir names a directory that does not exist, or a file THEN the one-shot logs one line, which quotes the
// path (a line break in it included) and gives why it cannot be used, runs nothing and exits 1; an existing directory
// without settings.json is an uninitialized Core (TestOneShotOnAnUninitializedCoreRunsNothingAndExitsZero).
func TestOneShotRefusesAStateDirectoryThatIsNoDirectory(t *testing.T) {
	for _, tc := range []struct{ name, dir, reason string }{
		{"missing", "missing", "no such file or directory"},
		{"a line break", "miss\ning", "no such file or directory"},
		{"a file", "state/settings.json", "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, flags := oneShotRoot(t)
			state := filepath.Join(root, tc.dir)
			got := oneShot(t, `{"trigger":"cron"}`,
				append([]string{"--run-hooks", "pre", "--state-dir", state}, flags[2:]...)...)
			if got.status != 1 || strings.Count(got.stderr, "\n") != 1 {
				t.Errorf("exit status %d and stderr %s, want 1 and one line", got.status, clip(got.stderr))
			}
			if !strings.Contains(got.stderr, strconv.Quote(state)) || !strings.Contains(got.stderr, tc.reason) {
				t.Errorf("stderr %s, want the path quoted as %s and %q", clip(got.stderr), strconv.Quote(state), tc.reason)
			}
			if runs := recordedRuns(t, root); runs != nil {
				t.Errorf("hooks ran without a state directory: %+v", runs)
			}
		})
	}
}

// WHEN --settings-backend-cmd is given with a --state-dir that does not exist THEN the state directory is never needed:
// the hooks run and the exit status is 0.
func TestOneShotThroughTheAdapterIgnoresTheStateDirectory(t *testing.T) {
	root, flags := oneShotRoot(t)
	got := oneShot(t, `{"trigger":"cron"}`,
		append([]string{"--run-hooks", "pre", "--state-dir", filepath.Join(root, "missing")}, flags...)...)
	if runs := recordedRuns(t, root); got.status != 0 || len(runs) != 1 || runs[0].Script != "hook_pre_a.sh" {
		t.Errorf("exit status %d and runs %+v, want 0 and hook_pre_a.sh once; stderr %s", got.status, runs,
			clip(got.stderr))
	}
}

// WHEN the settings cannot be read, through a failing backend or from a state directory that does not exist THEN under
// "lifecycle":"uninstall" the console (stdout) gets the same line as the main log (stderr), and without a lifecycle
// stdout stays empty.
func TestOneShotCopiesAnUnreadableSettingsLineToTheUninstallConsole(t *testing.T) {
	for _, source := range []string{"a failing backend", "a missing state directory"} {
		for _, stdin := range []string{`{"lifecycle":"uninstall"}`, `{}`} {
			t.Run(source+" "+stdin, func(t *testing.T) {
				root, flags := oneShotRoot(t)
				args := []string{"--run-hooks", "pre", "--state-dir", filepath.Join(root, "missing")}
				if source == "a failing backend" {
					backend := filepath.Join(root, "backend.sh")
					if err := os.WriteFile(backend, []byte("#!/bin/sh\necho broken >&2\nexit 1\n"), 0o755); err != nil {
						t.Fatal(err)
					}
					args = append(args, "--settings-backend-cmd", backend)
				}
				got := oneShot(t, stdin, append(args, flags[2:]...)...)
				if got.status != 1 || !strings.Contains(got.stderr, "cannot read the hooks") {
					t.Fatalf("exit status %d and stderr %s, want 1 and the line that the hooks cannot be read",
						got.status, clip(got.stderr))
				}
				want := ""
				if stdin != `{}` {
					want = got.stderr
				}
				if got.stdout != want {
					t.Errorf("stdout %s, want %s", clip(got.stdout), clip(want))
				}
			})
		}
	}
}
