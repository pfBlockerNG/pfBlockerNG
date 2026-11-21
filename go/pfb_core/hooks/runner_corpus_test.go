//go:build linux || freebsd

package hooks_test

// The ADR-12 hook runner corpus (#4035 slice 6a): JSON scenarios in tests/hooks/fixtures/runner that today's
// pfb_run_hooks() passes (tests/php/HookRunnerCorpusTest.php documents the keys) and this package's Runner passes. Here
// a stored row becomes a Hook as config.xml holds it (enabled is "on", timeout reads as PHP's (int)), vars, lifecycle and
// pkgOp become the Context, and the grace is 1 s. old_expect is today's answer where Go deliberately differs; it is not
// read here.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
)

// content is a string, {"b64": bytes} or {"prefix", "repeat", "times", "suffix"}.
type content struct {
	text, prefix, repeat, suffix string
	times                        int
	raw                          []byte
	isRaw                        bool
}

func (c *content) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, &c.text) == nil {
		return nil
	}
	var d struct {
		B64    *string `json:"b64"`
		Prefix string  `json:"prefix"`
		Repeat string  `json:"repeat"`
		Times  int     `json:"times"`
		Suffix string  `json:"suffix"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return err
	}
	if d.B64 != nil {
		raw, err := base64.StdEncoding.DecodeString(*d.B64)
		c.raw, c.isRaw = raw, true
		return err
	}
	c.prefix, c.repeat, c.times, c.suffix = d.Prefix, d.Repeat, d.Times, d.Suffix
	return nil
}

func (c content) bytes(expand func(string) string) string {
	if c.isRaw {
		return string(c.raw)
	}
	if c.repeat != "" {
		return expand(c.prefix) + strings.Repeat(c.repeat, c.times) + expand(c.suffix)
	}
	return expand(c.text)
}

type corpusFile struct {
	Body    *content `json:"body"`
	Mode    string   `json:"mode"`
	Symlink string   `json:"symlink"`
	Dir     bool     `json:"dir"`
}

type corpusRun struct {
	Script  string            `json:"script"`
	Wrapped bool              `json:"wrapped"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

type corpusCase struct {
	Description string                     `json:"description"`
	Departure   string                     `json:"departure"`
	When        string                     `json:"when"`
	Trigger     *string                    `json:"trigger"`
	Lifecycle   string                     `json:"lifecycle"`
	PkgOp       string                     `json:"pkgOp"`
	Python      string                     `json:"python"`
	Rows        []map[string]any           `json:"rows"`
	Vars        map[string]content         `json:"vars"`
	Files       map[string]corpusFile      `json:"files"`
	OldExpect   map[string]json.RawMessage `json:"old_expect"`
	Expect      struct {
		Runs       []corpusRun `json:"runs"`
		Log        content     `json:"log"`
		Errors     content     `json:"errors"`
		Transcript content     `json:"transcript"`
		Absent     []string    `json:"absent"`
		Alive      []string    `json:"alive"`
		Dead       []string    `json:"dead"`
		Throws     string      `json:"throws"`
	} `json:"expect"`
}

// phpInt is PHP's (int) of a stored timeout as the corpus stores one: a decimal string or number, else 0.
func phpInt(v any) int64 {
	switch v := v.(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

func storedHooks(rows []map[string]any, expand func(string) string) []hooks.Hook {
	str := func(v any) string { s, _ := v.(string); return expand(s) }
	var out []hooks.Hook
	for _, r := range rows {
		out = append(out, hooks.Hook{When: str(r["when"]), Script: str(r["script"]), Description: str(r["description"]),
			Timeout: phpInt(r["timeout"]), Enabled: r["enabled"] == "on"})
	}
	return out
}

func stage(t *testing.T, root string, sc corpusCase, expand func(string) string) {
	t.Helper()
	write := func(path, body string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "record.sh"), "{\n\tprintf 'script=%s\\000' \"${0##*/}\"\n"+
		"\tprintf 'wrapped=%s\\000' \"${HOOK_TEST_WRAPPED:-0}\"\n"+
		"\tfor arg in \"$@\"; do printf 'arg=%s\\000' \"$arg\"; done\n"+
		"\tenv -0\n\tprintf 'end\\000'\n} >> '"+root+"/record'\n", 0o644)
	interpreter := "\tprintf '/fixture/interpreter\\n'\n\texit 0\n"
	if sc.Python == "none" {
		interpreter = "\texit 127\n"
	}
	write(filepath.Join(root, "wrapper.sh"), "#!/bin/sh\nif [ \"$1\" = --print-interpreter ]; then\n"+interpreter+"fi\n"+
		"HOOK_TEST_WRAPPED=1 exec /bin/sh \"$@\"\n", 0o755)
	for _, path := range slices.Sorted(maps.Keys(sc.Files)) {
		f, target := sc.Files[path], filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		switch {
		case f.Symlink != "":
			if err := os.Symlink(expand(f.Symlink), target); err != nil {
				t.Fatal(err)
			}
		case f.Dir:
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
		default:
			mode := uint64(0o755)
			if f.Mode != "" {
				mode, _ = strconv.ParseUint(f.Mode, 8, 32)
			}
			write(target, f.Body.bytes(expand), os.FileMode(mode))
		}
	}
}

func recordedRuns(t *testing.T, root string) []corpusRun {
	t.Helper()
	record, err := os.ReadFile(filepath.Join(root, "record"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var runs []corpusRun
	cur := corpusRun{Args: []string{}, Env: map[string]string{}}
	for _, entry := range strings.Split(string(record), "\x00") {
		switch {
		case entry == "end":
			runs = append(runs, cur)
			cur = corpusRun{Args: []string{}, Env: map[string]string{}}
		case strings.HasPrefix(entry, "script="):
			cur.Script = strings.TrimPrefix(entry, "script=")
		case strings.HasPrefix(entry, "wrapped="):
			cur.Wrapped = entry == "wrapped=1"
		case strings.HasPrefix(entry, "arg="):
			cur.Args = append(cur.Args, strings.TrimPrefix(entry, "arg="))
		case strings.HasPrefix(entry, "PFB_"):
			name, value, _ := strings.Cut(entry, "=")
			cur.Env[name] = value
		}
	}
	return runs
}

func alive(t *testing.T, pidfile string) bool {
	t.Helper()
	b, _ := os.ReadFile(pidfile)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid file %s holds no pid: %q", pidfile, b)
	}
	return syscall.Kill(pid, 0) == nil
}

func TestHookRunnerCorpus(t *testing.T) {
	files, _ := filepath.Glob("../../../tests/hooks/fixtures/runner/*.json")
	if len(files) == 0 {
		t.Fatal("no hook runner corpus scenarios")
	}
	// A hook inherits the runner's environment: only the scenario's PFB_* may reach it.
	for _, kv := range os.Environ() {
		if name, value, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "PFB_") {
			os.Unsetenv(name)
			t.Cleanup(func() { os.Setenv(name, value) })
		}
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var sc corpusCase
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
			t.Cleanup(func() {
				pidfiles, _ := filepath.Glob(filepath.Join(root, "*.pid"))
				for _, p := range pidfiles {
					if b, err := os.ReadFile(p); err == nil {
						if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
							syscall.Kill(pid, syscall.SIGKILL)
						}
					}
				}
			})
			stage(t, root, sc, expand)
			vars := map[string]string{}
			for name, value := range sc.Vars {
				vars[name] = value.bytes(expand)
			}
			var log, errs, transcript bytes.Buffer
			r := hooks.Runner{Dir: filepath.Join(root, "hooks"), Python: filepath.Join(root, "wrapper.sh"), Log: &log,
				Errors: &errs, Transcript: &transcript, Grace: time.Second}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
			defer cancel()
			r.Run(ctx, sc.When, storedHooks(sc.Rows, expand), hooks.Context{Lifecycle: sc.Lifecycle, PkgOp: sc.PkgOp, Vars: vars})
			if ctx.Err() != nil {
				t.Fatal("STUCK: the run did not return")
			}

			want := []corpusRun{}
			for _, run := range sc.Expect.Runs {
				env := map[string]string{}
				for k, v := range run.Env {
					env[k] = expand(v)
				}
				want = append(want, corpusRun{Script: run.Script, Wrapped: run.Wrapped, Args: run.Args, Env: env})
			}
			got := recordedRuns(t, root)
			if got == nil {
				got = []corpusRun{}
			}
			wantJSON, _ := json.MarshalIndent(want, "", " ")
			gotJSON, _ := json.MarshalIndent(got, "", " ")
			if !bytes.Equal(wantJSON, gotJSON) {
				t.Errorf("recorded invocations (order, launcher, arguments, PFB_* environment):\n got %s\nwant %s", gotJSON, wantJSON)
			}
			for name, pair := range map[string]struct {
				got  string
				want content
			}{"log": {log.String(), sc.Expect.Log}, "errors": {errs.String(), sc.Expect.Errors},
				"transcript": {transcript.String(), sc.Expect.Transcript}} {
				if want := pair.want.bytes(expand); pair.got != want {
					t.Errorf("%s:\n got %s\nwant %s", name, clip(pair.got), clip(want))
				}
			}
			if sc.Expect.Throws != "" {
				t.Errorf("expect.throws = %q: the Go runner never throws", sc.Expect.Throws)
			}
			for _, canary := range sc.Expect.Absent {
				if _, err := os.Stat(filepath.Join(root, canary)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("canary %s exists: an unvetted or unevaluated script ran", canary)
				}
			}
			for _, p := range sc.Expect.Alive {
				if !alive(t, filepath.Join(root, p)) {
					t.Errorf("%s: the process must outlive the run", p)
				}
			}
			for _, p := range sc.Expect.Dead {
				if alive(t, filepath.Join(root, p)) {
					t.Errorf("%s: the process must be gone when the run returns", p)
				}
			}
		})
	}
}

// clip quotes a text, its middle elided when long, so a 10 MiB mismatch stays readable.
func clip(s string) string {
	if len(s) > 600 {
		return strconv.Quote(s[:300]) + " ... " + strconv.Quote(s[len(s)-300:]) + " (" + strconv.Itoa(len(s)) + " bytes)"
	}
	return strconv.Quote(s)
}
